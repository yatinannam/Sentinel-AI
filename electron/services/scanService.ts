import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';
import { db, ScanReport } from './database';
import { threatEngine } from './threatEngine';
import { yaraScanner } from './yaraScanner';

export interface ScanStatusUpdate {
  scanType: 'Quick Scan' | 'Deep Scan' | 'Custom Scan';
  status: string;
  progress: number;
  filesScanned: number;
  filesSkipped: number;
  threatsFound: number;
  threatsRemoved: number;
  estimatedTimeRemaining: string; // MM:SS format
  currentLayer: string;
  currentFile: string;
}

class ScanService {
  private isScanPaused = false;
  private isScanRunning = false;
  private isScanCancelled = false;
  private filesQueue: string[] = [];
  private totalFiles = 0;
  
  // Progress telemetry tracking
  private filesScannedCount = 0;
  private filesSkippedCount = 0;
  private threatsFoundCount = 0;
  private threatsRemovedCount = 0;
  private scanStartTime = 0;
  private scanType: 'Quick Scan' | 'Deep Scan' | 'Custom Scan' = 'Quick Scan';
  private currentStatus = 'System Idle';
  private currentLayer = 'Signature Detection';
  private currentFile = '';
  private threatReports: any[] = [];
  
  // Concurrency pool
  private concurrency = 4;
  private activeWorkers = 0;

  // CPU average calculation variables
  private cpuSamples: number[] = [];
  private cpuTimer: NodeJS.Timeout | null = null;
  private lastCpuTicks = this.getCpuTicks();

  private window: any = null;

  public setWindow(win: any) {
    this.window = win;
  }

  public getIsRunning() {
    return this.isScanRunning;
  }

  public pauseScan() {
    this.isScanPaused = true;
    this.sendStatusUpdate();
  }

  public resumeScan() {
    this.isScanPaused = false;
    this.sendStatusUpdate();
  }

  public cancelScan() {
    this.isScanCancelled = true;
    this.isScanPaused = false;
    this.sendStatusUpdate();
  }

  private async checkPause() {
    while (this.isScanPaused && !this.isScanCancelled) {
      await new Promise(resolve => setTimeout(resolve, 200));
    }
  }

  // CPU load measurement utilities
  private getCpuTicks() {
    const cpus = os.cpus();
    let user = 0, nice = 0, sys = 0, idle = 0, irq = 0;
    if (!cpus) return { idle: 0, total: 0 };
    for (const cpu of cpus) {
      user += cpu.times.user;
      nice += cpu.times.nice;
      sys += cpu.times.sys;
      idle += cpu.times.idle;
      irq += cpu.times.irq;
    }
    return { idle, total: user + nice + sys + idle + irq };
  }

  private getCpuUsage() {
    const currentTicks = this.getCpuTicks();
    const idleDiff = currentTicks.idle - this.lastCpuTicks.idle;
    const totalDiff = currentTicks.total - this.lastCpuTicks.total;
    this.lastCpuTicks = currentTicks;
    if (totalDiff === 0) return 0;
    return Math.min(100, Math.max(0, 100 - Math.round((100 * idleDiff) / totalDiff)));
  }

  private startCpuTracking() {
    this.cpuSamples = [];
    this.lastCpuTicks = this.getCpuTicks();
    this.cpuTimer = setInterval(() => {
      this.cpuSamples.push(this.getCpuUsage());
    }, 1000);
  }

  private stopCpuTracking(): number {
    if (this.cpuTimer) {
      clearInterval(this.cpuTimer);
      this.cpuTimer = null;
    }
    if (this.cpuSamples.length === 0) return 3; // fallback min
    const sum = this.cpuSamples.reduce((a, b) => a + b, 0);
    return Math.round(sum / this.cpuSamples.length);
  }

  // File collection utilities
  private collectExecutables(dir: string, fileList: string[], depth = 0, maxDepth = 3) {
    if (depth > maxDepth || this.isScanCancelled) return;
    try {
      if (!fs.existsSync(dir)) return;
      const stat = fs.statSync(dir);
      if (!stat.isDirectory()) return;

      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (this.isScanCancelled) return;
        const fullPath = path.join(dir, entry.name);
        
        // Skip common large caches & system folders
        if (['node_modules', '.git', 'AppData', 'Local Settings', 'Application Data'].includes(entry.name)) {
          continue;
        }

        if (entry.isDirectory()) {
          this.collectExecutables(fullPath, fileList, depth + 1, maxDepth);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.msi', '.dll', '.sys'].includes(ext)) {
            fileList.push(fullPath);
          }
        }
      }
    } catch (err) {
      // Ignore directories with restricted access (EPERM/EACCES)
    }
  }

  // Startup locations crawler
  private getStartupPrograms(fileList: string[]) {
    const userStartup = path.join(os.homedir(), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
    const commonStartup = 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup';
    this.collectExecutables(userStartup, fileList, 0, 2);
    this.collectExecutables(commonStartup, fileList, 0, 2);
  }

  // Active processes crawler
  private getRunningProcesses(fileList: string[]) {
    try {
      const psCommand = `powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.Path } | Select-Object -ExpandProperty Path | ConvertTo-Json"`;
      const output = execSync(psCommand, { encoding: 'utf-8', timeout: 5000 });
      if (output.trim()) {
        const paths = JSON.parse(output);
        const uniquePaths = Array.isArray(paths) ? Array.from(new Set(paths)) : [paths];
        for (const p of uniquePaths) {
          if (typeof p === 'string' && fs.existsSync(p)) {
            fileList.push(p);
          }
        }
      }
    } catch (err) {
      // Fallback
    }
  }

  // Windows Active Services crawler
  private getActiveServices(fileList: string[]) {
    try {
      const psCommand = `powershell -NoProfile -Command "Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' -and $_.PathName } | Select-Object -ExpandProperty PathName | ConvertTo-Json"`;
      const output = execSync(psCommand, { encoding: 'utf-8', timeout: 5000 });
      if (output.trim()) {
        const paths = JSON.parse(output);
        const rawPaths = Array.isArray(paths) ? paths : [paths];
        for (let p of rawPaths) {
          if (typeof p === 'string') {
            p = p.trim();
            if (p.startsWith('"')) {
              p = p.substring(1, p.indexOf('"', 1));
            } else {
              p = p.split(' ')[0];
            }
            if (fs.existsSync(p)) {
              fileList.push(p);
            }
          }
        }
      }
    } catch (err) {}
  }

  // Active Network connections crawler
  private getNetworkProcesses(fileList: string[]) {
    try {
      const psCommand = `netstat -ano`;
      const output = execSync(psCommand, { encoding: 'utf-8', timeout: 5000 });
      const lines = output.split('\n');
      const pids = new Set<number>();
      for (const line of lines) {
        const tokens = line.trim().split(/\s+/);
        if (tokens.length >= 5) {
          const pid = parseInt(tokens[tokens.length - 1]);
          if (pid > 0) pids.add(pid);
        }
      }
      for (const pid of pids) {
        try {
          const procPathCmd = `powershell -NoProfile -Command "(Get-Process -Id ${pid}).Path"`;
          const procPath = execSync(procPathCmd, { encoding: 'utf-8', timeout: 2000 }).trim();
          if (procPath && fs.existsSync(procPath)) {
            fileList.push(procPath);
          }
        } catch (e) {}
      }
    } catch (err) {}
  }

  // Connected USB devices volumes crawler
  private getUsbDevices(fileList: string[]) {
    try {
      const psCommand = `powershell -NoProfile -Command "Get-CimInstance Win32_Volume | Where-Object { $_.DriveType -eq 2 } | Select-Object -ExpandProperty Name | ConvertTo-Json"`;
      const output = execSync(psCommand, { encoding: 'utf-8', timeout: 5000 });
      if (output.trim()) {
        const volumes = JSON.parse(output);
        const volumeList = Array.isArray(volumes) ? volumes : [volumes];
        for (const vol of volumeList) {
          if (typeof vol === 'string' && fs.existsSync(vol)) {
            this.collectExecutables(vol, fileList, 0, 2);
          }
        }
      }
    } catch (err) {}
  }

  // Main targeting router
  private async gatherFiles(type: 'Quick Scan' | 'Deep Scan' | 'Custom Scan', customPath?: string): Promise<string[]> {
    const list: string[] = [];

    if (type === 'Custom Scan' && customPath) {
      this.collectExecutables(customPath, list, 0, 4);
    } else if (type === 'Quick Scan') {
      this.collectExecutables(path.join(os.homedir(), 'Desktop'), list, 0, 2);
      this.collectExecutables(path.join(os.homedir(), 'Downloads'), list, 0, 2);
      this.collectExecutables(path.join(os.homedir(), 'Documents'), list, 0, 2);
      this.getStartupPrograms(list);
      this.getRunningProcesses(list);
      this.getActiveServices(list);
      this.getUsbDevices(list);
    } else if (type === 'Deep Scan') {
      this.collectExecutables(path.join(os.homedir(), 'Desktop'), list, 0, 4);
      this.collectExecutables(path.join(os.homedir(), 'Downloads'), list, 0, 4);
      this.collectExecutables(path.join(os.homedir(), 'Documents'), list, 0, 4);
      
      this.collectExecutables(path.join(os.homedir(), 'AppData', 'Local', 'Temp'), list, 0, 3);
      this.collectExecutables('C:\\Windows\\Temp', list, 0, 3);

      this.collectExecutables('C:\\Windows\\System32', list, 0, 2);
      this.collectExecutables('C:\\Program Files', list, 0, 2);
      this.collectExecutables('C:\\Program Files (x86)', list, 0, 2);

      const chromeExts = path.join(os.homedir(), 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Extensions');
      this.collectExecutables(chromeExts, list, 0, 3);

      this.getStartupPrograms(list);
      this.getRunningProcesses(list);
      this.getActiveServices(list);
      this.getUsbDevices(list);
      this.getNetworkProcesses(list);
    }

    const uniqueList = Array.from(new Set(list));

    try {
      const statsList = uniqueList.map(filePath => {
        try {
          const stat = fs.statSync(filePath);
          return { filePath, mtime: stat.mtimeMs };
        } catch {
          return { filePath, mtime: 0 };
        }
      });
      statsList.sort((a, b) => b.mtime - a.mtime);
      return statsList.map(s => s.filePath);
    } catch {
      return uniqueList;
    }
  }

  // Core execution engine
  public async startScan(type: 'Quick Scan' | 'Deep Scan' | 'Custom Scan', customPath?: string) {
    if (this.isScanRunning) return;
    this.isScanRunning = true;
    this.isScanCancelled = false;
    this.isScanPaused = false;
    this.scanType = type;

    this.filesScannedCount = 0;
    this.filesSkippedCount = 0;
    this.threatsFoundCount = 0;
    this.threatsRemovedCount = 0;
    this.threatReports = [];
    this.currentStatus = `Gathering files for ${type}...`;
    this.sendStatusUpdate();

    this.startCpuTracking();
    this.scanStartTime = Date.now();

    try {
      const targets = await this.gatherFiles(type, customPath);
      this.totalFiles = targets.length;

      if (this.totalFiles === 0) {
        this.currentStatus = 'Scan finished. No files evaluated.';
        this.isScanRunning = false;
        this.stopCpuTracking();
        this.sendStatusUpdate();
        return;
      }

      this.filesQueue = [...targets];
      this.activeWorkers = 0;

      const workerPromises = Array.from({ length: this.concurrency }, () => this.runWorker());
      await Promise.all(workerPromises);

      const durationSeconds = Math.round((Date.now() - this.scanStartTime) / 1000);
      const avgCpu = this.stopCpuTracking();

      let threatsRemoved = 0;
      let finalScoreSum = 0;
      
      for (const t of this.threatReports) {
        if (t.status === 'Quarantined' || t.status === 'Killed' || t.status === 'Blocked') {
          threatsRemoved++;
        }
        finalScoreSum += t.finalScore;
      }

      const averageThreatImpact = this.threatReports.length > 0 ? (finalScoreSum / this.threatReports.length) : 0;
      const securityScore = Math.max(0, 100 - Math.round(averageThreatImpact * Math.min(1.0, this.threatReports.length / 5)));

      const report: Omit<ScanReport, 'id' | 'date'> = {
        scanType: this.scanType,
        duration: durationSeconds,
        filesScanned: this.filesScannedCount,
        filesSkipped: this.filesSkippedCount,
        threatsFound: this.threatReports.length,
        threatsRemoved: threatsRemoved,
        securityScore: securityScore,
        cpuUsage: avgCpu,
        detailsJson: JSON.stringify(this.threatReports)
      };

      if (!this.isScanCancelled) {
        const savedReport = db.addScan(report);
        this.currentStatus = `Scan completed. Threats found: ${this.threatReports.length}`;
        if (this.window && !this.window.isDestroyed()) {
          this.window.webContents.send('scan-report-completed', savedReport);
        }
      } else {
        this.currentStatus = 'Scan cancelled by user.';
      }

    } catch (err: any) {
      console.error('[ScanService] Error during system scan:', err);
      this.currentStatus = 'Scan failed due to an internal error.';
    } finally {
      this.isScanRunning = false;
      this.stopCpuTracking();
      this.sendStatusUpdate();
    }
  }

  // Async queue worker loop
  private async runWorker() {
    this.activeWorkers++;
    try {
      while (this.filesQueue.length > 0 && !this.isScanCancelled) {
        await this.checkPause();
        if (this.isScanCancelled) break;

        const file = this.filesQueue.shift();
        if (!file) continue;

        this.currentFile = file;

        let stats: fs.Stats | null = null;
        try {
          stats = fs.statSync(file);
        } catch {
          continue;
        }

        const cacheEntry = db.getFileCache(file);
        if (cacheEntry && cacheEntry.mtime === stats.mtimeMs) {
          this.filesSkippedCount++;
          if (cacheEntry.status === 'Malicious') {
            this.threatReports.push({
              filePath: file,
              fileName: path.basename(file),
              hash: cacheEntry.hash,
              finalScore: cacheEntry.finalScore,
              status: cacheEntry.status
            });
            this.threatsFoundCount++;
          }
          this.sendStatusUpdate();
          continue;
        }

        const isMicrosoftSystem = this.checkTrustedMicrosoft(file);
        if (isMicrosoftSystem) {
          this.filesSkippedCount++;
          this.sendStatusUpdate();
          continue;
        }

        this.filesScannedCount++;
        this.currentLayer = 'YARA Signature Check';
        
        try {
          const result = await threatEngine.analyzeFile(file);
          
          db.setFileCache({
            filePath: file,
            hash: result.hash,
            mtime: stats.mtimeMs,
            status: result.status,
            finalScore: result.finalScore
          });

          if (this.window && !this.window.isDestroyed()) {
            this.window.webContents.send('multi-layer-scan-progress', result);
          }

          if (result.status === 'Malicious') {
            this.threatsFoundCount++;
            this.threatReports.push({
              filePath: file,
              fileName: path.basename(file),
              hash: result.hash,
              finalScore: result.finalScore,
              status: result.status,
              type: result.layers.layer1.status === 'Failed' ? 'Malware' : 'Trojan'
            });
          }
        } catch (e) {
        }

        this.sendStatusUpdate();
      }
    } finally {
      this.activeWorkers--;
    }
  }

  private checkTrustedMicrosoft(filePath: string): boolean {
    const norm = filePath.toLowerCase();
    if (norm.startsWith('c:\\windows\\system32') || norm.startsWith('c:\\program files')) {
      try {
        const signatureCmd = `powershell -NoProfile -Command "(Get-AuthenticodeSignature -FilePath '${filePath.replace(/'/g, "''")}').SignerCertificate.Subject"`;
        const publisher = execSync(signatureCmd, { encoding: 'utf-8', timeout: 3000 }).trim();
        if (publisher && (publisher.includes('Microsoft') || publisher.includes('Windows') || publisher.includes('Intel'))) {
          return true;
        }
      } catch (e) {}
    }
    return false;
  }

  private calculateEta(): string {
    if (this.filesScannedCount === 0) return 'Estimating...';
    const elapsed = (Date.now() - this.scanStartTime) / 1000;
    const avgPerFile = elapsed / (this.filesScannedCount + this.filesSkippedCount);
    const remaining = this.totalFiles - (this.filesScannedCount + this.filesSkippedCount);
    const etaSec = Math.round((avgPerFile * remaining) / this.concurrency);
    
    if (etaSec <= 0) return '00:00';
    const mins = Math.floor(etaSec / 60);
    const secs = etaSec % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }

  private sendStatusUpdate() {
    if (!this.window || this.window.isDestroyed()) return;

    const progress = this.totalFiles > 0 
      ? Math.round(((this.filesScannedCount + this.filesSkippedCount) / this.totalFiles) * 100) 
      : 0;

    const update: ScanStatusUpdate = {
      scanType: this.scanType,
      status: this.isScanPaused ? 'Scan Paused' : this.isScanRunning ? 'Scanning System...' : this.currentStatus,
      progress,
      filesScanned: this.filesScannedCount,
      filesSkipped: this.filesSkippedCount,
      threatsFound: this.threatsFoundCount,
      threatsRemoved: this.threatsRemovedCount,
      estimatedTimeRemaining: this.isScanPaused ? 'Paused' : this.calculateEta(),
      currentLayer: this.currentLayer,
      currentFile: this.currentFile
    };

    this.window.webContents.send('scan-status-update', update);

    if ((global as any).updateTrayStatus) {
      (global as any).updateTrayStatus();
    }
  }
}

export const scanService = new ScanService();
