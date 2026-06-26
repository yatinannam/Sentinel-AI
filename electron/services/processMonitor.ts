import { exec } from 'child_process';
import { BrowserWindow } from 'electron';
import { db } from './database';
import { quarantine } from './quarantine';

export interface ProcessTelemetry {
  pid: number;
  parentPid: number;
  name: string;
  commandLine: string;
  memoryUsage: number; // in MB
  cpuUsage: number; // simulated/calculated
  suspicious: boolean;
  reasons: string[];
}

class ProcessMonitorService {
  private mainWindow: BrowserWindow | null = null;
  private intervalId: NodeJS.Timeout | null = null;
  private isMonitoring: boolean = false;
  private knownSuspiciousPids: Set<number> = new Set();

  public start(window: BrowserWindow) {
    if (this.isMonitoring) return;
    this.mainWindow = window;
    this.isMonitoring = true;

    // Poll processes every 4 seconds
    this.intervalId = setInterval(() => this.pollProcesses(), 4000);
    this.pollProcesses(); // initial run
  }

  public stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this.isMonitoring = false;
  }

  private pollProcesses() {
    // Run WMIC to get running processes. WMIC is fast and native on Windows.
    const cmd = 'wmic process get CommandLine,Name,ParentProcessId,ProcessId,WorkingSetSize /FORMAT:csv';
    
    exec(cmd, (error, stdout) => {
      if (error) {
        // Fallback for non-Windows or environments without WMIC
        this.simulateProcesses();
        return;
      }

      try {
        const processes = this.parseWmicOutput(stdout);
        this.analyzeProcesses(processes);
      } catch (err) {
        console.error('Failed to parse processes:', err);
      }
    });
  }

  private parseWmicOutput(stdout: string): ProcessTelemetry[] {
    const lines = stdout.split(/\r?\n/);
    const processes: ProcessTelemetry[] = [];

    // Header index maps: Node, CommandLine, Name, ParentProcessId, ProcessId, WorkingSetSize
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      // WMIC CSV format has a tendency to output commas inside quotes.
      // We parse CSV row safely.
      const parts = this.parseCsvRow(line);
      if (parts.length < 6) continue;

      // Node (parts[0]), CommandLine (parts[1]), Name (parts[2]), ParentProcessId (parts[3]), ProcessId (parts[4]), WorkingSetSize (parts[5])
      const commandLine = parts[1] || '';
      const name = parts[2] || '';
      const parentPid = parseInt(parts[3]) || 0;
      const pid = parseInt(parts[4]) || 0;
      const workingSetSize = parseInt(parts[5]) || 0;

      if (pid === 0) continue;

      processes.push({
        pid,
        parentPid,
        name,
        commandLine,
        memoryUsage: Math.round(workingSetSize / (1024 * 1024)), // Convert to MB
        cpuUsage: Math.round(Math.random() * 5), // Simulated CPU load
        suspicious: false,
        reasons: []
      });
    }

    return processes;
  }

  private parseCsvRow(row: string): string[] {
    const result = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < row.length; i++) {
      const char = row[i];
      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        result.push(current);
        current = '';
      } else {
        current += char;
      }
    }
    result.push(current);
    return result;
  }

  private analyzeProcesses(processes: ProcessTelemetry[]) {
    const analyzed: ProcessTelemetry[] = [];
    const settings = db.getSettings();

    for (const proc of processes) {
      const commandLineLower = proc.commandLine.toLowerCase();
      const nameLower = proc.name.toLowerCase();

      // Check 1: PowerShell abuse
      if (nameLower.includes('powershell.exe')) {
        if (
          commandLineLower.includes('-ep bypass') ||
          commandLineLower.includes('-executionpolicy bypass') ||
          commandLineLower.includes('-w hidden') ||
          commandLineLower.includes('-windowstyle hidden') ||
          commandLineLower.includes('iex') ||
          commandLineLower.includes('downloadstring') ||
          commandLineLower.includes('-enc') ||
          commandLineLower.includes('-encodedcommand')
        ) {
          proc.suspicious = true;
          proc.reasons.push('PowerShell executed with execution bypass or hidden window style');
        }
      }

      // Check 2: MS Office spawning script host or command processor (Macro abuse)
      if (nameLower === 'cmd.exe' || nameLower === 'powershell.exe' || nameLower === 'wscript.exe') {
        const parent = processes.find(p => p.pid === proc.parentPid);
        if (parent) {
          const parentName = parent.name.toLowerCase();
          if (
            parentName.includes('winword.exe') ||
            parentName.includes('excel.exe') ||
            parentName.includes('powerpnt.exe') ||
            parentName.includes('outlook.exe')
          ) {
            proc.suspicious = true;
            proc.reasons.push(`Shell spawned by office application macro (${parent.name})`);
          }
        }
      }

      // Check 3: CMD launching from temp directory or running network downloads
      if (nameLower === 'cmd.exe' && (commandLineLower.includes('curl') || commandLineLower.includes('wget') || commandLineLower.includes('certutil'))) {
        proc.suspicious = true;
        proc.reasons.push('Command processor running suspicious web downloads');
      }

      analyzed.push(proc);

      // Handle detections and automatic response
      if (proc.suspicious && !this.knownSuspiciousPids.has(proc.pid)) {
        this.knownSuspiciousPids.add(proc.pid);
        this.handleProcessThreat(proc, settings);
      }
    }

    // Send process list to UI
    this.sendToRenderer('process-update', analyzed);
  }

  private handleProcessThreat(proc: ProcessTelemetry, settings: any) {
    let actionTaken = 'None';
    let status: 'Killed' | 'Detected' = 'Detected';

    console.warn(`[Process Monitor] Suspicious process detected: ${proc.name} (PID: ${proc.pid}). Reason: ${proc.reasons.join(', ')}`);

    if (settings.realTimeProtection) {
      // Kill the threat process
      try {
        process.kill(proc.pid, 'SIGKILL');
        actionTaken = 'Process Terminated';
        status = 'Killed';
        console.log(`[Process Monitor] Successfully killed suspicious process PID: ${proc.pid}`);
      } catch (err: any) {
        actionTaken = 'Kill Failed';
        console.error(`Failed to kill process PID: ${proc.pid}:`, err.message);
      }
    }

    // Log incident
    const incident = db.addIncident({
      name: proc.name,
      path: proc.commandLine || proc.name,
      hash: 'N/A (Active Process)',
      type: 'SUSPICIOUS PROCESS',
      severity: 'high',
      confidence: 90,
      status: status,
      actionTaken: actionTaken,
      details: proc.reasons.join('. ')
    });

    this.sendToRenderer('incident-detected', incident);
  }

  private simulateProcesses() {
    // Simulates process telemetry when testing in non-windows environment
    const simulated: ProcessTelemetry[] = [
      { pid: 104, parentPid: 4, name: 'System', commandLine: 'System', memoryUsage: 12, cpuUsage: 1, suspicious: false, reasons: [] },
      { pid: 1420, parentPid: 800, name: 'explorer.exe', commandLine: 'C:\\Windows\\explorer.exe', memoryUsage: 142, cpuUsage: 2, suspicious: false, reasons: [] },
      { pid: 3412, parentPid: 1420, name: 'chrome.exe', commandLine: '"C:\\Program Files\\Google\\Chrome\\chrome.exe"', memoryUsage: 350, cpuUsage: 5, suspicious: false, reasons: [] },
      { pid: 8820, parentPid: 1420, name: 'SentinelAI.exe', commandLine: '"D:\\The Proj\\SentinelAI\\dist\\win-unpacked\\SentinelAI.exe"', memoryUsage: 65, cpuUsage: 1, suspicious: false, reasons: [] }
    ];
    this.sendToRenderer('process-update', simulated);
  }

  private sendToRenderer(channel: string, data: any) {
    if (this.mainWindow && !this.mainWindow.isDestroyed()) {
      this.mainWindow.webContents.send(channel, data);
    }
  }
}

export const processMonitor = new ProcessMonitorService();
