import { app, BrowserWindow } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import * as chokidar from 'chokidar';
import { yaraScanner } from './yaraScanner';
import { quarantine } from './quarantine';
import { db } from './database';

class FileMonitorService {
  private watchers: chokidar.FSWatcher[] = [];
  private mainWindow: BrowserWindow | null = null;
  private isMonitoring: boolean = false;

  constructor() {
    // Initialized from main process
  }

  public start(window: BrowserWindow) {
    if (this.isMonitoring) return;
    this.mainWindow = window;
    this.isMonitoring = true;

    const pathsToWatch = this.getWatchPaths();
    console.log('SentinelAI File Monitor starting for paths:', pathsToWatch);

    pathsToWatch.forEach(dir => {
      if (fs.existsSync(dir)) {
        const watcher = chokidar.watch(dir, {
          persistent: true,
          ignoreInitial: true,
          depth: 1, // Only monitor root of these folders to optimize performance
          awaitWriteFinish: {
            stabilityThreshold: 1000,
            pollInterval: 100
          }
        });

        watcher.on('add', (filePath) => this.handleNewFile(filePath));
        watcher.on('change', (filePath) => this.handleNewFile(filePath));

        this.watchers.push(watcher);
      }
    });
  }

  public stop() {
    this.watchers.forEach(w => w.close());
    this.watchers = [];
    this.isMonitoring = false;
  }

  private getWatchPaths(): string[] {
    const paths = [];
    try {
      paths.push(app.getPath('desktop'));
      paths.push(app.getPath('documents'));
      paths.push(app.getPath('downloads'));
    } catch (e) {
      // Fallbacks for testing environment
      paths.push(path.join(process.env.USERPROFILE || 'C:\\', 'Desktop'));
      paths.push(path.join(process.env.USERPROFILE || 'C:\\', 'Downloads'));
    }
    return paths;
  }

  private isExecutable(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    const executableExtensions = ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.msi', '.scr'];
    return executableExtensions.includes(ext);
  }

  private async handleNewFile(filePath: string) {
    if (!this.isExecutable(filePath)) {
      // Send file creation event to dashboard for real-time monitoring logs
      this.sendToRenderer('file-event', {
        action: 'Created',
        path: filePath,
        time: new Date().toLocaleTimeString(),
        status: 'Safe'
      });
      return;
    }

    console.log(`[File Monitor] New executable detected: ${filePath}`);

    this.sendToRenderer('file-event', {
      action: 'Created (Executable)',
      path: filePath,
      time: new Date().toLocaleTimeString(),
      status: 'Analyzing...'
    });

    try {
      // 1. Quick YARA scan
      const scanResult = await yaraScanner.scanFile(filePath);

      if (scanResult.isMalicious) {
        const matched = scanResult.matchedRules[0];
        console.warn(`[File Monitor] Threat detected via signature scan: ${matched.name} in ${filePath}`);

        // Handle automated response (Quarantine)
        const settings = db.getSettings();
        let status: 'Quarantined' | 'Detected' = 'Detected';
        let actionTaken = 'None';

        if (settings.autoQuarantine) {
          try {
            await quarantine.quarantineFile(filePath, scanResult.hash);
            status = 'Quarantined';
            actionTaken = 'Quarantined';
          } catch (qErr: any) {
            console.error('Auto-quarantine failed:', qErr);
            actionTaken = 'Quarantine Failed';
          }
        }

        // Log incident to database
        const incident = db.addIncident({
          name: matched.name,
          path: filePath,
          hash: scanResult.hash,
          type: matched.category.toUpperCase(),
          severity: matched.severity,
          confidence: 100,
          status: status,
          actionTaken: actionTaken,
          details: `Signature match: ${matched.description}`
        });

        // Notify user via Electron UI/Tray
        this.sendToRenderer('incident-detected', incident);
        return;
      }

      // 2. Pass to AI engine for deep behavioral/static analysis
      this.sendToRenderer('ai-scan-request', {
        filePath,
        hash: scanResult.hash
      });

    } catch (error) {
      console.error(`Error processing file ${filePath}:`, error);
    }
  }

  private sendToRenderer(channel: string, data: any) {
    if (this.mainWindow && !this.mainWindow.isDestroyed()) {
      this.mainWindow.webContents.send(channel, data);
    }
  }
}

export const fileMonitor = new FileMonitorService();
