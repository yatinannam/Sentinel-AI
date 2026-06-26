import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { BrowserWindow } from 'electron';
import { yaraScanner } from './yaraScanner';
import { quarantine } from './quarantine';
import { db } from './database';

export interface UsbDrive {
  letter: string;
  label: string;
}

class UsbMonitorService {
  private mainWindow: BrowserWindow | null = null;
  private intervalId: NodeJS.Timeout | null = null;
  private isMonitoring: boolean = false;
  private connectedDrives: Set<string> = new Set();

  public start(window: BrowserWindow) {
    if (this.isMonitoring) return;
    this.mainWindow = window;
    this.isMonitoring = true;

    // Poll USB drives every 5 seconds
    this.intervalId = setInterval(() => this.pollUsbDrives(), 5000);
    this.pollUsbDrives();
  }

  public stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this.isMonitoring = false;
  }

  private pollUsbDrives() {
    // DriveType = 2 (Removable)
    const cmd = `powershell -Command "Get-CimInstance Win32_Volume | Where-Object {$_.DriveType -eq 2} | Select-Object DriveLetter, Label | ConvertTo-Json"`;

    exec(cmd, (error, stdout) => {
      if (error) {
        // Silent fail (likely non-Windows env)
        return;
      }
      try {
        const output = stdout.trim();
        if (!output) {
          this.handleDrivesList([]);
          return;
        }

        const data = JSON.parse(output);
        const drives: UsbDrive[] = [];

        if (Array.isArray(data)) {
          data.forEach(item => {
            if (item.DriveLetter) {
              drives.push({
                letter: item.DriveLetter,
                label: item.Label || 'USB Drive'
              });
            }
          });
        } else if (data && data.DriveLetter) {
          drives.push({
            letter: data.DriveLetter,
            label: data.Label || 'USB Drive'
          });
        }

        this.handleDrivesList(drives);
      } catch (err) {
        // Fallback for raw objects or json parsing errors
      }
    });
  }

  private handleDrivesList(drives: UsbDrive[]) {
    const currentLetters = new Set(drives.map(d => d.letter));

    // Detect Insertions
    drives.forEach(drive => {
      if (!this.connectedDrives.has(drive.letter)) {
        this.connectedDrives.add(drive.letter);
        this.onUsbInsert(drive);
      }
    });

    // Detect Removals
    for (const letter of this.connectedDrives) {
      if (!currentLetters.has(letter)) {
        this.connectedDrives.delete(letter);
        this.onUsbRemove(letter);
      }
    }
  }

  private onUsbInsert(drive: UsbDrive) {
    console.log(`[USB Monitor] USB drive inserted: ${drive.label} (${drive.letter})`);
    
    this.sendToRenderer('usb-event', {
      action: 'Inserted',
      letter: drive.letter,
      label: drive.label,
      time: new Date().toLocaleTimeString()
    });

    // Auto scan USB drive
    this.scanUsbDrive(drive.letter);
  }

  private onUsbRemove(letter: string) {
    console.log(`[USB Monitor] USB drive removed: ${letter}`);
    
    this.sendToRenderer('usb-event', {
      action: 'Removed',
      letter: letter,
      label: '',
      time: new Date().toLocaleTimeString()
    });
  }

  private async scanUsbDrive(driveLetter: string) {
    console.log(`[USB Monitor] Initiating automatic threat scan on ${driveLetter}`);
    
    this.sendToRenderer('scan-status-update', {
      type: 'USB Scan',
      status: `Scanning Removable Drive ${driveLetter}...`,
      progress: 10
    });

    try {
      const filesToScan: string[] = [];
      this.findExecutables(driveLetter + '\\', filesToScan);

      if (filesToScan.length === 0) {
        this.sendToRenderer('scan-status-update', {
          type: 'USB Scan',
          status: `USB Drive ${driveLetter} scan finished. Clean.`,
          progress: 100
        });
        return;
      }

      let threatCount = 0;
      const settings = db.getSettings();

      for (let i = 0; i < filesToScan.length; i++) {
        const filePath = filesToScan[i];
        const progress = Math.round(((i + 1) / filesToScan.length) * 100);

        this.sendToRenderer('scan-status-update', {
          type: 'USB Scan',
          status: `Scanning file (${i+1}/${filesToScan.length}): ${path.basename(filePath)}`,
          progress
        });

        // Run scan
        const scanResult = await yaraScanner.scanFile(filePath);
        if (scanResult.isMalicious) {
          threatCount++;
          const matched = scanResult.matchedRules[0];

          let actionTaken = 'None';
          let status: 'Quarantined' | 'Detected' = 'Detected';

          if (settings.autoQuarantine) {
            try {
              await quarantine.quarantineFile(filePath, scanResult.hash);
              status = 'Quarantined';
              actionTaken = 'Quarantined';
            } catch (err: any) {
              actionTaken = 'Quarantine Failed';
            }
          }

          // Add to incidents DB
          const incident = db.addIncident({
            name: matched.name,
            path: filePath,
            hash: scanResult.hash,
            type: matched.category.toUpperCase(),
            severity: matched.severity,
            confidence: 100,
            status: status,
            actionTaken: actionTaken,
            details: `USB threat detection: ${matched.description}`
          });

          this.sendToRenderer('incident-detected', incident);
        }
      }

      this.sendToRenderer('scan-status-update', {
        type: 'USB Scan',
        status: `Scan completed on ${driveLetter}. Found ${threatCount} threat(s).`,
        progress: 100
      });

    } catch (err: any) {
      console.error(`USB Scan failed on ${driveLetter}:`, err.message);
    }
  }

  private findExecutables(dir: string, fileList: string[], depth = 0) {
    if (depth > 2) return; // Prevent scanning deep folders to maintain low CPU load
    try {
      if (!fs.existsSync(dir)) return;
      const files = fs.readdirSync(dir);

      for (const file of files) {
        const filePath = path.join(dir, file);
        try {
          const stat = fs.statSync(filePath);
          if (stat.isDirectory()) {
            this.findExecutables(filePath, fileList, depth + 1);
          } else {
            const ext = path.extname(file).toLowerCase();
            if (['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.msi'].includes(ext)) {
              fileList.push(filePath);
            }
          }
        } catch (e) {
          // Skip locked files
        }
      }
    } catch (e) {
      // Access denied
    }
  }

  private sendToRenderer(channel: string, data: any) {
    if (this.mainWindow && !this.mainWindow.isDestroyed()) {
      this.mainWindow.webContents.send(channel, data);
    }
  }
}

export const usbMonitor = new UsbMonitorService();
