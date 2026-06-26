import { exec } from 'child_process';
import { BrowserWindow } from 'electron';
import { db } from './database';
import { yaraScanner } from './yaraScanner';

export interface RegistryEntry {
  keyPath: string;
  name: string;
  type: string;
  value: string;
}

class RegistryMonitorService {
  private mainWindow: BrowserWindow | null = null;
  private intervalId: NodeJS.Timeout | null = null;
  private isMonitoring: boolean = false;
  private startupCache: Map<string, string> = new Map();

  private runKeys = [
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
  ];

  public start(window: BrowserWindow) {
    if (this.isMonitoring) return;
    this.mainWindow = window;
    this.isMonitoring = true;

    // Load initial registry startup entries into cache
    this.initializeCache().then(() => {
      // Poll registry every 6 seconds
      this.intervalId = setInterval(() => this.pollRegistry(), 6000);
    });
  }

  public stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this.isMonitoring = false;
  }

  private async initializeCache() {
    for (const key of this.runKeys) {
      const entries = await this.queryRegistryKey(key);
      entries.forEach(entry => {
        this.startupCache.set(`${entry.keyPath}\\${entry.name}`, entry.value);
      });
    }
  }

  private async pollRegistry() {
    const registryEvents: any[] = [];

    for (const key of this.runKeys) {
      const currentEntries = await this.queryRegistryKey(key);
      const currentKeys = new Set<string>();

      for (const entry of currentEntries) {
        const cacheKey = `${entry.keyPath}\\${entry.name}`;
        currentKeys.add(cacheKey);

        const cachedValue = this.startupCache.get(cacheKey);

        if (cachedValue === undefined) {
          // New Registry Key Added! (Persistence mechanism)
          console.warn(`[Registry Monitor] New startup entry added: ${entry.name} -> ${entry.value}`);
          
          this.startupCache.set(cacheKey, entry.value);
          registryEvents.push({
            action: 'Added (Startup)',
            key: entry.keyPath,
            name: entry.name,
            value: entry.value,
            time: new Date().toLocaleTimeString(),
            status: 'Analyzing...'
          });

          // Perform analysis on the registry target executable
          this.analyzeRegistryTarget(entry);

        } else if (cachedValue !== entry.value) {
          // Registry Key Modified!
          console.warn(`[Registry Monitor] Startup entry modified: ${entry.name} was ${cachedValue}, now ${entry.value}`);
          
          this.startupCache.set(cacheKey, entry.value);
          registryEvents.push({
            action: 'Modified',
            key: entry.keyPath,
            name: entry.name,
            value: entry.value,
            time: new Date().toLocaleTimeString(),
            status: 'Analyzing...'
          });

          this.analyzeRegistryTarget(entry);
        }
      }

      // Check for deletions
      for (const [cacheKey, cachedValue] of this.startupCache.entries()) {
        if (cacheKey.startsWith(key) && !currentKeys.has(cacheKey)) {
          const keyName = cacheKey.substring(cacheKey.lastIndexOf('\\') + 1);
          console.log(`[Registry Monitor] Startup entry deleted: ${keyName}`);
          
          this.startupCache.delete(cacheKey);
          registryEvents.push({
            action: 'Deleted',
            key: key,
            name: keyName,
            value: cachedValue,
            time: new Date().toLocaleTimeString(),
            status: 'Safe'
          });
        }
      }
    }

    if (registryEvents.length > 0) {
      this.sendToRenderer('registry-event', registryEvents);
    }
  }

  private queryRegistryKey(keyPath: string): Promise<RegistryEntry[]> {
    return new Promise((resolve) => {
      // Query registry using native 'reg' command
      exec(`reg query "${keyPath}"`, (error, stdout) => {
        if (error) {
          // If key does not exist or access denied, return empty array
          resolve([]);
          return;
        }

        const lines = stdout.split(/\r?\n/);
        const entries: RegistryEntry[] = [];

        lines.forEach(line => {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('HKEY_')) return;

          // Reg query output format: Name   REG_SZ    PathToExe
          const parts = trimmed.split(/\s{4,}/); // split by 4 or more spaces
          if (parts.length >= 3) {
            entries.push({
              keyPath,
              name: parts[0],
              type: parts[1],
              value: parts[2]
            });
          }
        });

        resolve(entries);
      });
    });
  }

  private async analyzeRegistryTarget(entry: RegistryEntry) {
    // Extract executable path from registry command arguments
    // e.g. "C:\Program Files\App\app.exe" /background -> C:\Program Files\App\app.exe
    let targetPath = entry.value.trim();
    if (targetPath.startsWith('"')) {
      const secondQuote = targetPath.indexOf('"', 1);
      if (secondQuote !== -1) {
        targetPath = targetPath.substring(1, secondQuote);
      }
    } else {
      const spaceIdx = targetPath.indexOf(' ');
      if (spaceIdx !== -1) {
        targetPath = targetPath.substring(0, spaceIdx);
      }
    }

    try {
      // Run quick scan
      const scanResult = await yaraScanner.scanFile(targetPath);
      if (scanResult.isMalicious) {
        const matched = scanResult.matchedRules[0];
        console.warn(`[Registry Monitor] Malicious startup file found: ${targetPath}`);

        const settings = db.getSettings();
        let actionTaken = 'None';
        let status: 'Blocked' | 'Detected' = 'Detected';

        if (settings.realTimeProtection) {
          // Delete malicious startup registry key to restore persistence
          const deleteCmd = `reg delete "${entry.keyPath}" /v "${entry.name}" /f`;
          exec(deleteCmd, (delErr) => {
            if (delErr) {
              console.error(`Failed to delete registry key ${entry.name}:`, delErr.message);
            } else {
              console.log(`[Registry Monitor] Deleted malicious startup registry entry: ${entry.name}`);
            }
          });
          actionTaken = 'Registry Key Deleted';
          status = 'Blocked';
        }

        // Log incident
        const incident = db.addIncident({
          name: 'MALICIOUS_PERSISTENCE',
          path: entry.keyPath,
          hash: scanResult.hash,
          type: 'PERSISTENCE KEY',
          severity: 'high',
          confidence: 95,
          status: status,
          actionTaken: actionTaken,
          details: `Startup persistence targeting malicious binary. Target: ${targetPath}. Signature: ${matched.name}`
        });

        this.sendToRenderer('incident-detected', incident);
      }
    } catch (err: any) {
      console.error('Error analyzing registry target path:', err.message);
    }
  }

  private sendToRenderer(channel: string, data: any) {
    if (this.mainWindow && !this.mainWindow.isDestroyed()) {
      this.mainWindow.webContents.send(channel, data);
    }
  }
}

export const registryMonitor = new RegistryMonitorService();
