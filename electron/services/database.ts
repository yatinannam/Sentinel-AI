import { app } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import Database from 'better-sqlite3';

export interface Incident {
  id: string;
  name: string;
  path: string;
  hash: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  time: string;
  status: 'Quarantined' | 'Killed' | 'Blocked' | 'Allowed' | 'Detected';
  actionTaken: string;
  details: string;
}

export interface QuarantinedFile {
  id: string;
  originalPath: string;
  quarantinePath: string;
  hash: string;
  size: number;
  date: string;
}

export interface ScanReport {
  id: string;
  date: string;
  scanType: string;
  duration: number; // in seconds
  filesScanned: number;
  filesSkipped: number;
  threatsFound: number;
  threatsRemoved: number;
  securityScore: number;
  cpuUsage: number;
  detailsJson: string; // JSON string
}

export interface FileCacheEntry {
  filePath: string;
  hash: string;
  mtime: number;
  status: 'Safe' | 'Suspicious' | 'Malicious';
  finalScore: number;
}

export interface Settings {
  aiSensitivity: number; // 1-100
  realTimeProtection: boolean;
  networkProtection: boolean;
  autoQuarantine: boolean;
  notifications: boolean;
  startWithWindows: boolean;
  virusTotalApiKey: string;
  minimizeToTray: boolean;
  autoUpdates: boolean;
  aiDetection: boolean;
  ransomwareShield: boolean;
  usbProtection: boolean;
  networkMonitoring: boolean;
  desktopNotifications: boolean;
  emailAlerts: boolean;
  shareIntel: boolean;
  cloudAi: boolean;
  firstTimeUser: boolean;
}

const defaultSettings: Settings = {
  aiSensitivity: 75,
  realTimeProtection: true,
  networkProtection: true,
  autoQuarantine: true,
  notifications: true,
  startWithWindows: false,
  virusTotalApiKey: '',
  minimizeToTray: true,
  autoUpdates: true,
  aiDetection: true,
  ransomwareShield: true,
  usbProtection: true,
  networkMonitoring: true,
  desktopNotifications: true,
  emailAlerts: false,
  shareIntel: true,
  cloudAi: true,
  firstTimeUser: true
};

class DatabaseService {
  private db: Database.Database;

  constructor() {
    // Determine path in app user data directory
    const userDataPath = app ? app.getPath('userData') : './';
    const dbPath = path.join(userDataPath, 'sentinel_db.sqlite');
    
    // Ensure directory exists
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    console.log(`[Database] Initializing SQLite database at: ${dbPath}`);
    this.db = new Database(dbPath);
    this.init();
  }

  private init() {
    try {
      // 1. Create settings table
      this.db.prepare(`
        CREATE TABLE IF NOT EXISTS settings (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          aiSensitivity INTEGER DEFAULT 75,
          realTimeProtection INTEGER DEFAULT 1,
          networkProtection INTEGER DEFAULT 1,
          autoQuarantine INTEGER DEFAULT 1,
          notifications INTEGER DEFAULT 1,
          startWithWindows INTEGER DEFAULT 0,
          virusTotalApiKey TEXT DEFAULT ''
        )
      `).run();

      // Dynamically migrate table columns if they do not exist
      const columnsToAdd = [
        { name: 'minimizeToTray', type: 'INTEGER DEFAULT 1' },
        { name: 'autoUpdates', type: 'INTEGER DEFAULT 1' },
        { name: 'aiDetection', type: 'INTEGER DEFAULT 1' },
        { name: 'ransomwareShield', type: 'INTEGER DEFAULT 1' },
        { name: 'usbProtection', type: 'INTEGER DEFAULT 1' },
        { name: 'networkMonitoring', type: 'INTEGER DEFAULT 1' },
        { name: 'desktopNotifications', type: 'INTEGER DEFAULT 1' },
        { name: 'emailAlerts', type: 'INTEGER DEFAULT 0' },
        { name: 'shareIntel', type: 'INTEGER DEFAULT 1' },
        { name: 'cloudAi', type: 'INTEGER DEFAULT 1' },
        { name: 'firstTimeUser', type: 'INTEGER DEFAULT 1' }
      ];

      for (const col of columnsToAdd) {
        try {
          this.db.prepare(`ALTER TABLE settings ADD COLUMN ${col.name} ${col.type}`).run();
        } catch (e) {
          // Column already exists, safe to ignore
        }
      }

      // Initialize default settings row if not exists
      this.db.prepare(`
        INSERT OR IGNORE INTO settings (
          id, aiSensitivity, realTimeProtection, networkProtection, 
          autoQuarantine, notifications, startWithWindows, virusTotalApiKey,
          minimizeToTray, autoUpdates, aiDetection, ransomwareShield,
          usbProtection, networkMonitoring, desktopNotifications, emailAlerts,
          shareIntel, cloudAi, firstTimeUser
        ) VALUES (1, 75, 1, 1, 1, 1, 0, '', 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1)
      `).run();

      // 2. Create incidents table
      this.db.prepare(`
        CREATE TABLE IF NOT EXISTS incidents (
          id TEXT PRIMARY KEY,
          name TEXT,
          path TEXT,
          hash TEXT,
          type TEXT,
          severity TEXT,
          confidence INTEGER,
          time TEXT,
          status TEXT,
          actionTaken TEXT,
          details TEXT
        )
      `).run();

      // Create index on time for fast sorting
      this.db.prepare(`
        CREATE INDEX IF NOT EXISTS idx_incidents_time ON incidents(time DESC)
      `).run();

      // 3. Create quarantine table
      this.db.prepare(`
        CREATE TABLE IF NOT EXISTS quarantine (
          id TEXT PRIMARY KEY,
          originalPath TEXT,
          quarantinePath TEXT,
          hash TEXT,
          size INTEGER,
          date TEXT
        )
      `).run();

      // 4. Create scans table
      this.db.prepare(`
        CREATE TABLE IF NOT EXISTS scans (
          id TEXT PRIMARY KEY,
          date TEXT,
          scanType TEXT,
          duration INTEGER,
          filesScanned INTEGER,
          filesSkipped INTEGER,
          threatsFound INTEGER,
          threatsRemoved INTEGER,
          securityScore INTEGER,
          cpuUsage INTEGER,
          detailsJson TEXT
        )
      `).run();

      this.db.prepare(`
        CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(date DESC)
      `).run();

      // 5. Create file_cache table
      this.db.prepare(`
        CREATE TABLE IF NOT EXISTS file_cache (
          filePath TEXT PRIMARY KEY,
          hash TEXT,
          mtime INTEGER,
          status TEXT,
          finalScore INTEGER
        )
      `).run();

    } catch (error) {
      console.error('[Database] Failed to initialize tables:', error);
    }
  }

  // Incidents
  public getIncidents(): Incident[] {
    try {
      const rows = this.db.prepare('SELECT * FROM incidents ORDER BY time DESC').all() as any[];
      return rows.map(row => ({
        id: row.id,
        name: row.name,
        path: row.path,
        hash: row.hash,
        type: row.type,
        severity: row.severity,
        confidence: Number(row.confidence),
        time: row.time,
        status: row.status,
        actionTaken: row.actionTaken,
        details: row.details
      }));
    } catch (error) {
      console.error('[Database] Failed to get incidents:', error);
      return [];
    }
  }

  public addIncident(incident: Omit<Incident, 'id' | 'time'>): Incident {
    try {
      const id = `inc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const time = new Date().toISOString();
      
      const stmt = this.db.prepare(`
        INSERT INTO incidents (id, name, path, hash, type, severity, confidence, time, status, actionTaken, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      
      stmt.run(
        id,
        incident.name,
        incident.path,
        incident.hash,
        incident.type,
        incident.severity,
        incident.confidence,
        time,
        incident.status,
        incident.actionTaken,
        incident.details
      );

      return {
        ...incident,
        id,
        time
      };
    } catch (error) {
      console.error('[Database] Failed to add incident:', error);
      throw error;
    }
  }

  public clearIncidents(): void {
    try {
      this.db.prepare('DELETE FROM incidents').run();
    } catch (error) {
      console.error('[Database] Failed to clear incidents:', error);
    }
  }

  // Quarantine
  public getQuarantine(): QuarantinedFile[] {
    try {
      const rows = this.db.prepare('SELECT * FROM quarantine ORDER BY date DESC').all() as any[];
      return rows.map(row => ({
        id: row.id,
        originalPath: row.originalPath,
        quarantinePath: row.quarantinePath,
        hash: row.hash,
        size: Number(row.size),
        date: row.date
      }));
    } catch (error) {
      console.error('[Database] Failed to get quarantine files:', error);
      return [];
    }
  }

  public addQuarantine(file: QuarantinedFile): void {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO quarantine (id, originalPath, quarantinePath, hash, size, date)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        file.id,
        file.originalPath,
        file.quarantinePath,
        file.hash,
        file.size,
        file.date
      );
    } catch (error) {
      console.error('[Database] Failed to add quarantined file record:', error);
    }
  }

  public removeQuarantine(id: string): QuarantinedFile | undefined {
    try {
      const file = this.db.prepare('SELECT * FROM quarantine WHERE id = ?').get(id) as any;
      if (file) {
        this.db.prepare('DELETE FROM quarantine WHERE id = ?').run(id);
        return {
          id: file.id,
          originalPath: file.originalPath,
          quarantinePath: file.quarantinePath,
          hash: file.hash,
          size: Number(file.size),
          date: file.date
        };
      }
      return undefined;
    } catch (error) {
      console.error('[Database] Failed to remove quarantined file record:', error);
      return undefined;
    }
  }

  // Settings
  public getSettings(): Settings {
    try {
      const row = this.db.prepare('SELECT * FROM settings WHERE id = 1').get() as any;
      if (row) {
        return {
          aiSensitivity: Number(row.aiSensitivity),
          realTimeProtection: Boolean(row.realTimeProtection),
          networkProtection: Boolean(row.networkProtection),
          autoQuarantine: Boolean(row.autoQuarantine),
          notifications: Boolean(row.notifications),
          startWithWindows: Boolean(row.startWithWindows),
          virusTotalApiKey: row.virusTotalApiKey || '',
          minimizeToTray: Boolean(row.minimizeToTray ?? 1),
          autoUpdates: Boolean(row.autoUpdates ?? 1),
          aiDetection: Boolean(row.aiDetection ?? 1),
          ransomwareShield: Boolean(row.ransomwareShield ?? 1),
          usbProtection: Boolean(row.usbProtection ?? 1),
          networkMonitoring: Boolean(row.networkMonitoring ?? 1),
          desktopNotifications: Boolean(row.desktopNotifications ?? 1),
          emailAlerts: Boolean(row.emailAlerts ?? 0),
          shareIntel: Boolean(row.shareIntel ?? 1),
          cloudAi: Boolean(row.cloudAi ?? 1),
          firstTimeUser: Boolean(row.firstTimeUser ?? 1)
        };
      }
      return defaultSettings;
    } catch (error) {
      console.error('[Database] Failed to get settings:', error);
      return defaultSettings;
    }
  }

  public updateSettings(settings: Partial<Settings>): Settings {
    try {
      const keys = Object.keys(settings);
      if (keys.length > 0) {
        const setClause = keys.map(k => `${k} = ?`).join(', ');
        const values = keys.map(k => {
          const val = (settings as any)[k];
          return typeof val === 'boolean' ? (val ? 1 : 0) : val;
        });
        
        this.db.prepare(`UPDATE settings SET ${setClause} WHERE id = 1`).run(...values);
      }
      return this.getSettings();
    } catch (error) {
      console.error('[Database] Failed to update settings:', error);
      return this.getSettings();
    }
  }

  // Scans History
  public getScans(): ScanReport[] {
    try {
      const rows = this.db.prepare('SELECT * FROM scans ORDER BY date DESC').all() as any[];
      return rows.map(r => ({
        id: r.id,
        date: r.date,
        scanType: r.scanType,
        duration: Number(r.duration),
        filesScanned: Number(r.filesScanned),
        filesSkipped: Number(r.filesSkipped),
        threatsFound: Number(r.threatsFound),
        threatsRemoved: Number(r.threatsRemoved),
        securityScore: Number(r.securityScore),
        cpuUsage: Number(r.cpuUsage),
        detailsJson: r.detailsJson
      }));
    } catch (error) {
      console.error('[Database] Failed to get scan logs:', error);
      return [];
    }
  }

  public addScan(scan: Omit<ScanReport, 'id' | 'date'>): ScanReport {
    try {
      const id = `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const date = new Date().toISOString();
      
      const stmt = this.db.prepare(`
        INSERT INTO scans (id, date, scanType, duration, filesScanned, filesSkipped, threatsFound, threatsRemoved, securityScore, cpuUsage, detailsJson)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      
      stmt.run(
        id,
        date,
        scan.scanType,
        scan.duration,
        scan.filesScanned,
        scan.filesSkipped,
        scan.threatsFound,
        scan.threatsRemoved,
        scan.securityScore,
        scan.cpuUsage,
        scan.detailsJson
      );

      return {
        ...scan,
        id,
        date
      };
    } catch (error) {
      console.error('[Database] Failed to save scan report:', error);
      throw error;
    }
  }

  // Hash Cache
  public getFileCache(filePath: string): FileCacheEntry | null {
    try {
      const row = this.db.prepare('SELECT * FROM file_cache WHERE filePath = ?').get(filePath) as any;
      if (row) {
        return {
          filePath: row.filePath,
          hash: row.hash,
          mtime: Number(row.mtime),
          status: row.status as any,
          finalScore: Number(row.finalScore)
        };
      }
      return null;
    } catch (error) {
      console.error('[Database] Failed to fetch file cache:', error);
      return null;
    }
  }

  public setFileCache(entry: FileCacheEntry): void {
    try {
      const stmt = this.db.prepare(`
        INSERT OR REPLACE INTO file_cache (filePath, hash, mtime, status, finalScore)
        VALUES (?, ?, ?, ?, ?)
      `);
      stmt.run(
        entry.filePath,
        entry.hash,
        entry.mtime,
        entry.status,
        entry.finalScore
      );
    } catch (error) {
      console.error('[Database] Failed to set file cache:', error);
    }
  }
}

export const db = new DatabaseService();
