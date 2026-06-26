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

export interface Settings {
  aiSensitivity: number; // 1-100
  realTimeProtection: boolean;
  networkProtection: boolean;
  autoQuarantine: boolean;
  notifications: boolean;
  startWithWindows: boolean;
  virusTotalApiKey: string;
}

const defaultSettings: Settings = {
  aiSensitivity: 75,
  realTimeProtection: true,
  networkProtection: true,
  autoQuarantine: true,
  notifications: true,
  startWithWindows: false,
  virusTotalApiKey: ''
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

      // Initialize default settings row if not exists
      this.db.prepare(`
        INSERT OR IGNORE INTO settings (
          id, aiSensitivity, realTimeProtection, networkProtection, 
          autoQuarantine, notifications, startWithWindows, virusTotalApiKey
        ) VALUES (1, 75, 1, 1, 1, 1, 0, '')
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
          virusTotalApiKey: row.virusTotalApiKey || ''
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
}

export const db = new DatabaseService();
