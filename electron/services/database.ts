import { app } from 'electron';
import * as path from 'path';
import * as fs from 'fs';

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
  private dbPath: string;
  private data: {
    incidents: Incident[];
    quarantine: QuarantinedFile[];
    settings: Settings;
  };

  constructor() {
    // Determine path in app user data directory
    const userDataPath = app ? app.getPath('userData') : './';
    this.dbPath = path.join(userDataPath, 'sentinel_db.json');
    this.data = {
      incidents: [],
      quarantine: [],
      settings: defaultSettings
    };
    this.init();
  }

  private init() {
    try {
      if (fs.existsSync(this.dbPath)) {
        const fileContent = fs.readFileSync(this.dbPath, 'utf8');
        this.data = JSON.parse(fileContent);
        // Merge missing default settings if any
        this.data.settings = { ...defaultSettings, ...this.data.settings };
      } else {
        this.save();
      }
    } catch (error) {
      console.error('Failed to initialize SentinelAI DB:', error);
    }
  }

  private save() {
    try {
      const dir = path.dirname(this.dbPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(this.dbPath, JSON.stringify(this.data, null, 2), 'utf8');
    } catch (error) {
      console.error('Failed to save SentinelAI DB:', error);
    }
  }

  // Incidents
  public getIncidents(): Incident[] {
    return this.data.incidents;
  }

  public addIncident(incident: Omit<Incident, 'id' | 'time'>): Incident {
    const newIncident: Incident = {
      ...incident,
      id: `inc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      time: new Date().toISOString()
    };
    this.data.incidents.unshift(newIncident); // Newest first
    this.save();
    return newIncident;
  }

  public clearIncidents(): void {
    this.data.incidents = [];
    this.save();
  }

  // Quarantine
  public getQuarantine(): QuarantinedFile[] {
    return this.data.quarantine;
  }

  public addQuarantine(file: QuarantinedFile): void {
    this.data.quarantine.unshift(file);
    this.save();
  }

  public removeQuarantine(id: string): QuarantinedFile | undefined {
    const idx = this.data.quarantine.findIndex(f => f.id === id);
    if (idx !== -1) {
      const removed = this.data.quarantine.splice(idx, 1)[0];
      this.save();
      return removed;
    }
    return undefined;
  }

  // Settings
  public getSettings(): Settings {
    return this.data.settings;
  }

  public updateSettings(settings: Partial<Settings>): Settings {
    this.data.settings = { ...this.data.settings, ...settings };
    this.save();
    return this.data.settings;
  }
}

export const db = new DatabaseService();
