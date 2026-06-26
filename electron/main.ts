import { app, BrowserWindow, ipcMain, Tray, Menu, dialog } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import { db } from './services/database';
import { quarantine } from './services/quarantine';
import { aiScanner } from './services/aiScanner';
import { yaraScanner } from './services/yaraScanner';
import { fileMonitor } from './services/fileMonitor';
import { processMonitor } from './services/processMonitor';
import { networkMonitor } from './services/networkMonitor';
import { registryMonitor } from './services/registryMonitor';
import { usbMonitor } from './services/usbMonitor';

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1366,
    height: 850,
    minWidth: 1024,
    minHeight: 720,
    title: "SentinelAI - Enterprise Endpoint Security",
    icon: path.join(__dirname, '../assets/icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    frame: true,
    show: false,
    backgroundColor: '#0B1220'
  });

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    // Open tools automatically in development
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist-renderer/index.html'));
  }

  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
    // Start background monitors
    if (mainWindow) {
      fileMonitor.start(mainWindow);
      processMonitor.start(mainWindow);
      networkMonitor.start(mainWindow);
      registryMonitor.start(mainWindow);
      usbMonitor.start(mainWindow);
    }
  });

  mainWindow.on('closed', () => {
    // Stop all monitoring threads/polls
    fileMonitor.stop();
    processMonitor.stop();
    networkMonitor.stop();
    registryMonitor.stop();
    usbMonitor.stop();
    mainWindow = null;
  });
}

function createTray() {
  const trayIconPath = path.join(__dirname, '../assets/icon.png');
  // Fallback placeholder
  if (fs.existsSync(trayIconPath)) {
    tray = new Tray(trayIconPath);
  } else {
    // Silent fail or placeholder in dev
  }

  const contextMenu = Menu.buildFromTemplate([
    { label: 'Open SentinelAI Dashboard', click: () => { mainWindow?.show(); } },
    { label: 'Run Full Scanner', click: () => { mainWindow?.webContents.send('trigger-quick-scan'); } },
    { type: 'separator' },
    { label: 'Quit SentinelAI', click: () => { app.quit(); } }
  ]);

  if (tray) {
    tray.setToolTip('SentinelAI EDR - Protected');
    tray.setContextMenu(contextMenu);
    tray.on('double-click', () => {
      mainWindow?.show();
    });
  }
}

// Single instance lock
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(() => {
    // Create folders
    const assetsDir = path.join(__dirname, '../assets');
    if (!fs.existsSync(assetsDir)) {
      fs.mkdirSync(assetsDir, { recursive: true });
    }
    
    createMainWindow();
    createTray();

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createMainWindow();
      }
    });
  });
}

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC Communications Setup
ipcMain.handle('get-incidents', () => {
  return db.getIncidents();
});

ipcMain.handle('clear-incidents', () => {
  db.clearIncidents();
  return { success: true };
});

ipcMain.handle('get-quarantine', () => {
  return db.getQuarantine();
});

ipcMain.handle('restore-quarantine', async (_, id: string) => {
  try {
    const filePath = await quarantine.restoreFile(id);
    return { success: true, path: filePath };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('delete-quarantine', (_, id: string) => {
  const success = quarantine.deleteFile(id);
  return { success };
});

ipcMain.handle('get-settings', () => {
  return db.getSettings();
});

ipcMain.handle('update-settings', (_, newSettings: any) => {
  return db.updateSettings(newSettings);
});

// Deep scan custom paths
ipcMain.handle('select-folder', async () => {
  if (!mainWindow) return null;
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  });
  return result.filePaths[0] || null;
});

// Deep / Custom scans execution
ipcMain.handle('run-system-scan', async (_, scanPath: string) => {
  if (!mainWindow) return { success: false };

  console.log(`[Scanner] Running scan on directory: ${scanPath}`);
  
  // Asynchronous recursive scanner
  scanDirectoryAsync(scanPath);
  return { success: true };
});

async function scanDirectoryAsync(dirPath: string) {
  const files: string[] = [];
  collectExecutables(dirPath, files);

  if (files.length === 0) {
    sendScanProgress('System Scan', 'Scan finished. No executables found.', 100);
    return;
  }

  let threatCount = 0;
  const settings = db.getSettings();

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const progress = Math.round(((i + 1) / files.length) * 100);
    
    sendScanProgress('System Scan', `Scanning file ${i + 1}/${files.length}: ${path.basename(file)}`, progress);

    const scanResult = await yaraScanner.scanFile(file);
    let isMalicious = scanResult.isMalicious;
    let threatName = scanResult.matchedRules[0]?.name || '';
    let category = scanResult.matchedRules[0]?.category || '';
    let severity: 'low' | 'medium' | 'high' | 'critical' = scanResult.matchedRules[0]?.severity || 'high';
    let confidence = 100;
    let reasons = scanResult.matchedRules[0]?.description ? [scanResult.matchedRules[0].description] : [];

    // If YARA is clean, run AI prediction
    if (!isMalicious) {
      const aiResult = await aiScanner.analyzeFile(file, scanResult.hash);
      if (aiResult.threatType !== 'Safe') {
        isMalicious = true;
        threatName = aiResult.threatType;
        category = aiResult.threatType;
        severity = aiResult.severity;
        confidence = aiResult.confidence;
        reasons = aiResult.reasons;
      }
    }

    if (isMalicious) {
      threatCount++;
      let actionTaken = 'None';
      let status: 'Quarantined' | 'Detected' = 'Detected';

      if (settings.autoQuarantine) {
        try {
          await quarantine.quarantineFile(file, scanResult.hash);
          status = 'Quarantined';
          actionTaken = 'Quarantined';
        } catch (err) {
          actionTaken = 'Quarantine Failed';
        }
      }

      const incident = db.addIncident({
        name: threatName,
        path: file,
        hash: scanResult.hash,
        type: category.toUpperCase(),
        severity: severity,
        confidence: confidence,
        status: status,
        actionTaken: actionTaken,
        details: reasons.join('. ')
      });

      mainWindow?.webContents.send('incident-detected', incident);
    }
  }

  sendScanProgress('System Scan', `Scan finished. Scanned ${files.length} executables, found ${threatCount} threat(s).`, 100);
}

function collectExecutables(dir: string, fileList: string[], depth = 0) {
  if (depth > 3) return; // Prevent infinite loops or deep file trees (e.g. node_modules)
  try {
    if (!fs.existsSync(dir)) return;
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      
      // Ignore node_modules, .git, and common cache folders to preserve performance
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'AppData') {
        continue;
      }

      if (entry.isDirectory()) {
        collectExecutables(fullPath, fileList, depth + 1);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.msi'].includes(ext)) {
          fileList.push(fullPath);
        }
      }
    }
  } catch (err) {
    // Skip directories with access restrictions
  }
}

function sendScanProgress(type: string, status: string, progress: number) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('scan-status-update', { type, status, progress });
  }
}

// Bridge AI Scan requests from File Monitor
ipcMain.on('ai-scan-request', async (_, data: { filePath: string; hash: string }) => {
  const { filePath, hash } = data;
  const aiResult = await aiScanner.analyzeFile(filePath, hash);
  const settings = db.getSettings();

  if (aiResult.threatType !== 'Safe') {
    let actionTaken = 'None';
    let status: 'Quarantined' | 'Detected' = 'Detected';

    if (settings.autoQuarantine) {
      try {
        await quarantine.quarantineFile(filePath, hash);
        status = 'Quarantined';
        actionTaken = 'Quarantined';
      } catch (err) {
        actionTaken = 'Quarantine Failed';
      }
    }

    const incident = db.addIncident({
      name: aiResult.threatType,
      path: filePath,
      hash: hash,
      type: aiResult.threatType.toUpperCase(),
      severity: aiResult.severity,
      confidence: aiResult.confidence,
      status: status,
      actionTaken: actionTaken,
      details: aiResult.reasons.join('. ')
    });

    mainWindow?.webContents.send('incident-detected', incident);
  } else {
    // Clean file event
    mainWindow?.webContents.send('file-event', {
      action: 'Analyzed (AI Safe)',
      path: filePath,
      time: new Date().toLocaleTimeString(),
      status: 'Safe'
    });
  }
});

// Tray quick scan listener
ipcMain.on('trigger-quick-scan', () => {
  mainWindow?.webContents.send('trigger-quick-scan');
});
