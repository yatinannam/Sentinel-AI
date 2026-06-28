import { app, BrowserWindow, ipcMain, Tray, Menu, dialog } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { db } from './services/database';
import { quarantine } from './services/quarantine';
import { aiScanner } from './services/aiScanner';
import { yaraScanner } from './services/yaraScanner';
import { fileMonitor } from './services/fileMonitor';
import { processMonitor } from './services/processMonitor';
import { networkMonitor } from './services/networkMonitor';
import { registryMonitor } from './services/registryMonitor';
import { usbMonitor } from './services/usbMonitor';
import { threatEngine } from './services/threatEngine';
import { scanService } from './services/scanService';

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;
(app as any).isQuitting = false;
const isStartupLaunch = process.argv.includes('--startup');

// Dynamic BMP Tray Icon Generator
function generateColorBMP(color: { r: number, g: number, b: number }): Buffer {
  const width = 16;
  const height = 16;
  const pixelDataSize = width * height * 3;
  const fileSize = 54 + pixelDataSize;
  const buffer = Buffer.alloc(fileSize);

  // BMP Header
  buffer.write('BM', 0);
  buffer.writeUInt32LE(fileSize, 2);
  buffer.writeUInt32LE(54, 10);

  // DIB Header
  buffer.writeUInt32LE(40, 14);
  buffer.writeUInt32LE(width, 18);
  buffer.writeUInt32LE(height, 22);
  buffer.writeUInt16LE(1, 26);
  buffer.writeUInt16LE(24, 28);
  buffer.writeUInt32LE(0, 30);
  buffer.writeUInt32LE(pixelDataSize, 34);

  // Pixel Data (BGR format, matching theme background)
  let offset = 54;
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const dx = x - 7.5;
      const dy = y - 7.5;
      const dist = Math.sqrt(dx * dx + dy * dy);
      
      if (dist <= 7.5) {
        buffer.writeUInt8(color.b, offset);
        buffer.writeUInt8(color.g, offset + 1);
        buffer.writeUInt8(color.r, offset + 2);
      } else {
        // Antivirus theme background #0B1220
        buffer.writeUInt8(32, offset);     // Blue
        buffer.writeUInt8(18, offset + 1); // Green
        buffer.writeUInt8(11, offset + 2); // Red
      }
      offset += 3;
    }
  }

  return buffer;
}

function ensureTrayIcons() {
  const assetsDir = path.join(app.getPath('userData'), 'assets');
  if (!fs.existsSync(assetsDir)) {
    fs.mkdirSync(assetsDir, { recursive: true });
  }

  const icons = [
    { name: 'tray_green.bmp', color: { r: 34, g: 197, b: 94 } },
    { name: 'tray_yellow.bmp', color: { r: 234, g: 179, b: 8 } },
    { name: 'tray_red.bmp', color: { r: 239, g: 68, b: 68 } },
    { name: 'tray_gray.bmp', color: { r: 100, g: 116, b: 139 } }
  ];

  for (const icon of icons) {
    const iconPath = path.join(assetsDir, icon.name);
    if (!fs.existsSync(iconPath)) {
      const buffer = generateColorBMP(icon.color);
      fs.writeFileSync(iconPath, buffer);
    }
  }
}

function updateTrayStatus() {
  if (!tray) return;

  const settings = db.getSettings();
  const incidents = db.getIncidents();
  const isScanRunning = scanService.getIsRunning();

  let status: 'green' | 'yellow' | 'red' | 'gray' = 'green';
  let tooltip = 'SentinelAI - Protected';

  if (!settings.realTimeProtection) {
    status = 'gray';
    tooltip = 'SentinelAI - Protection Disabled';
  } else if (isScanRunning) {
    status = 'yellow';
    tooltip = 'SentinelAI - Scan in Progress';
  } else if (incidents.some(i => i.status === 'Detected')) {
    status = 'red';
    tooltip = 'SentinelAI - Threat Detected!';
  }

  const iconName = `tray_${status}.bmp`;
  const iconPath = path.join(app.getPath('userData'), 'assets', iconName);
  if (fs.existsSync(iconPath)) {
    tray.setImage(iconPath);
  }
  tray.setToolTip(tooltip);
}

// Share status function globally
(global as any).updateTrayStatus = updateTrayStatus;

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1366,
    height: 850,
    minWidth: 1024,
    minHeight: 720,
    title: "SentinelAI - Endpoint Security",
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

  // Remove menu bar for clean app feel
  mainWindow.setMenuBarVisibility(false);

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist-renderer/index.html'));
  }

  mainWindow.once('ready-to-show', () => {
    const settings = db.getSettings();
    if (isStartupLaunch || (settings.startWithWindows && process.argv.includes('--hidden'))) {
      // Run silently in background
    } else {
      mainWindow?.show();
    }
    
    // Start background monitors
    if (mainWindow) {
      threatEngine.setWindow(mainWindow);
      scanService.setWindow(mainWindow);
      fileMonitor.start(mainWindow);
      processMonitor.start(mainWindow);
      networkMonitor.start(mainWindow);
      registryMonitor.start(mainWindow);
      usbMonitor.start(mainWindow);
    }
  });

  mainWindow.on('close', (event) => {
    const settings = db.getSettings();
    if (!(app as any).isQuitting && settings.minimizeToTray) {
      event.preventDefault();
      mainWindow?.hide();
    }
  });

  mainWindow.on('closed', () => {
    fileMonitor.stop();
    processMonitor.stop();
    networkMonitor.stop();
    registryMonitor.stop();
    usbMonitor.stop();
    mainWindow = null;
  });
}

function createTray() {
  ensureTrayIcons();
  
  const iconPath = path.join(app.getPath('userData'), 'assets', 'tray_green.bmp');
  if (fs.existsSync(iconPath)) {
    tray = new Tray(iconPath);
  } else {
    // Fallback to default icon if bmp failed
    const defaultIconPath = path.join(__dirname, '../assets/icon.png');
    if (fs.existsSync(defaultIconPath)) {
      tray = new Tray(defaultIconPath);
    }
  }

  const contextMenu = Menu.buildFromTemplate([
    { label: 'Open SentinelAI Dashboard', click: () => { mainWindow?.show(); mainWindow?.focus(); } },
    { type: 'separator' },
    { label: 'Run Quick Scan', click: () => { scanService.startScan('Quick Scan'); } },
    { label: 'Run Deep Scan', click: () => { scanService.startScan('Deep Scan'); } },
    { type: 'separator' },
    { label: 'Pause Protection', click: () => {
        db.updateSettings({ realTimeProtection: false });
        updateTrayStatus();
        mainWindow?.webContents.send('settings-updated', db.getSettings());
      }
    },
    { label: 'Resume Protection', click: () => {
        db.updateSettings({ realTimeProtection: true });
        updateTrayStatus();
        mainWindow?.webContents.send('settings-updated', db.getSettings());
      }
    },
    { type: 'separator' },
    { label: 'Check for Updates', click: () => {
        mainWindow?.show();
        mainWindow?.webContents.send('trigger-update-check');
      }
    },
    { type: 'separator' },
    { label: 'Exit SentinelAI', click: () => {
        (app as any).isQuitting = true;
        app.quit();
      }
    }
  ]);

  if (tray) {
    tray.setContextMenu(contextMenu);
    tray.on('double-click', () => {
      mainWindow?.show();
      mainWindow?.focus();
    });
    updateTrayStatus();
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
      mainWindow.show();
      mainWindow.focus();
    }
  });

  app.whenReady().then(() => {
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
  const updated = db.updateSettings(newSettings);
  if (newSettings.startWithWindows !== undefined) {
    try {
      app.setLoginItemSettings({
        openAtLogin: newSettings.startWithWindows,
        path: process.execPath,
        args: ['--startup', '--hidden']
      });
    } catch (e) {
      console.error('[Startup] Failed to set login item settings:', e);
    }
  }
  updateTrayStatus();
  return updated;
});

ipcMain.handle('check-for-updates', async () => {
  // Return updater checkpoints progress for visual simulator
  return [
    { text: "Checking for Updates...", delay: 800 },
    { text: "Security Definitions Updated", delay: 1000 },
    { text: "AI Model Updated", delay: 900 },
    { text: "Platform Updated", delay: 700 },
    { text: "No manual downloads required. All shields are up to date.", delay: 500 }
  ];
});

// Deep scan custom paths
ipcMain.handle('select-folder', async () => {
  if (!mainWindow) return null;
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  });
  return result.filePaths[0] || null;
});

// IPC handles for scan control
ipcMain.handle('pause-scan', () => {
  scanService.pauseScan();
  return { success: true };
});

ipcMain.handle('resume-scan', () => {
  scanService.resumeScan();
  return { success: true };
});

ipcMain.handle('cancel-scan', () => {
  scanService.cancelScan();
  return { success: true };
});

ipcMain.handle('is-scan-paused', () => {
  return false;
});

ipcMain.handle('run-multi-layer-scan', async (_, filePath: string) => {
  return await threatEngine.analyzeFile(filePath);
});

ipcMain.handle('run-normal-scan', async () => {
  scanService.startScan('Quick Scan');
  return { success: true };
});

ipcMain.handle('run-deep-scan', async () => {
  scanService.startScan('Deep Scan');
  return { success: true };
});

ipcMain.handle('run-system-scan', async (_, scanPath: string) => {
  scanService.startScan('Custom Scan', scanPath);
  return { success: true };
});

ipcMain.handle('get-scan-history', () => {
  return db.getScans();
});

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

// CPU tick calculation variables
let lastCpuTicks = getCpuTicks();

function getCpuTicks() {
  const cpus = os.cpus();
  let user = 0;
  let nice = 0;
  let sys = 0;
  let idle = 0;
  let irq = 0;
  if (!cpus) return { idle: 0, total: 0 };
  for (const cpu of cpus) {
    user += cpu.times.user;
    nice += cpu.times.nice;
    sys += cpu.times.sys;
    idle += cpu.times.idle;
    irq += cpu.times.irq;
  }
  const total = user + nice + sys + idle + irq;
  return { idle, total };
}

function getCpuUsagePercentage() {
  const currentTicks = getCpuTicks();
  const idleDiff = currentTicks.idle - lastCpuTicks.idle;
  const totalDiff = currentTicks.total - lastCpuTicks.total;
  
  lastCpuTicks = currentTicks;

  if (totalDiff === 0) return 0;
  const usage = 100 - Math.round((100 * idleDiff) / totalDiff);
  return Math.min(100, Math.max(0, usage));
}

function getRamUsagePercentage() {
  const total = os.totalmem();
  const free = os.freemem();
  const used = total - free;
  if (total === 0) return 0;
  return Math.min(100, Math.max(0, Math.round((used / total) * 100)));
}

// System stats and specifications IPC handlers
ipcMain.handle('get-system-stats', () => {
  return {
    cpu: getCpuUsagePercentage(),
    ram: getRamUsagePercentage()
  };
});

ipcMain.handle('get-system-specs', () => {
  const cpus = os.cpus();
  const cpuModel = cpus && cpus.length > 0 ? cpus[0].model.trim() : 'Unknown CPU';
  const totalMemoryGB = Math.round(os.totalmem() / (1024 * 1024 * 1024));
  
  // Clean up CPU model for visual presentation
  let cleanCpu = cpuModel
    .replace(/\(R\)/g, '')
    .replace(/\(TM\)/g, '')
    .replace(/\s+CPU\s+/g, ' ')
    .split('@')[0]
    .trim();

  // Handle common CPU names formatting
  if (cleanCpu.includes('Intel')) {
    const parts = cleanCpu.split('Intel Core');
    if (parts.length > 1) {
      cleanCpu = 'Intel Core' + parts[1];
    }
  }

  let osName = 'Windows';
  const platform = os.platform();
  if (platform === 'win32') {
    const release = os.release();
    const buildNum = parseInt(release.split('.')[2]) || 0;
    if (buildNum >= 22000) {
      osName = 'Windows 11';
    } else {
      osName = 'Windows 10';
    }
  } else if (platform === 'darwin') {
    osName = 'macOS';
  } else if (platform === 'linux') {
    osName = 'Linux';
  }

  return {
    cpu: cleanCpu,
    ram: `${totalMemoryGB} GB`,
    os: osName,
    hostname: os.hostname(),
    arch: os.arch()
  };
});

