# SentinelAI - AI-Powered Endpoint Security Platform

An intelligent endpoint detection and response (EDR) desktop application built with Electron, React, and TypeScript. SentinelAI provides real-time system monitoring, threat detection using YARA rules and AI classification, and automated threat quarantine.

---

## Features

### Real-Time Monitoring

- **Active Processes** — Polls running processes via WMI with PID, command line, memory usage, and suspicious flag detection
- **Network Connections** — Monitors active TCP/UDP sockets, flags connections to suspicious remote addresses
- **File System Events** — Watches for file modifications in real-time using chokidar
- **Registry Changes** — Tracks Windows startup registry key modifications (Run/RunOnce)
- **USB Device Events** — Detects USB insertion and removal events

### Threat Detection & Response

- **YARA Pattern Matching** — Scans executables against YARA rule sets for known malware signatures
- **AI Behavioral Analysis** — Python-based ML model (scikit-learn) classifies unknown executables as Safe or malicious with confidence scoring
- **VirusTotal Integration** — Optional API key for cloud-based hash verification
- **Automated Quarantine** — Encrypts and isolates suspicious files using XOR byte-encryption
- **Real-Time Protection** — Terminates and blocks suspicious processes and network connections on detection

### Scanning Capabilities

- **Quick System Scan** — Scans user directories (Desktop, Documents, Downloads)
- **Deep Directory Sweep** — Recursive traversal across C:\ (excluding AppData, node_modules, .git)
- **Custom Directory Scan** — Scan any selected folder
- **Drag & Drop Scanning** — Drop files/folders for instant YARA + AI analysis
- **Pause/Resume/Cancel** — Full scan lifecycle control with state preservation

### System Dashboards

- **Overview Dashboard** — Agent status, active processes, established connections, threat statistics, AI sensitivity gauge, threat classification distribution, live system log feed
- **Live Monitoring** — Granular views for processes, network connections, file events, registry changes, and USB events with search/filter
- **Threat History** — Comprehensive log of all detected threats with severity, confidence scores, timestamps, and response actions
- **Quarantine Vault** — List of encrypted/isolated files with restore and permanent delete options

### User Interface

- Dark cyber-themed UI with neon cyan accents
- System tray integration with quick-scan and dashboard access
- Real system metrics: CPU usage, RAM usage, system specifications
- Compact header stats bar showing scan status, last scan time, CPU & RAM in real-time
- Single instance lock (prevents multiple app instances)
- Glass-morphism panels and glow effects

---

## Tech Stack

| Layer                | Technology                                       |
| -------------------- | ------------------------------------------------ |
| **Frontend**         | React 18, TypeScript, Tailwind CSS, Lucide Icons |
| **Desktop Shell**    | Electron 29                                      |
| **Build Tool**       | Vite 7                                           |
| **Backend Services** | Node.js (Electron main process)                  |
| **AI Engine**        | Python 3, scikit-learn, joblib                   |
| **Database**         | JSON-file based (electron-store style)           |
| **Scanning**         | YARA rules + Custom AI classifier                |
| **Packaging**        | electron-builder (NSIS + Portable)               |

---

## Project Structure

```
Sentinel-AI/
├── electron/                    # Electron main process
│   ├── main.ts                  # App entry, IPC handlers, scan logic, system stats
│   ├── preload.ts               # Context bridge (exposes API to renderer)
│   ├── tsconfig.json
│   └── services/
│       ├── aiScanner.ts         # Python AI model interface
│       ├── database.ts          # JSON file-based persistence
│       ├── fileMonitor.ts       # chokidar file system watcher
│       ├── networkMonitor.ts    # TCP/UDP connection polling
│       ├── processMonitor.ts    # WMI process polling
│       ├── quarantine.ts        # XOR encryption quarantine engine
│       ├── registryMonitor.ts   # Windows registry watcher
│       ├── usbMonitor.ts        # USB volume change detection
│       └── yaraScanner.ts       # YARA rule matching engine
├── renderer/                    # React frontend
│   ├── index.html
│   ├── tsconfig.json
│   └── src/
│       ├── App.tsx              # Main React component (all views, state, IPC)
│       ├── main.tsx             # React entry point
│       └── index.css            # Tailwind + custom styles
├── python-ai/                   # Python ML model
│   ├── train.py                 # Model training script
│   ├── inference.py             # Prediction server
│   └── requirements.txt
├── assets/                      # App icons and resources
├── package.json
├── tailwind.config.js
├── postcss.config.js
├── tsconfig.json                # Root project references
└── vite.config.ts               # Vite renderer bundler config
```

---

## Getting Started

### Prerequisites

- Node.js 18+
- npm 9+
- Python 3.8+ (for AI engine)
- Windows 10/11 (primary target; macOS/Linux compatibility partial)

### Development

```bash
# Install dependencies
npm install

# Install Python AI dependencies
pip install -r python-ai/requirements.txt

# Run in development mode (Vite dev server + Electron)
npm run dev
```

### Build & Package

```bash
# Full build (renderer + electron)
npm run build

# Package into Windows installer + portable executable
npm run package
```

Output will be in the `dist/` directory:

- `dist/win-unpacked/` — Unpacked application
- `dist/SentinelAI Setup x.x.x.exe` — NSIS installer
- `dist/SentinelAI x.x.x.exe` — Portable executable

---

## IPC API (Renderer ↔ Main Process)

The renderer communicates with the Electron main process via `window.electronAPI`:

| Method                     | Type   | Description                              |
| -------------------------- | ------ | ---------------------------------------- |
| `getIncidents()`           | invoke | Get all threat incidents                 |
| `clearIncidents()`         | invoke | Clear incident history                   |
| `getQuarantine()`          | invoke | Get quarantined files                    |
| `restoreQuarantine(id)`    | invoke | Restore file from quarantine             |
| `deleteQuarantine(id)`     | invoke | Permanently delete quarantined file      |
| `getSettings()`            | invoke | Get agent settings                       |
| `updateSettings(settings)` | invoke | Update agent settings                    |
| `selectFolder()`           | invoke | Open folder picker dialog                |
| `runSystemScan(path)`      | invoke | Start directory scan                     |
| `pauseScan()`              | invoke | Pause active scan                        |
| `resumeScan()`             | invoke | Resume paused scan                       |
| `cancelScan()`             | invoke | Cancel active scan                       |
| `isScanPaused()`           | invoke | Check if scan is paused                  |
| `getSystemStats()`         | invoke | Get current CPU + RAM usage              |
| `getSystemSpecs()`         | invoke | Get system specifications (CPU, RAM, OS) |
| `onFileEvent(cb)`          | event  | File system change events                |
| `onProcessUpdate(cb)`      | event  | Process list updates                     |
| `onNetworkUpdate(cb)`      | event  | Network connection updates               |
| `onRegistryEvent(cb)`      | event  | Registry change events                   |
| `onUsbEvent(cb)`           | event  | USB insertion/removal events             |
| `onScanStatusUpdate(cb)`   | event  | Scan progress updates                    |
| `onIncidentDetected(cb)`   | event  | New threat incident alert                |
| `onTriggerQuickScan(cb)`   | event  | Tray menu quick-scan trigger             |

---

## Configuration

Settings are persisted to a JSON file and include:

| Setting              | Type    | Default | Description                     |
| -------------------- | ------- | ------- | ------------------------------- |
| `aiSensitivity`      | number  | 75      | AI detection threshold (10–100) |
| `realTimeProtection` | boolean | true    | Process blocking on/off         |
| `networkProtection`  | boolean | true    | Network connection filtering    |
| `autoQuarantine`     | boolean | true    | Auto-encrypt detected threats   |
| `notifications`      | boolean | true    | OS tray notifications           |
| `startWithWindows`   | boolean | false   | Auto-launch on login            |
| `virusTotalApiKey`   | string  | ""      | VirusTotal API key              |

---

## Scanning Details

- Scans for executable types: `.exe`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.msi`
- Max traversal depth: 3 levels (prevents infinite recursion)
- Skips: `node_modules`, `.git`, `AppData` directories
- Each file is checked against YARA rules first, then AI model if YARA reports clean
- Real system CPU and RAM metrics update every 2 seconds during operation

---

## AI Engine

The Python-based AI classifier (`python-ai/`) uses:

- Feature extraction from PE file headers and entropy analysis
- scikit-learn Random Forest classifier
- Threshold-based severity classification (low/medium/high/critical)
- Confidence scoring for each prediction

To retrain the model:

```bash
cd python-ai
pip install -r requirements.txt
python train.py
```

---

## Version History

- **v1.0.1** — Real system metrics, pause/resume scan, Threat History layout fix, compact stats bar, system specs display
- **v1.0.0** — Initial release with full EDR capabilities, AI detection, YARA scanning, live monitoring, quarantine vault
