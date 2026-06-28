import React, { useEffect, useState, useRef } from 'react';
import { 
  Shield, Cpu, Network, History, Settings as SettingsIcon, 
  Trash2, RotateCcw, AlertTriangle, Search, RefreshCw, 
  Play, FolderOpen, Eye, EyeOff, Upload,
  Layers, Lock, Laptop, Pause, ChevronDown, ChevronUp, Activity
} from 'lucide-react';

// TypeScript Interfaces for IPC Data
interface Incident {
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

interface QuarantinedFile {
  id: string;
  originalPath: string;
  quarantinePath: string;
  hash: string;
  size: number;
  date: string;
}

interface LayerCheck {
  name: string;
  status: 'Passed' | 'Failed' | 'Completed' | 'Skipped' | 'Executed' | 'No Action';
  details: string;
  score: number;
}

interface MultiLayerScanResult {
  filePath: string;
  fileName: string;
  hash: string;
  finalScore: number;
  status: 'Safe' | 'Suspicious' | 'Malicious';
  layers: {
    layer1: LayerCheck;
    layer2: LayerCheck & {
      features?: {
        fileSizeKb: number;
        entropy: number;
        apiCount: number;
        stringCount: number;
        peHeaders: string;
        importedDlls: string[];
        digitalSignature: string;
        sections: number;
        entryPoint: string;
      };
      threatProbability?: number;
      confidenceScore?: number;
      malwareFamily?: string;
    };
    layer3: LayerCheck & {
      monitoredEvents?: {
        fileEvents: number;
        registryEvents: number;
        powershellExecutions: number;
        processInjections: number;
        memoryAllocations: number;
        networkCommunications: number;
        rapidEncryption: number;
      };
      behavioralRiskScore?: number;
    };
    layer4: LayerCheck & {
      reputationScore?: number;
      detectionRatio?: string;
      knownThreatInfo?: string;
    };
    layer5: LayerCheck & {
      weights?: { signature: number; static: number; behavioral: number; threatIntel: number };
      contributions?: { signature: number; static: number; behavioral: number; threatIntel: number };
    };
    layer6: LayerCheck & {
      actions?: string[];
    };
  };
}

interface Settings {
  aiSensitivity: number;
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

export interface ProcessTelemetry {
  pid: number;
  parentPid: number;
  name: string;
  commandLine: string;
  memoryUsage: number;
  cpuUsage: number;
  suspicious: boolean;
  reasons: string[];
}

export interface NetworkConnection {
  protocol: 'TCP' | 'UDP';
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
  pid: number;
  processName: string;
  suspicious: boolean;
}

export interface RegistryEvent {
  action: 'Added (Startup)' | 'Modified' | 'Deleted';
  key: string;
  name: string;
  value: string;
  time: string;
  status: string;
}

export interface FileEvent {
  action: string;
  path: string;
  time: string;
  status: string;
}

interface UsbEvent {
  action: 'Inserted' | 'Removed';
  letter: string;
  label: string;
  time: string;
}

const App: React.FC = () => {
  const electronAPI = (window as any).electronAPI;

  // Navigation
  const [activeTab, setActiveTab] = useState<'dashboard' | 'threats' | 'quarantine' | 'scanner' | 'settings'>('dashboard');

  // EDR Telemetry Streams
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [quarantineList, setQuarantineList] = useState<QuarantinedFile[]>([]);
  const [settings, setSettings] = useState<Settings>({
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
  });
  // Onboarding Wizard & Simulated Update state
  const [onboardingStep, setOnboardingStep] = useState<number>(1);
  const [onboardingScanProgress, setOnboardingScanProgress] = useState<number>(0);
  const [isCheckingForUpdates, setIsCheckingForUpdates] = useState<boolean>(false);
  const [updaterStepText, setUpdaterStepText] = useState<string>('');

  // Search Filters
  const [searchQuery, setSearchQuery] = useState('');

  // Scanning State
  const [scanStatus, setScanStatus] = useState<string>('System Idle');
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [isScanPaused, setIsScanPaused] = useState<boolean>(false);
  const [selectedScanPath, setSelectedScanPath] = useState<string>('C:\\');
  const [isDragOver, setIsDragOver] = useState(false);

  // Scan Center states
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [activeReport, setActiveReport] = useState<any>(null);
  const [liveScanStatus, setLiveScanStatus] = useState<any>(null);
  const [scannerSubTab, setScannerSubTab] = useState<'options' | 'results' | 'history'>('options');

  // Multi-layer AI Threat Detection states
  const [scannedFiles, setScannedFiles] = useState<MultiLayerScanResult[]>([]);
  const [activeAnalysis, setActiveAnalysis] = useState<MultiLayerScanResult | null>(null);
  const [currentAnimLayer, setCurrentAnimLayer] = useState<number>(0);
  const [expandedLayers, setExpandedLayers] = useState<Record<string, boolean>>({
    layer2: false,
    layer3: false,
    layer4: false
  });

  // Settings visibility
  const [showApiKey, setShowApiKey] = useState(false);

  // Stats / CPU Usage simulation
  const [cpuUsage, setCpuUsage] = useState(3);
  const [ramUsage, setRamUsage] = useState(38);
  const [systemSpecs, setSystemSpecs] = useState<{
    cpu: string;
    ram: string;
    os: string;
    hostname: string;
    arch: string;
  }>({
    cpu: 'Loading CPU...',
    ram: 'Loading RAM...',
    os: 'Loading OS...',
    hostname: 'Loading Host...',
    arch: 'x64'
  });

  // File Drop Ref
  const dropZoneRef = useRef<HTMLDivElement>(null);

  // Fetch initial logs and set up event listeners
  useEffect(() => {
    if (electronAPI) {
      // Get incidents
      electronAPI.getIncidents().then((data: Incident[]) => setIncidents(data));
      // Get quarantine
      electronAPI.getQuarantine().then((data: QuarantinedFile[]) => setQuarantineList(data));
      // Get settings
      electronAPI.getSettings().then((data: Settings) => setSettings(data));

      // Register live events listeners
      const cleanFile = electronAPI.onFileEvent(() => {});
      const cleanProcess = electronAPI.onProcessUpdate(() => {});
      const cleanNetwork = electronAPI.onNetworkUpdate(() => {});
      const cleanRegistry = electronAPI.onRegistryEvent(() => {});
      const cleanUsb = electronAPI.onUsbEvent((event: UsbEvent) => {
        if (event.action === 'Inserted' && settings.notifications) {
          new Notification('Removable USB Device Detected', {
            body: `Volume ${event.letter} (${event.letter || 'Removable Storage'}) is active. Running signature check...`,
            icon: '../assets/icon.png'
          });
        }
      });

      const cleanScan = electronAPI.onScanStatusUpdate((update: any) => {
        setLiveScanStatus(update);
        setScanStatus(update.status);
        setScanProgress(update.progress);
        
        if (update.status === 'Scan Paused') {
          setIsScanPaused(true);
        } else {
          setIsScanPaused(false);
        }

        // If completed or idle
        if (update.progress === 100 || update.status.includes('completed') || update.status.includes('finished')) {
          electronAPI.getScanHistory().then((data: any[]) => setScanHistory(data));
          electronAPI.getIncidents().then((data: Incident[]) => setIncidents(data));
          electronAPI.getQuarantine().then((data: QuarantinedFile[]) => setQuarantineList(data));
        }
      });

      const cleanScanReport = electronAPI.onScanReportCompleted((report: any) => {
        setActiveReport(report);
        setScannerSubTab('results');
      });

      const cleanIncident = electronAPI.onIncidentDetected((incident: Incident) => {
        setIncidents(prev => [incident, ...prev]);
        electronAPI.getQuarantine().then((data: QuarantinedFile[]) => setQuarantineList(data));
        
        // Native notifications trigger
        if (settings.notifications) {
          new Notification('SentinelAI Security Alert', {
            body: `Threat Detected: ${incident.name} in ${incident.path}. Action: ${incident.actionTaken}`,
            icon: '../assets/icon.png'
          });
        }
      });

      // Listen to multi-layer scan progress updates
      const cleanMultiProgress = electronAPI.onMultiLayerScanProgress((result: MultiLayerScanResult) => {
        setScannedFiles(prev => {
          const filtered = prev.filter(f => f.filePath !== result.filePath);
          return [result, ...filtered];
        });
        setActiveAnalysis(result);
      });

      // Quick scan tray menu trigger listener
      const cleanTrayScan = electronAPI.onTriggerQuickScan(() => {
        handleQuickScan();
      });

      const cleanTriggerUpdate = electronAPI.onTriggerUpdateCheck(() => {
        triggerSimulatedUpdateCheck();
      });

      const cleanSettingsUpdated = electronAPI.onSettingsUpdated((updatedSettings: any) => {
        setSettings(updatedSettings);
      });

      return () => {
        cleanFile();
        cleanProcess();
        cleanNetwork();
        cleanRegistry();
        cleanUsb();
        cleanScan();
        cleanIncident();
        cleanMultiProgress();
        cleanTrayScan();
        cleanScanReport();
        cleanTriggerUpdate();
        cleanSettingsUpdated();
      };
    }
  }, [settings.notifications]);

  // Load system specs and scan history on mount
  useEffect(() => {
    if (electronAPI) {
      if (electronAPI.getSystemSpecs) {
        electronAPI.getSystemSpecs().then((specs: any) => {
          if (specs) {
            setSystemSpecs(specs);
          }
        }).catch((err: any) => {
          console.error('Failed to load system specs:', err);
        });
      }
      if (electronAPI.getScanHistory) {
        electronAPI.getScanHistory().then((data: any[]) => {
          setScanHistory(data);
        }).catch((err: any) => {
          console.error('Failed to load scan history:', err);
        });
      }
    }
  }, []);

  // CPU and RAM real-time usage polling loop
  useEffect(() => {
    if (!electronAPI || !electronAPI.getSystemStats) return;

    const fetchStats = async () => {
      try {
        const stats = await electronAPI.getSystemStats();
        if (stats) {
          setCpuUsage(stats.cpu);
          setRamUsage(stats.ram);
        }
      } catch (err) {
        console.error('Failed to fetch system stats:', err);
      }
    };

    fetchStats(); // initial fetch

    const timer = setInterval(fetchStats, 2000);
    return () => clearInterval(timer);
  }, []);

  // Trigger step-by-step layer animation when a new active analysis is set
  useEffect(() => {
    if (activeAnalysis) {
      setCurrentAnimLayer(1);
      const t1 = setTimeout(() => setCurrentAnimLayer(2), 500);
      const t2 = setTimeout(() => setCurrentAnimLayer(3), 1000);
      const t3 = setTimeout(() => setCurrentAnimLayer(4), 1500);
      const t4 = setTimeout(() => setCurrentAnimLayer(5), 2000);
      const t5 = setTimeout(() => setCurrentAnimLayer(6), 2500);
      return () => {
        clearTimeout(t1);
        clearTimeout(t2);
        clearTimeout(t3);
        clearTimeout(t4);
        clearTimeout(t5);
      };
    }
  }, [activeAnalysis]);

  // Actions
  const handleToggleScanPause = async () => {
    if (electronAPI) {
      if (isScanPaused) {
        await electronAPI.resumeScan();
        setIsScanPaused(false);
      } else {
        await electronAPI.pauseScan();
        setIsScanPaused(true);
      }
    }
  };

  const handleCancelScan = async () => {
    if (electronAPI) {
      await electronAPI.cancelScan();
      setIsScanPaused(false);
      setScanStatus('System Idle');
      setScanProgress(0);
    }
  };

  const triggerSimulatedUpdateCheck = async () => {
    if (isCheckingForUpdates) return;
    setIsCheckingForUpdates(true);
    setUpdaterStepText("Checking for Updates...");
    
    if (electronAPI && electronAPI.checkForUpdates) {
      try {
        const steps = await electronAPI.checkForUpdates();
        for (const step of steps) {
          setUpdaterStepText(step.text);
          await new Promise(resolve => setTimeout(resolve, step.delay));
        }
      } catch (err) {
        setUpdaterStepText("Unable to contact the cloud protection service. Local protection is still active.");
        await new Promise(resolve => setTimeout(resolve, 2500));
      }
    } else {
      await new Promise(resolve => setTimeout(resolve, 1000));
      setUpdaterStepText("Security Definitions Updated");
      await new Promise(resolve => setTimeout(resolve, 1000));
      setUpdaterStepText("AI Model Updated");
      await new Promise(resolve => setTimeout(resolve, 1000));
      setUpdaterStepText("Platform Updated");
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    setIsCheckingForUpdates(false);
    if (settings.notifications) {
      new Notification('Security Definitions Updated', {
        body: 'Your AI model and definition bases are up to date.',
        icon: '../assets/icon.png'
      });
    }
  };

  const handleQuickScan = () => {
    setIsScanPaused(false);
    if (electronAPI) {
      electronAPI.runNormalScan();
    }
  };

  const handleDeepScan = () => {
    setIsScanPaused(false);
    if (electronAPI) {
      electronAPI.runDeepScan();
    }
  };

  const handleSelectFolder = async () => {
    if (electronAPI) {
      const folderPath = await electronAPI.selectFolder();
      if (folderPath) {
        setSelectedScanPath(folderPath);
      }
    }
  };

  const handleCustomScan = () => {
    setIsScanPaused(false);
    if (electronAPI) {
      electronAPI.runSystemScan(selectedScanPath);
    }
  };

  const handleRestoreQuarantine = async (id: string) => {
    if (electronAPI) {
      const result = await electronAPI.restoreQuarantine(id);
      if (result.success) {
        alert(`File restored successfully to: ${result.path}`);
        electronAPI.getQuarantine().then((data: QuarantinedFile[]) => setQuarantineList(data));
        electronAPI.getIncidents().then((data: Incident[]) => setIncidents(data));
        
        if (settings.notifications) {
          new Notification('Threat Restored', {
            body: 'The quarantined file was successfully restored to its original location.',
            icon: '../assets/icon.png'
          });
        }
      } else {
        alert(`Failed to restore file: ${result.error}`);
      }
    }
  };

  const handleDeleteQuarantine = async (id: string) => {
    if (electronAPI) {
      const success = await electronAPI.deleteQuarantine(id);
      if (success) {
        electronAPI.getQuarantine().then((data: QuarantinedFile[]) => setQuarantineList(data));
        
        if (settings.notifications) {
          new Notification('Threat Removed', {
            body: 'The quarantined file was permanently removed from disk.',
            icon: '../assets/icon.png'
          });
        }
      } else {
        alert('Failed to delete file.');
      }
    }
  };

  const handleClearIncidents = async () => {
    if (electronAPI && confirm('Clear all incident log history?')) {
      const result = await electronAPI.clearIncidents();
      if (result.success) {
        setIncidents([]);
      }
    }
  };

  const handleUpdateSetting = async (key: keyof Settings, value: any) => {
    const updatedSettings = { ...settings, [key]: value };
    setSettings(updatedSettings);

    if (electronAPI) {
      await electronAPI.updateSettings(updatedSettings);
      
      if (key === 'realTimeProtection') {
        if (settings.notifications) {
          new Notification(value ? 'Real-Time Protection Enabled' : 'Real-Time Protection Disabled', {
            body: value ? 'All security shields are active.' : 'Warning: Your device is now vulnerable.',
            icon: '../assets/icon.png'
          });
        }
      }
    }
  };

  // Drag and drop scanning
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      const file = files[0];
      const filePath = (file as any).path; // Electron exposes path on File object

      if (filePath) {
        setIsScanPaused(false);
        setScanStatus(`AI Analyzing dropped file: ${file.name}`);
        setScanProgress(30);

        if (electronAPI) {
          try {
            setScanProgress(60);
            const result = await (electronAPI as any).runMultiLayerScan(filePath);
            setScanProgress(100);
            setScannedFiles(prev => {
              const filtered = prev.filter(f => f.filePath !== result.filePath);
              return [result, ...filtered];
            });
            setActiveAnalysis(result);
          } catch (err) {
            console.error('Multi-layer scan failed:', err);
          } finally {
            setTimeout(() => {
              setScanStatus('System Idle');
              setScanProgress(0);
            }, 2000);
          }
        }
      }
    }
  };

  // Helper colors
  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case 'low': return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/30 ring-1 ring-red-500/40';
      default: return 'text-slate-400 bg-slate-500/10';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Quarantined': return 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10';
      case 'Killed': return 'text-red-400 border-red-500/30 bg-red-500/10';
      case 'Blocked': return 'text-purple-400 border-purple-500/30 bg-purple-500/10';
      case 'Allowed': return 'text-green-400 border-green-500/30 bg-green-500/10';
      default: return 'text-yellow-400 border-yellow-500/30';
    }
  };

  // Count active issues
  const activeThreatsCount = incidents.filter(i => i.status === 'Detected').length;
  const totalBlockedCount = incidents.filter(i => i.status === 'Quarantined' || i.status === 'Killed' || i.status === 'Blocked').length;

  const renderAiLayerAnalysis = () => {
    if (!activeAnalysis) {
      return (
        <div className="glass-panel rounded-2xl p-8 flex flex-col items-center justify-center text-center gap-4 h-full min-h-[400px]">
          <div className="p-4 rounded-full bg-slate-900/60 border border-slate-800 text-slate-500">
            <Layers className="w-10 h-10" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-200">AI Multi-Layer Analysis</h3>
            <p className="text-xs text-slate-500 mt-1 max-w-[240px]">
              Select a module from the Telemetry history or drop a file to view a real-time layered security evaluation.
            </p>
          </div>
        </div>
      );
    }

    const { finalScore, status, layers, fileName } = activeAnalysis;

    const getLayerStatusBadge = (layerStatus: string) => {
      switch (layerStatus) {
        case 'Passed': return <span className="text-green-400 font-bold">✔ PASSED</span>;
        case 'Failed': return <span className="text-red-400 font-bold">✘ DETECTED</span>;
        case 'Skipped': return <span className="text-slate-500">N/A SKIPPED</span>;
        case 'Executed': return <span className="text-cyan-400 font-bold">✔ EXECUTED</span>;
        case 'Completed': return <span className="text-cyan-400 font-bold">✔ DONE</span>;
        default: return <span className="text-slate-400">{layerStatus.toUpperCase()}</span>;
      }
    };

    return (
      <div className="glass-panel rounded-2xl p-6 flex flex-col gap-6 animate-fadeIn font-mono text-xs select-none">
        <div className="flex flex-col gap-1 border-b border-slate-800 pb-3">
          <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">Diagnostics Core</span>
          <h3 className="text-sm font-bold text-white truncate" title={fileName}>{fileName}</h3>
        </div>

        <div className="flex flex-col gap-5 relative">
          <div className="absolute left-4 top-2.5 bottom-2.5 w-0.5 bg-slate-800" />
          
          {currentAnimLayer < 6 && (
            <div 
              className="absolute left-3.5 w-1.5 h-1.5 rounded-full bg-[#00E5FF] shadow-[0_0_8px_#00E5FF] transition-all duration-300 animate-pulse"
              style={{
                top: `${(currentAnimLayer - 1) * 15.5 + 2}%`
              }}
            />
          )}

          <div className={`flex items-start gap-4 transition-all duration-300 ${currentAnimLayer >= 1 ? 'opacity-100' : 'opacity-30'}`}>
            <div className={`z-10 p-1.5 rounded-full border ${
              currentAnimLayer === 1 
                ? 'bg-cyan-500/20 border-[#00E5FF] animate-pulse text-[#00E5FF]' 
                : layers.layer1.status === 'Failed' 
                  ? 'bg-red-500/20 border-red-500 text-red-400' 
                  : 'bg-slate-900 border-slate-800 text-green-400'
            }`}>
              <Shield className="w-3.5 h-3.5" />
            </div>
            <div className="flex-1 flex flex-col gap-0.5">
              <div className="flex justify-between items-center font-bold">
                <span className="text-white">Layer 1 - Signatures</span>
                {currentAnimLayer === 1 ? <span className="text-cyan-400 animate-pulse">ANALYZING...</span> : getLayerStatusBadge(layers.layer1.status)}
              </div>
              <span className="text-[10px] text-slate-400 leading-normal">{layers.layer1.details}</span>
            </div>
          </div>

          <div className={`flex items-start gap-4 transition-all duration-300 ${currentAnimLayer >= 2 ? 'opacity-100' : 'opacity-30'}`}>
            <div className={`z-10 p-1.5 rounded-full border ${
              currentAnimLayer === 2 
                ? 'bg-cyan-500/20 border-[#00E5FF] animate-pulse text-[#00E5FF]' 
                : layers.layer2.status === 'Failed'
                  ? 'bg-red-500/20 border-red-500 text-red-400'
                  : layers.layer2.status === 'Skipped'
                    ? 'bg-slate-900 border-slate-800 text-slate-500'
                    : 'bg-slate-900 border-slate-800 text-green-400'
            }`}>
              <Cpu className="w-3.5 h-3.5" />
            </div>
            <div className="flex-1 flex flex-col gap-0.5">
              <div className="flex justify-between items-center font-bold">
                <span className="text-white">Layer 2 - Static AI</span>
                {currentAnimLayer === 2 ? <span className="text-cyan-400 animate-pulse">EVALUATING...</span> : getLayerStatusBadge(layers.layer2.status)}
              </div>
              <span className="text-[10px] text-slate-400 leading-normal">{layers.layer2.details}</span>
            </div>
          </div>

          <div className={`flex items-start gap-4 transition-all duration-300 ${currentAnimLayer >= 3 ? 'opacity-100' : 'opacity-30'}`}>
            <div className={`z-10 p-1.5 rounded-full border ${
              currentAnimLayer === 3 
                ? 'bg-cyan-500/20 border-[#00E5FF] animate-pulse text-[#00E5FF]' 
                : layers.layer3.status === 'Failed'
                  ? 'bg-red-500/20 border-red-500 text-red-400'
                  : layers.layer3.status === 'Skipped'
                    ? 'bg-slate-900 border-slate-800 text-slate-500'
                    : 'bg-slate-900 border-slate-800 text-green-400'
            }`}>
              <Activity className="w-3.5 h-3.5" />
            </div>
            <div className="flex-1 flex flex-col gap-0.5">
              <div className="flex justify-between items-center font-bold">
                <span className="text-white">Layer 3 - Behavioral AI</span>
                {currentAnimLayer === 3 ? <span className="text-cyan-400 animate-pulse">MONITORING...</span> : getLayerStatusBadge(layers.layer3.status)}
              </div>
              <span className="text-[10px] text-slate-400 leading-normal">{layers.layer3.details}</span>
            </div>
          </div>

          <div className={`flex items-start gap-4 transition-all duration-300 ${currentAnimLayer >= 4 ? 'opacity-100' : 'opacity-30'}`}>
            <div className={`z-10 p-1.5 rounded-full border ${
              currentAnimLayer === 4 
                ? 'bg-cyan-500/20 border-[#00E5FF] animate-pulse text-[#00E5FF]' 
                : layers.layer4.status === 'Failed'
                  ? 'bg-red-500/20 border-red-500 text-red-400'
                  : layers.layer4.status === 'Skipped'
                    ? 'bg-slate-900 border-slate-800 text-slate-500'
                    : 'bg-slate-900 border-slate-800 text-green-400'
            }`}>
              <Network className="w-3.5 h-3.5" />
            </div>
            <div className="flex-1 flex flex-col gap-0.5">
              <div className="flex justify-between items-center font-bold">
                <span className="text-white">Layer 4 - Threat Intel</span>
                {currentAnimLayer === 4 ? <span className="text-cyan-400 animate-pulse">LOOKING UP...</span> : getLayerStatusBadge(layers.layer4.status)}
              </div>
              <span className="text-[10px] text-slate-400 leading-normal">{layers.layer4.details}</span>
            </div>
          </div>

          <div className={`flex items-start gap-4 transition-all duration-300 ${currentAnimLayer >= 5 ? 'opacity-100' : 'opacity-30'}`}>
            <div className={`z-10 p-1.5 rounded-full border ${
              currentAnimLayer === 5 
                ? 'bg-cyan-500/20 border-[#00E5FF] animate-pulse text-[#00E5FF]' 
                : status === 'Malicious'
                  ? 'bg-red-500/20 border-red-500 text-red-400'
                  : status === 'Suspicious'
                    ? 'bg-amber-500/20 border-amber-500 text-amber-400'
                    : 'bg-slate-900 border-slate-800 text-green-400'
            }`}>
              <Layers className="w-3.5 h-3.5" />
            </div>
            <div className="flex-1 flex flex-col gap-0.5">
              <div className="flex justify-between items-center font-bold">
                <span className="text-white">Layer 5 - Decision AI</span>
                {currentAnimLayer === 5 ? <span className="text-cyan-400 animate-pulse">COMPILING...</span> : getLayerStatusBadge(layers.layer5.status)}
              </div>
              <span className="text-[10px] text-slate-400 leading-normal">{layers.layer5.details}</span>
            </div>
          </div>

          <div className={`flex items-start gap-4 transition-all duration-300 ${currentAnimLayer >= 6 ? 'opacity-100' : 'opacity-30'}`}>
            <div className={`z-10 p-1.5 rounded-full border ${
              currentAnimLayer === 6 && layers.layer6.status === 'Executed'
                ? 'bg-red-500/20 border-red-500 text-red-400'
                : 'bg-slate-900 border-slate-800 text-slate-500'
            }`}>
              <Lock className="w-3.5 h-3.5" />
            </div>
            <div className="flex-1 flex flex-col gap-0.5">
              <div className="flex justify-between items-center font-bold">
                <span className="text-white">Layer 6 - Response</span>
                {getLayerStatusBadge(layers.layer6.status)}
              </div>
              <span className="text-[10px] text-slate-400 leading-normal">{layers.layer6.details}</span>
            </div>
          </div>
        </div>

        {currentAnimLayer >= 5 && (
          <div className="flex items-center justify-between border-t border-b border-slate-800 py-3.5 mt-2">
            <div className="flex flex-col gap-1">
              <span className="text-[10px] text-slate-500 uppercase font-bold">Verdict Status</span>
              <span className={`text-base font-black ${
                status === 'Malicious' ? 'text-red-500' : status === 'Suspicious' ? 'text-amber-500' : 'text-green-500'
              }`}>
                {status.toUpperCase()}
              </span>
            </div>
            
            <div className="flex flex-col items-end gap-1">
              <span className="text-[10px] text-slate-500 uppercase font-bold">Threat Score</span>
              <span className="text-xl font-black text-white">{finalScore}%</span>
            </div>
          </div>
        )}

        {currentAnimLayer >= 5 && (
          <div className="flex flex-col gap-2.5">
            <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">Detection Details & Contributions</span>
            
            {layers.layer2.status !== 'Skipped' && (
              <div className="border border-slate-800/80 rounded-xl overflow-hidden bg-slate-950/20">
                <div 
                  onClick={() => setExpandedLayers(prev => ({ ...prev, layer2: !prev.layer2 }))}
                  className="p-3 flex items-center justify-between cursor-pointer hover:bg-slate-900/30 transition select-none"
                >
                  <span className="font-semibold text-slate-300">Static AI Features (30% weight)</span>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400 font-bold">+{layers.layer5.contributions?.static || 0}%</span>
                    {expandedLayers.layer2 ? <ChevronUp className="w-3.5 h-3.5 text-slate-500" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-500" />}
                  </div>
                </div>
                {expandedLayers.layer2 && layers.layer2.features && (
                  <div className="p-3 border-t border-slate-800 bg-[#070D18]/50 flex flex-col gap-2 font-mono text-[10px] text-slate-400 leading-normal">
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
                      <div>Format: <span className="text-white">{layers.layer2.features.peHeaders}</span></div>
                      <div>Entropy: <span className="text-yellow-400 font-bold">{layers.layer2.features.entropy}</span></div>
                      <div>Size: <span className="text-white">{layers.layer2.features.fileSizeKb} KB</span></div>
                      <div>Signature: <span className={layers.layer2.features.digitalSignature === 'Unsigned' ? 'text-orange-400' : 'text-green-400'}>{layers.layer2.features.digitalSignature}</span></div>
                      <div>Sections: <span className="text-white">{layers.layer2.features.sections}</span></div>
                      <div>Entry Point: <span className="text-white">{layers.layer2.features.entryPoint}</span></div>
                    </div>
                    <div className="flex flex-col gap-1 border-t border-slate-900 pt-2 mt-1">
                      <span className="text-slate-500 font-bold uppercase text-[9px]">Imported Modules:</span>
                      <div className="flex flex-wrap gap-1 mt-0.5">
                        {layers.layer2.features.importedDlls.map((dll: string, i: number) => (
                          <span key={i} className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 text-[9px]">{dll}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {layers.layer3.status !== 'Skipped' && (
              <div className="border border-slate-800/80 rounded-xl overflow-hidden bg-slate-950/20">
                <div 
                  onClick={() => setExpandedLayers(prev => ({ ...prev, layer3: !prev.layer3 }))}
                  className="p-3 flex items-center justify-between cursor-pointer hover:bg-slate-900/30 transition select-none"
                >
                  <span className="font-semibold text-slate-300">Behavioral NN Risk (50% weight)</span>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400 font-bold">+{layers.layer5.contributions?.behavioral || 0}%</span>
                    {expandedLayers.layer3 ? <ChevronUp className="w-3.5 h-3.5 text-slate-500" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-500" />}
                  </div>
                </div>
                {expandedLayers.layer3 && layers.layer3.monitoredEvents && (
                  <div className="p-3 border-t border-slate-800 bg-[#070D18]/50 flex flex-col gap-2 font-mono text-[10px] text-slate-400 leading-normal">
                    <span className="text-slate-500 font-bold uppercase text-[9px]">Monitored Capabilities:</span>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 mt-0.5">
                      <div>File Operations: <span className="text-white font-bold">{layers.layer3.monitoredEvents.fileEvents}</span></div>
                      <div>Registry Modifications: <span className="text-white font-bold">{layers.layer3.monitoredEvents.registryEvents}</span></div>
                      <div>PowerShell Invocation: <span className={layers.layer3.monitoredEvents.powershellExecutions > 0 ? 'text-orange-400 font-bold' : 'text-slate-500'}>{layers.layer3.monitoredEvents.powershellExecutions}</span></div>
                      <div>Process Injection APIs: <span className={layers.layer3.monitoredEvents.processInjections > 0 ? 'text-red-400 font-bold' : 'text-slate-500'}>{layers.layer3.monitoredEvents.processInjections}</span></div>
                      <div>Virtual Memory Alloc: <span className="text-white">{layers.layer3.monitoredEvents.memoryAllocations}</span></div>
                      <div>Network Sockets: <span className="text-white">{layers.layer3.monitoredEvents.networkCommunications}</span></div>
                      <div>Ransomware Signatures: <span className={layers.layer3.monitoredEvents.rapidEncryption > 0 ? 'text-red-400 font-bold' : 'text-slate-500'}>{layers.layer3.monitoredEvents.rapidEncryption}</span></div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {layers.layer4.status !== 'Skipped' && (
              <div className="border border-slate-800/80 rounded-xl overflow-hidden bg-slate-950/20">
                <div 
                  onClick={() => setExpandedLayers(prev => ({ ...prev, layer4: !prev.layer4 }))}
                  className="p-3 flex items-center justify-between cursor-pointer hover:bg-slate-900/30 transition select-none"
                >
                  <span className="font-semibold text-slate-300">Threat Intelligence (20% weight)</span>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400 font-bold">+{layers.layer5.contributions?.threatIntel || 0}%</span>
                    {expandedLayers.layer4 ? <ChevronUp className="w-3.5 h-3.5 text-slate-500" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-500" />}
                  </div>
                </div>
                {expandedLayers.layer4 && (
                  <div className="p-3 border-t border-slate-800 bg-[#070D18]/50 flex flex-col gap-1.5 font-mono text-[10px] text-slate-400 leading-normal">
                    <div>VirusTotal Ratio: <span className="text-white font-bold">{layers.layer4.detectionRatio}</span></div>
                    <div>Reputation Score: <span className="text-white">{layers.layer4.reputationScore}</span></div>
                    <div>Threat Label: <span className="text-red-400">{layers.layer4.knownThreatInfo}</span></div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#0B1220] text-slate-200">
      {/* Background Neon Gradients */}
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-[radial-gradient(circle,rgba(0,229,255,0.04),transparent_70%)] pointer-events-none" />
      <div className="absolute bottom-0 left-0 w-[400px] h-[400px] bg-[radial-gradient(circle,rgba(239,68,68,0.02),transparent_70%)] pointer-events-none" />

      {/* SIDEBAR NAVIGATION */}
      <nav className="w-64 flex flex-col border-r border-slate-800 bg-[#0E1726]/60 backdrop-blur-md relative z-10 select-none">
        {/* Logo and Brand */}
        <div className="p-6 flex items-center gap-3 border-b border-slate-800/80">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-[#00E5FF]/30 glow-cyan">
            <Shield className="w-6 h-6 text-[#00E5FF]" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wider text-white">SENTINEL<span className="text-[#00E5FF]">AI</span></h1>
            <p className="text-[10px] text-slate-400 tracking-widest font-mono">EDR AGENT v1.0</p>
          </div>
        </div>

        {/* Navigation Items */}
        <div className="flex-1 p-4 flex flex-col gap-1.5 mt-4">
          <button 
            onClick={() => setActiveTab('dashboard')}
            className={`flex items-center gap-3.5 px-4 py-3 rounded-xl text-sm font-medium transition ${
              activeTab === 'dashboard' 
                ? 'bg-cyan-500/10 text-white border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.1)]' 
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
            }`}
          >
            <Layers className="w-4 h-4" />
            Overview Dashboard
          </button>

          <button 
            onClick={() => setActiveTab('threats')}
            className={`flex items-center gap-3.5 px-4 py-3 rounded-xl text-sm font-medium transition ${
              activeTab === 'threats' 
                ? 'bg-cyan-500/10 text-white border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.1)]' 
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
            }`}
          >
            <History className="w-4 h-4" />
            Threat History
            {activeThreatsCount > 0 && (
              <span className="ml-auto px-2 py-0.5 text-[10px] font-bold rounded-full bg-red-500/20 text-red-400 border border-red-500/40">
                {activeThreatsCount}
              </span>
            )}
          </button>

          <button 
            onClick={() => setActiveTab('quarantine')}
            className={`flex items-center gap-3.5 px-4 py-3 rounded-xl text-sm font-medium transition ${
              activeTab === 'quarantine' 
                ? 'bg-cyan-500/10 text-white border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.1)]' 
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
            }`}
          >
            <Lock className="w-4 h-4" />
            Quarantine Vault
            {quarantineList.length > 0 && (
              <span className="ml-auto px-2 py-0.5 text-[10px] font-bold rounded-full bg-cyan-500/20 text-[#00E5FF] border border-[#00E5FF]/40">
                {quarantineList.length}
              </span>
            )}
          </button>

          <button 
            onClick={() => setActiveTab('scanner')}
            className={`flex items-center gap-3.5 px-4 py-3 rounded-xl text-sm font-medium transition ${
              activeTab === 'scanner' 
                ? 'bg-cyan-500/10 text-white border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.1)]' 
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
            }`}
          >
            <Play className="w-4 h-4" />
            Threat Scanner
          </button>

          <button 
            onClick={() => setActiveTab('settings')}
            className={`flex items-center gap-3.5 px-4 py-3 rounded-xl text-sm font-medium transition ${
              activeTab === 'settings' 
                ? 'bg-cyan-500/10 text-white border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.1)]' 
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
            }`}
          >
            <SettingsIcon className="w-4 h-4" />
            Agent Settings
          </button>
        </div>

        {/* Protection Banner Footer */}
        <div className="p-4 border-t border-slate-800 bg-[#070D18]/80 flex flex-col gap-2 mt-auto">
          <div className="flex items-center gap-2">
            <div className={`w-2.5 h-2.5 rounded-full ${
              settings.realTimeProtection 
                ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' 
                : 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]'
            }`} />
            <span className="text-xs font-semibold">
              {settings.realTimeProtection ? 'SHIELD ONLINE' : 'SHIELD DISABLED'}
            </span>
          </div>
          <p className="text-[10px] text-slate-500 font-mono">
            Heuristic: {settings.aiSensitivity >= 80 ? 'Aggressive' : settings.aiSensitivity >= 50 ? 'Standard' : 'Basic'}
          </p>
        </div>
      </nav>

      {/* MAIN CONTAINER */}
      <main className="flex-1 flex flex-col overflow-hidden relative z-10">
        
        {/* TOP HEADER BAR */}
        <header className="h-16 border-b border-slate-800/80 bg-[#0C1220]/80 backdrop-blur-md px-8 flex items-center justify-between select-none">
          <div>
            {scanStatus !== 'System Idle' ? (
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2.5 text-cyan-400">
                  {isScanPaused ? (
                    <Pause className="w-4 h-4 text-amber-400 animate-pulse" />
                  ) : (scanProgress === 100 || scanStatus.includes('finished')) ? (
                    <span className="w-4 h-4 rounded-full bg-green-500/10 border border-green-500/30 flex items-center justify-center text-green-400 font-bold text-xs">✓</span>
                  ) : (
                    <RefreshCw className="w-4 h-4 animate-spin text-[#00E5FF]" />
                  )}
                  <span className={`text-xs font-medium tracking-wide font-mono ${
                    (scanProgress === 100 || scanStatus.includes('finished')) 
                      ? 'text-green-400 font-semibold' 
                      : isScanPaused 
                        ? 'text-amber-400 font-semibold' 
                        : 'text-[#00E5FF]'
                  }`}>
                    {(scanProgress === 100 || scanStatus.includes('finished')) ? 'Scan Completed' : isScanPaused ? 'Scan Paused' : scanStatus} ({scanProgress}%)
                  </span>
                </div>
                
                <div className="flex items-center gap-1.5">
                  {scanProgress < 100 && !scanStatus.includes('finished') ? (
                    <>
                      <button
                        onClick={handleToggleScanPause}
                        className={`px-2 py-0.5 rounded border text-[10px] font-bold font-mono transition-all duration-200 ${
                          isScanPaused
                            ? 'border-green-500/30 bg-green-500/10 text-green-400 hover:bg-green-500/20'
                            : 'border-amber-500/30 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20'
                        }`}
                        title={isScanPaused ? "Resume system scan" : "Pause system scan"}
                      >
                        {isScanPaused ? 'RESUME' : 'PAUSE'}
                      </button>

                      <button
                        onClick={handleCancelScan}
                        className="px-2 py-0.5 rounded border border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20 text-[10px] font-bold font-mono transition-all duration-200"
                        title="Stop and cancel scan"
                      >
                        STOP
                      </button>
                    </>
                  ) : (
                    <button
                      onClick={() => {
                        setScanStatus('System Idle');
                        setScanProgress(0);
                      }}
                      className="px-2 py-0.5 rounded border border-slate-700 hover:bg-slate-800 text-[10px] font-bold font-mono text-slate-300 transition"
                      title="Dismiss scan report"
                    >
                      DISMISS
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-4 text-xs text-slate-400 bg-slate-900/40 px-4 py-2 rounded-xl border border-slate-800/80">
                <div className="flex items-center gap-1.5 border-r border-slate-800/60 pr-3.5">
                  <Laptop className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="font-semibold text-slate-200">{systemSpecs.os} ({systemSpecs.arch})</span>
                </div>
                <div className="flex items-center gap-1.5 border-r border-slate-800/60 pr-3.5 max-w-[240px] truncate">
                  <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-slate-300 font-medium" title={systemSpecs.cpu}>{systemSpecs.cpu}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-purple-400" />
                  <span className="text-slate-300 font-medium">{systemSpecs.ram} RAM</span>
                </div>
              </div>
            )}
          </div>

          <div className="flex items-center gap-6">
            <div className="flex gap-4 text-xs font-mono">
              <div className="flex items-center gap-1.5 bg-slate-900/60 px-3 py-1.5 rounded-lg border border-slate-800">
                <span className="text-slate-400">CPU</span>
                <span className="font-semibold text-white">{cpuUsage}%</span>
              </div>
              <div className="flex items-center gap-1.5 bg-slate-900/60 px-3 py-1.5 rounded-lg border border-slate-800">
                <span className="text-slate-400">RAM</span>
                <span className="font-semibold text-white">{ramUsage}%</span>
              </div>
            </div>
          </div>
        </header>

        {/* VIEW SCROLLABLE BODY */}
        <div className="flex-1 overflow-y-auto p-8 relative">

          {/* VIEW: DASHBOARD */}
          {activeTab === 'dashboard' && (() => {
            const calculateSecurityScore = () => {
              let score = 100;
              if (!settings.realTimeProtection) score -= 20;
              if (!settings.aiDetection) score -= 15;
              if (!settings.ransomwareShield) score -= 15;
              if (!settings.usbProtection) score -= 10;
              if (!settings.networkMonitoring) score -= 10;
              if (activeThreatsCount > 0) score -= Math.min(30, activeThreatsCount * 10);
              return Math.max(0, score);
            };
            const score = calculateSecurityScore();
            const lastScan = scanHistory[0] ? new Date(scanHistory[0].date).toLocaleDateString() : 'Never';
            const isProtected = score >= 80 && settings.realTimeProtection;

            return (
              <div className="flex flex-col gap-6 animate-fadeIn font-mono text-xs text-slate-300">
                
                {/* 1. HERO SECURITY STATUS PANEL */}
                <div className={`p-6 rounded-3xl border flex flex-col md:flex-row justify-between items-center gap-6 ${
                  isProtected 
                    ? 'border-green-500/20 bg-green-500/5 text-slate-200 shadow-[0_0_20px_rgba(34,197,94,0.05)]' 
                    : 'border-red-500/20 bg-red-500/5 text-slate-200 shadow-[0_0_20px_rgba(239,68,68,0.05)]'
                }`}>
                  <div className="flex items-center gap-5">
                    <div className={`p-4 rounded-full border ${
                      isProtected 
                        ? 'bg-green-500/10 border-green-500/30 text-green-400' 
                        : 'bg-red-500/10 border-red-500/30 text-red-400'
                    }`}>
                      {isProtected ? <Shield className="w-10 h-10" /> : <AlertTriangle className="w-10 h-10" />}
                    </div>
                    <div className="flex flex-col gap-1 text-left">
                      <h2 className="text-xl font-bold text-white uppercase tracking-wider">
                        {isProtected ? 'Your System is Secured' : 'Action Required: System Vulnerable'}
                      </h2>
                      <p className="text-slate-400">
                        {isProtected 
                          ? 'Real-Time Protection is active and monitoring all system actions.' 
                          : 'Real-time shields are disabled or unresolved threats exist. Fix settings immediately.'}
                      </p>
                    </div>
                  </div>
                  <button 
                    onClick={handleQuickScan}
                    className="py-3 px-6 rounded-xl bg-cyan-500 text-[#0B1220] hover:bg-[#00E5FF]/80 transition font-black tracking-wider uppercase text-xs shadow-[0_0_15px_rgba(0,229,255,0.2)]"
                  >
                    Launch Quick Scan
                  </button>
                </div>

                {/* 2. STATS GRID */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-5">
                  <div className="glass-panel rounded-2xl p-5 flex flex-col gap-2.5 relative overflow-hidden border border-slate-800">
                    <span className="text-[10px] font-bold tracking-wider text-slate-500 uppercase">Protection Status</span>
                    <span className={`text-lg font-black ${settings.realTimeProtection ? 'text-green-400' : 'text-red-400'}`}>
                      {settings.realTimeProtection ? 'SHIELD ONLINE' : 'SHIELD DISABLED'}
                    </span>
                    <span className="text-[10px] text-slate-500">Real-Time Protection Status</span>
                  </div>

                  <div className="glass-panel rounded-2xl p-5 flex flex-col gap-2.5 relative overflow-hidden border border-slate-800">
                    <span className="text-[10px] font-bold tracking-wider text-slate-500 uppercase">Last Quick Scan</span>
                    <span className="text-lg font-black text-white">{lastScan}</span>
                    <span className="text-[10px] text-slate-500">Last system evaluation date</span>
                  </div>

                  <div className="glass-panel rounded-2xl p-5 flex flex-col gap-2.5 relative overflow-hidden border border-slate-800">
                    <span className="text-[10px] font-bold tracking-wider text-slate-500 uppercase">Threats Blocked</span>
                    <span className={`text-lg font-black ${totalBlockedCount > 0 ? 'text-red-400' : 'text-slate-350'}`}>
                      {totalBlockedCount}
                    </span>
                    <span className="text-[10px] text-slate-500">{activeThreatsCount} threats active / unresolved</span>
                  </div>

                  <div className="glass-panel rounded-2xl p-5 flex flex-col gap-2.5 relative overflow-hidden border border-slate-800">
                    <span className="text-[10px] font-bold tracking-wider text-slate-500 uppercase">Threats Isolated</span>
                    <span className="text-lg font-black text-cyan-400">{quarantineList.length}</span>
                    <span className="text-[10px] text-slate-500">Safely contained in quarantine vault</span>
                  </div>
                </div>

                {/* 3. ROW: DIALS & CONTROLS */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  
                  {/* Dial 1: Security Score Gauge */}
                  <div className="glass-panel rounded-2xl p-6 flex flex-col items-center justify-center text-center gap-4 border border-slate-800/80">
                    <span className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Security Score</span>
                    <div className="relative flex items-center justify-center w-28 h-28">
                      <svg className="w-full h-full transform -rotate-90">
                        <circle cx="56" cy="56" r="48" stroke="#1E293B" strokeWidth="8" fill="transparent" />
                        <circle 
                          cx="56" 
                          cy="56" 
                          r="48" 
                          stroke={score >= 80 ? "#22C55E" : score >= 55 ? "#EAB308" : "#EF4444"} 
                          strokeWidth="8" 
                          fill="transparent" 
                          strokeDasharray="301.6"
                          strokeDashoffset={301.6 - (301.6 * score) / 100}
                          className="transition-all duration-1000"
                        />
                      </svg>
                      <span className="absolute text-2xl font-black text-white">{score}%</span>
                    </div>
                    <span className={`px-2.5 py-0.5 rounded text-[10px] font-black border ${
                      score >= 80 
                        ? 'text-green-400 border-green-500/20 bg-green-500/5' 
                        : score >= 55 
                          ? 'text-yellow-400 border-yellow-500/20 bg-yellow-500/5' 
                          : 'text-red-400 border-red-500/20 bg-red-500/5'
                    }`}>
                      {score >= 80 ? 'PROTECTED' : score >= 55 ? 'ATTENTION' : 'DANGER'}
                    </span>
                  </div>

                  {/* Shield Controls Quick Switch Toggles */}
                  <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4 border border-slate-800/80 lg:col-span-2">
                    <h3 className="text-xs font-bold tracking-wider text-white uppercase border-b border-slate-800 pb-2">EDR Shield Module Controls</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 mt-1">
                      <div className="flex items-center justify-between p-2.5 bg-slate-900/30 rounded-xl border border-slate-850">
                        <div className="flex flex-col gap-0.5 max-w-[200px]">
                          <span className="text-white font-bold text-xs">Real-Time Protection</span>
                          <span className="text-[10px] text-slate-500">Scan incoming modules</span>
                        </div>
                        <button
                          onClick={() => handleUpdateSetting('realTimeProtection', !settings.realTimeProtection)}
                          className={`w-10 h-5 flex items-center rounded-full p-0.5 transition-all duration-200 ${
                            settings.realTimeProtection ? 'bg-[#00E5FF]' : 'bg-slate-700'
                          }`}
                        >
                          <div className={`bg-slate-900 w-4 h-4 rounded-full shadow-md transform transition-all duration-200 ${
                            settings.realTimeProtection ? 'translate-x-5' : ''
                          }`} />
                        </button>
                      </div>

                      <div className="flex items-center justify-between p-2.5 bg-slate-900/30 rounded-xl border border-slate-850">
                        <div className="flex flex-col gap-0.5 max-w-[200px]">
                          <span className="text-white font-bold text-xs">AI Heuristics Scanner</span>
                          <span className="text-[10px] text-slate-500">Static / Behavioral AI</span>
                        </div>
                        <button
                          onClick={() => handleUpdateSetting('aiDetection', !settings.aiDetection)}
                          className={`w-10 h-5 flex items-center rounded-full p-0.5 transition-all duration-200 ${
                            settings.aiDetection ? 'bg-[#00E5FF]' : 'bg-slate-700'
                          }`}
                        >
                          <div className={`bg-slate-900 w-4 h-4 rounded-full shadow-md transform transition-all duration-200 ${
                            settings.aiDetection ? 'translate-x-5' : ''
                          }`} />
                        </button>
                      </div>

                      <div className="flex items-center justify-between p-2.5 bg-slate-900/30 rounded-xl border border-slate-850">
                        <div className="flex flex-col gap-0.5 max-w-[200px]">
                          <span className="text-white font-bold text-xs">Ransomware Blocker</span>
                          <span className="text-[10px] text-slate-500">Shield rapid encryptions</span>
                        </div>
                        <button
                          onClick={() => handleUpdateSetting('ransomwareShield', !settings.ransomwareShield)}
                          className={`w-10 h-5 flex items-center rounded-full p-0.5 transition-all duration-200 ${
                            settings.ransomwareShield ? 'bg-[#00E5FF]' : 'bg-slate-700'
                          }`}
                        >
                          <div className={`bg-slate-900 w-4 h-4 rounded-full shadow-md transform transition-all duration-200 ${
                            settings.ransomwareShield ? 'translate-x-5' : ''
                          }`} />
                        </button>
                      </div>

                      <div className="flex items-center justify-between p-2.5 bg-slate-900/30 rounded-xl border border-slate-850">
                        <div className="flex flex-col gap-0.5 max-w-[200px]">
                          <span className="text-white font-bold text-xs">USB Shield Protection</span>
                          <span className="text-[10px] text-slate-500">Auto-check portable drives</span>
                        </div>
                        <button
                          onClick={() => handleUpdateSetting('usbProtection', !settings.usbProtection)}
                          className={`w-10 h-5 flex items-center rounded-full p-0.5 transition-all duration-200 ${
                            settings.usbProtection ? 'bg-[#00E5FF]' : 'bg-slate-700'
                          }`}
                        >
                          <div className={`bg-slate-900 w-4 h-4 rounded-full shadow-md transform transition-all duration-200 ${
                            settings.usbProtection ? 'translate-x-5' : ''
                          }`} />
                        </button>
                      </div>
                    </div>
                  </div>

                </div>

                {/* 4. UPDATER STATUS COMPONENT */}
                <div className="glass-panel rounded-2xl p-5 flex flex-col md:flex-row justify-between items-center gap-4 border border-slate-800/80">
                  <div className="flex flex-col gap-1 text-left">
                    <span className="text-[10px] text-slate-500 font-bold uppercase">Update & Signature Definitions</span>
                    <div className="flex items-center gap-2">
                      <span className="text-white font-bold text-xs">Definitions: v1.0.841</span>
                      <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-green-500/10 border border-green-500/20 text-green-400">CURRENT</span>
                    </div>
                  </div>
                  <button 
                    onClick={triggerSimulatedUpdateCheck}
                    className="py-2 px-4 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-200 text-xs font-bold transition"
                  >
                    Check for Updates
                  </button>
                </div>
                              {/* 5. RECENT INCIDENTS PANEL */}
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4 border border-slate-800/80">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-base font-bold text-white">Recent Security Threats Intercepted</h3>
                      <p className="text-xs text-slate-400">Proactive actions executed on zero-day executables and memory threats</p>
                    </div>
                    <button 
                      onClick={() => setActiveTab('threats')} 
                      className="text-xs text-[#00E5FF] hover:underline font-semibold"
                    >
                      View All Logs
                    </button>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                          <th className="py-3 px-4">Threat Info</th>
                          <th className="py-3 px-4">Type</th>
                          <th className="py-3 px-4">Location</th>
                          <th className="py-3 px-4">Time</th>
                          <th className="py-3 px-4">Severity</th>
                          <th className="py-3 px-4">Action Taken</th>
                        </tr>
                      </thead>
                      <tbody>
                        {incidents.length === 0 ? (
                          <tr>
                            <td colSpan={6} className="py-8 text-center text-slate-500 italic">
                              Zero security threats detected. System is running cleanly.
                            </td>
                          </tr>
                        ) : (
                          incidents.slice(0, 5).map((inc) => (
                            <tr key={inc.id} className="border-b border-slate-800/60 hover:bg-slate-900/20 transition">
                              <td className="py-3.5 px-4 font-bold text-white flex flex-col">
                                <span>{inc.name}</span>
                                <span className="text-[10px] text-slate-500 font-mono font-normal">SHA256: {inc.hash.slice(0,16)}...</span>
                              </td>
                              <td className="py-3.5 px-4 font-mono font-semibold text-slate-300">{inc.type}</td>
                              <td className="py-3.5 px-4 font-mono text-slate-400 truncate max-w-[200px]" title={inc.path}>{inc.path}</td>
                              <td className="py-3.5 px-4 text-slate-400">{new Date(inc.time).toLocaleString()}</td>
                              <td className="py-3.5 px-4">
                                <span className={`px-2.5 py-1 rounded-full border text-[10px] font-semibold ${getSeverityColor(inc.severity)}`}>
                                  {inc.severity.toUpperCase()}
                                </span>
                              </td>
                              <td className="py-3.5 px-4">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getStatusColor(inc.status)}`}>
                                  {inc.actionTaken}
                                </span>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

              </div>
            );
          })()}

          {/* VIEW: THREAT HISTORY */}
          {activeTab === 'threats' && (
            <div className="flex flex-col gap-6 animate-fadeIn">
              <div className="flex items-center justify-between">
                <div className="flex flex-col gap-2">
                  <h2 className="text-xl font-bold text-white">Threat History Log</h2>
                  <p className="text-xs text-slate-400">Consolidated logs of EDR block policies and automated threat isolation events</p>
                </div>
                {incidents.length > 0 && (
                  <button
                    onClick={handleClearIncidents}
                    className="py-1.5 px-3 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20 transition text-xs font-semibold flex items-center gap-1.5"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    Clear History Logs
                  </button>
                )}
              </div>

              {/* SEARCH FILTER */}
              <div className="flex items-center gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
                <Search className="w-4 h-4 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search historical threats by threat name, classification, path, hash, etc..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-transparent border-none outline-none text-xs text-slate-200 w-full placeholder-slate-500"
                />
              </div>

              <div className="glass-panel rounded-2xl overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                        <th className="py-3.5 px-5">Threat details</th>
                        <th className="py-3.5 px-5">Classification</th>
                        <th className="py-3.5 px-5">Target Path</th>
                        <th className="py-3.5 px-5">Severity</th>
                        <th className="py-3.5 px-5">Score</th>
                        <th className="py-3.5 px-5">Timestamp</th>
                        <th className="py-3.5 px-5">Response Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {incidents.length === 0 ? (
                        <tr>
                          <td colSpan={7} className="py-12 text-center text-slate-500 italic">
                            Zero incidents reported. System is healthy and secure.
                          </td>
                        </tr>
                      ) : (
                        incidents
                          .filter(i => i.name.toLowerCase().includes(searchQuery.toLowerCase()) || i.path.toLowerCase().includes(searchQuery.toLowerCase()) || i.type.toLowerCase().includes(searchQuery.toLowerCase()))
                          .map((inc) => (
                            <tr key={inc.id} className="border-b border-slate-800/60 hover:bg-slate-900/20 transition">
                              <td className="py-4 px-5">
                                <div className="flex flex-col gap-0.5">
                                  <span className="font-bold text-white text-sm">{inc.name}</span>
                                  <span className="text-[10px] text-slate-500 font-mono font-normal" title={inc.hash}>
                                    SHA256: {inc.hash.slice(0, 8)}...{inc.hash.slice(-8)}
                                  </span>
                                </div>
                              </td>
                              <td className="py-4 px-5 font-mono text-[#00E5FF] font-semibold">{inc.type}</td>
                              <td className="py-4 px-5">
                                <div className="font-mono text-slate-300 text-xs truncate max-w-[240px]" title={inc.path}>
                                  {inc.path}
                                </div>
                              </td>
                              <td className="py-4 px-5">
                                <span className={`px-2.5 py-1 rounded-full border text-[10px] font-semibold ${getSeverityColor(inc.severity)}`}>
                                  {inc.severity.toUpperCase()}
                                </span>
                              </td>
                              <td className="py-4 px-5 font-mono font-bold text-white">{inc.confidence}%</td>
                              <td className="py-4 px-5 text-slate-400 whitespace-nowrap">{new Date(inc.time).toLocaleString()}</td>
                              <td className="py-4 px-5">
                                <div className="flex flex-col gap-1 items-start max-w-[200px]">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusColor(inc.status)}`}>
                                    {inc.actionTaken}
                                  </span>
                                  {inc.details && (
                                    <div className="text-[10px] text-slate-400 font-mono line-clamp-2 mt-0.5 leading-normal" title={inc.details}>
                                      {inc.details}
                                    </div>
                                  )}
                                </div>
                              </td>
                            </tr>
                          ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* VIEW: QUARANTINE VAULT */}
          {activeTab === 'quarantine' && (
            <div className="flex flex-col gap-6 animate-fadeIn">
              <div className="flex flex-col gap-2">
                <h2 className="text-xl font-bold text-white">Quarantine Isolation Vault</h2>
                <p className="text-xs text-slate-400">Suspicious executables isolated using symmetric XOR byte-encryption. Restoring files decrypts them back to original paths.</p>
              </div>

              {quarantineList.length === 0 ? (
                <div className="glass-panel rounded-2xl p-12 flex flex-col items-center justify-center text-center gap-4">
                  <Lock className="w-12 h-12 text-slate-600" />
                  <div>
                    <h3 className="text-sm font-semibold text-slate-300">Quarantine Vault is Empty</h3>
                    <p className="text-xs text-slate-500 max-w-xs mt-1">Zero isolated files are currently stored in the encrypted backup folder.</p>
                  </div>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                  {quarantineList.map((file) => (
                    <div key={file.id} className="glass-panel rounded-xl p-5 flex flex-col gap-4 relative overflow-hidden">
                      <div className="flex justify-between items-start">
                        <div className="flex flex-col gap-0.5">
                          <span className="text-sm font-bold text-white truncate max-w-xs" title={file.originalPath.split('\\').pop()}>
                            {file.originalPath.split('\\').pop()}
                          </span>
                          <span className="text-[10px] text-slate-400 font-mono truncate max-w-xs" title={file.originalPath}>
                            Original Path: {file.originalPath}
                          </span>
                        </div>
                        <Lock className="w-4 h-4 text-cyan-400" />
                      </div>

                      <div className="flex flex-col gap-1.5 bg-black/20 p-3 rounded-lg border border-slate-900 font-mono text-[10px] text-slate-400">
                        <div>Backup Backup: <span className="text-slate-300 truncate block">{file.quarantinePath}</span></div>
                        <div className="mt-1 flex justify-between">
                          <span>Size: {(file.size / 1024).toFixed(1)} KB</span>
                          <span>Hash: {file.hash.slice(0, 16)}...</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Quarantine date:</span>
                          <span>{new Date(file.date).toLocaleString()}</span>
                        </div>
                      </div>

                      <div className="flex gap-3 justify-end">
                        <button
                          onClick={() => handleRestoreQuarantine(file.id)}
                          className="py-1.5 px-3 rounded-lg border border-[#00E5FF]/20 bg-cyan-500/5 hover:bg-cyan-500/15 text-[#00E5FF] transition text-xs font-semibold flex items-center gap-1.5"
                        >
                          <RotateCcw className="w-3.5 h-3.5" />
                          Restore file
                        </button>
                        <button
                          onClick={() => handleDeleteQuarantine(file.id)}
                          className="py-1.5 px-3 rounded-lg border border-red-500/30 bg-red-500/5 hover:bg-red-500/15 text-red-400 transition text-xs font-semibold flex items-center gap-1.5"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          Delete permanently
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* VIEW: THREAT SCANNER (SCAN CENTER) */}
          {activeTab === 'scanner' && (
            <div className="flex flex-col gap-6 animate-fadeIn">
              <div className="flex flex-col gap-2">
                <h2 className="text-xl font-bold text-white font-mono">Threat Protection Scan Center</h2>
                <p className="text-xs text-slate-400 font-mono">Select an execution analysis mode below or review historical intelligence reports.</p>
              </div>

              {/* IF SCAN IS RUNNING */}
              {scanStatus !== 'System Idle' && liveScanStatus && liveScanStatus.progress < 100 && (
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-5 max-w-4xl font-mono text-xs text-slate-300">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                    <span className="text-sm font-bold text-[#00E5FF]">{liveScanStatus.scanType} in Progress</span>
                    <div className="flex items-center gap-3">
                      <button
                        onClick={handleToggleScanPause}
                        className={`px-3 py-1 rounded-lg border text-[10px] font-bold transition ${
                          isScanPaused 
                            ? 'border-green-500/30 bg-green-500/10 text-green-400 hover:bg-green-500/20' 
                            : 'border-amber-500/30 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20'
                        }`}
                      >
                        {isScanPaused ? 'RESUME SCAN' : 'PAUSE SCAN'}
                      </button>
                      <button
                        onClick={handleCancelScan}
                        className="px-3 py-1 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20 text-[10px] font-bold transition"
                      >
                        STOP SCAN
                      </button>
                      <span className="text-white font-bold text-sm">{liveScanStatus.progress}%</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-[#0E1726]/40 p-4 rounded-xl border border-slate-800">
                    <div className="flex flex-col gap-1">
                      <span className="text-[10px] text-slate-500 font-bold uppercase">Files Scanned</span>
                      <span className="text-white font-black text-sm">{liveScanStatus.filesScanned}</span>
                    </div>
                    <div className="flex flex-col gap-1">
                      <span className="text-[10px] text-slate-500 font-bold uppercase">Files Skipped</span>
                      <span className="text-slate-400 font-black text-sm">{liveScanStatus.filesSkipped}</span>
                    </div>
                    <div className="flex flex-col gap-1">
                      <span className="text-[10px] text-slate-500 font-bold uppercase">Threats Found</span>
                      <span className={`font-black text-sm ${liveScanStatus.threatsFound > 0 ? 'text-red-400' : 'text-green-400'}`}>
                        {liveScanStatus.threatsFound}
                      </span>
                    </div>
                    <div className="flex flex-col gap-1">
                      <span className="text-[10px] text-slate-500 font-bold uppercase">Time Remaining</span>
                      <span className="text-white font-black text-sm">{liveScanStatus.estimatedTimeRemaining}</span>
                    </div>
                  </div>

                  <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden">
                    <div 
                      className={`h-full rounded-full transition-all duration-300 ${
                        isScanPaused ? 'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]' : 'bg-[#00E5FF] glow-cyan'
                      }`}
                      style={{ width: `${liveScanStatus.progress}%` }} 
                    />
                  </div>

                  <div className="flex flex-col gap-1.5 bg-black/15 p-3 rounded-lg border border-slate-900 leading-normal">
                    <div>Active Checking Gate: <span className="text-yellow-400 font-bold">{liveScanStatus.currentLayer}</span></div>
                    <div className="truncate">Scanning Module: <span className="text-white font-semibold">{liveScanStatus.currentFile || 'Initiating crawler...'}</span></div>
                  </div>

                  {/* Real-time scanned files feed */}
                  {scannedFiles.length > 0 && (
                    <div className="flex flex-col gap-2 mt-1 bg-slate-900/40 p-3 rounded-lg border border-slate-800">
                      <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Real-time Telemetry Stream</span>
                      <div className="flex flex-col gap-1.5 max-h-[120px] overflow-y-auto pr-1">
                        {scannedFiles.slice(0, 10).map((f, idx) => (
                          <div key={idx} className="flex justify-between items-center bg-black/20 p-1.5 rounded border border-slate-850">
                            <span className="text-slate-300 truncate max-w-[280px]" title={f.filePath}>{f.fileName}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${
                              f.status === 'Malicious' ? 'text-red-400 border-red-500/20 bg-red-500/5' : 'text-green-400 border-green-500/20 bg-green-500/5'
                            }`}>
                              {f.status}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* IF SCAN IS NOT RUNNING */}
              {(scanStatus === 'System Idle' || (liveScanStatus && liveScanStatus.progress === 100)) && (
                <>
                  {/* SUBTAB 1: SCAN OPTIONS */}
                  {scannerSubTab === 'options' && (
                    <div className="flex flex-col gap-6">
                      <div className="flex justify-end gap-3">
                        <button
                          onClick={() => setScannerSubTab('history')}
                          className="py-1.5 px-3.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-300 text-xs font-semibold flex items-center gap-1.5 font-mono"
                        >
                          <History className="w-3.5 h-3.5" />
                          View Historical Scan Reports ({scanHistory.length})
                        </button>
                      </div>

                      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        {/* QUICK / NORMAL SCAN CARD */}
                        <div className="glass-panel rounded-2xl p-5 flex flex-col justify-between gap-5 relative overflow-hidden">
                          <div className="flex flex-col gap-2">
                            <div className="p-2 rounded-lg bg-green-500/10 border border-green-500/20 w-fit text-green-400">
                              <Play className="w-4 h-4" />
                            </div>
                            <h3 className="text-sm font-bold text-white">Daily Quick Scan</h3>
                            <p className="text-xs text-slate-400 leading-relaxed">
                              Scan high-risk target folders and registry nodes.
                            </p>
                            <div className="border-t border-slate-800/80 pt-3 flex flex-col gap-1 font-mono text-[10px] text-slate-500 leading-normal">
                              <span className="text-slate-400 font-bold uppercase text-[9px]">Scopes Checked:</span>
                              <div>• User Desktop, Documents, Downloads</div>
                              <div>• Startup Programs / Run Registry keys</div>
                              <div>• Running Processes / Services</div>
                              <div>• Active USB Removable Drives</div>
                            </div>
                          </div>
                          <button
                            onClick={handleQuickScan}
                            className="w-full py-2 rounded-lg bg-green-500 hover:bg-green-400 text-slate-900 transition text-xs font-bold font-mono uppercase tracking-wider"
                          >
                            Run Quick Scan
                          </button>
                        </div>

                        {/* DEEP SCAN CARD */}
                        <div className="glass-panel rounded-2xl p-5 flex flex-col justify-between gap-5 relative overflow-hidden">
                          <div className="flex flex-col gap-2">
                            <div className="p-2 rounded-lg bg-[#00E5FF]/10 border border-[#00E5FF]/20 w-fit text-[#00E5FF]">
                              <Shield className="w-4 h-4" />
                            </div>
                            <h3 className="text-sm font-bold text-white">Full System Deep Scan</h3>
                            <p className="text-xs text-slate-400 leading-relaxed">
                              Performs deep traversal of binary images and directories.
                            </p>
                            <div className="border-t border-slate-800/80 pt-3 flex flex-col gap-1 font-mono text-[10px] text-slate-500 leading-normal">
                              <span className="text-[#00E5FF] font-bold uppercase text-[9px]">Scopes Checked:</span>
                              <div>• Entire File System & Hidden folders</div>
                              <div>• Temporary dirs & System32 libs</div>
                              <div>• Scheduled Tasks / Browser Extensions</div>
                              <div>• Memory inspection & Network ports</div>
                            </div>
                          </div>
                          <button
                            onClick={handleDeepScan}
                            className="w-full py-2 rounded-lg bg-[#00E5FF] hover:bg-[#00E5FF]/80 text-[#0B1220] transition text-xs font-bold font-mono uppercase tracking-wider"
                          >
                            Run Deep Scan
                          </button>
                        </div>

                        {/* CUSTOM SCAN CARD */}
                        <div className="glass-panel rounded-2xl p-5 flex flex-col justify-between gap-5 relative overflow-hidden">
                          <div className="flex flex-col gap-2">
                            <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20 w-fit text-purple-400">
                              <FolderOpen className="w-4 h-4" />
                            </div>
                            <h3 className="text-sm font-bold text-white">Custom Target Scan</h3>
                            <p className="text-xs text-slate-400 leading-relaxed font-mono text-slate-500 break-all">
                              Path: {selectedScanPath}
                            </p>
                          </div>
                          <div className="flex gap-2">
                            <button
                              onClick={handleSelectFolder}
                              className="py-2 px-3 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-300 text-xs font-bold font-mono"
                            >
                              Browse
                            </button>
                            <button
                              onClick={handleCustomScan}
                              className="flex-1 py-2 rounded-lg bg-purple-500 hover:bg-purple-450 text-slate-950 transition text-xs font-bold font-mono uppercase tracking-wider"
                            >
                              Scan Path
                            </button>
                          </div>
                        </div>
                      </div>

                      {/* DRAG AND DROP ZONE */}
                      <div 
                        ref={dropZoneRef}
                        onDragOver={handleDragOver}
                        onDragLeave={handleDragLeave}
                        onDrop={handleDrop}
                        className={`border-2 border-dashed rounded-2xl p-12 flex flex-col items-center justify-center text-center gap-4 transition select-none ${
                          isDragOver 
                            ? 'border-[#00E5FF] bg-cyan-500/5 glow-cyan' 
                            : 'border-slate-800 bg-[#0E1726]/30 hover:border-slate-700'
                        }`}
                      >
                        <Upload className="w-10 h-10 text-slate-500 animate-bounce" />
                        <div>
                          <h3 className="text-sm font-bold text-slate-200">Drag & Drop Executables</h3>
                          <p className="text-xs text-slate-500 max-w-xs mt-1">
                            Drag any file here to trigger instant multi-layer AI classification and signature scans.
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* SUBTAB 2: SCAN RESULTS DETAIL */}
                  {scannerSubTab === 'results' && activeReport && (
                    <div className="flex flex-col gap-6 animate-fadeIn font-mono text-xs text-slate-300">
                      <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                        <h3 className="text-sm font-bold text-white uppercase tracking-wider">Scan Diagnostic Report Summary</h3>
                        <button
                          onClick={() => setScannerSubTab('options')}
                          className="py-1.5 px-3 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-300 text-xs font-semibold"
                        >
                          Back to Scan Center
                        </button>
                      </div>

                      <div className="flex flex-col lg:flex-row gap-6">
                        
                        {/* LEFT COLUMN: STATS AND THREATS */}
                        <div className="flex-1 flex flex-col gap-6">
                          
                          <div className="flex flex-col md:flex-row gap-5">
                            {/* Security Score Gauge card */}
                            <div className="glass-panel rounded-2xl p-6 flex flex-col items-center justify-center text-center gap-4 w-full md:w-[200px] bg-slate-950/20 border border-slate-800">
                              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Security Score</span>
                              <div className="relative flex items-center justify-center w-24 h-24">
                                <svg className="w-full h-full transform -rotate-90">
                                  <circle cx="48" cy="48" r="40" stroke="#1E293B" strokeWidth="6" fill="transparent" />
                                  <circle 
                                    cx="48" 
                                    cy="48" 
                                    r="40" 
                                    stroke={activeReport.securityScore >= 70 ? "#22C55E" : activeReport.securityScore >= 40 ? "#EAB308" : "#EF4444"} 
                                    strokeWidth="6" 
                                    fill="transparent" 
                                    strokeDasharray="251.2"
                                    strokeDashoffset={251.2 - (251.2 * activeReport.securityScore) / 100}
                                    className="transition-all duration-1000"
                                  />
                                </svg>
                                <span className="absolute text-xl font-black text-white">{activeReport.securityScore}%</span>
                              </div>
                              <span className={`px-2 py-0.5 rounded text-[9px] font-black border ${
                                activeReport.securityScore >= 70 
                                  ? 'text-green-400 border-green-500/20 bg-green-500/5' 
                                  : activeReport.securityScore >= 40 
                                    ? 'text-yellow-400 border-yellow-500/20 bg-yellow-500/5' 
                                    : 'text-red-400 border-red-500/20 bg-red-500/5'
                              }`}>
                                {activeReport.securityScore >= 70 ? 'HEALTHY' : activeReport.securityScore >= 40 ? 'SUSPICIOUS' : 'MALICIOUS'}
                              </span>
                            </div>

                            {/* Details metadata grid */}
                            <div className="flex-1 grid grid-cols-2 md:grid-cols-3 gap-4">
                              <div className="glass-panel rounded-xl p-3 flex flex-col justify-center gap-1.5">
                                <span className="text-[10px] text-slate-500 font-bold uppercase">Scan Mode</span>
                                <span className="text-white font-black text-xs truncate">{activeReport.scanType}</span>
                              </div>
                              <div className="glass-panel rounded-xl p-3 flex flex-col justify-center gap-1.5">
                                <span className="text-[10px] text-slate-500 font-bold uppercase">Files Evaluated</span>
                                <span className="text-white font-black text-xs">{activeReport.filesScanned}</span>
                              </div>
                              <div className="glass-panel rounded-xl p-3 flex flex-col justify-center gap-1.5">
                                <span className="text-[10px] text-slate-500 font-bold uppercase">Files Skipped</span>
                                <span className="text-slate-400 font-black text-xs">{activeReport.filesSkipped}</span>
                              </div>
                              <div className="glass-panel rounded-xl p-3 flex flex-col justify-center gap-1.5">
                                <span className="text-[10px] text-slate-500 font-bold uppercase">Threats Detected</span>
                                <span className={`font-black text-xs ${activeReport.threatsFound > 0 ? 'text-red-400' : 'text-green-400'}`}>
                                  {activeReport.threatsFound}
                                </span>
                              </div>
                              <div className="glass-panel rounded-xl p-3 flex flex-col justify-center gap-1.5">
                                <span className="text-[10px] text-slate-500 font-bold uppercase">Threats Isolated</span>
                                <span className="text-cyan-400 font-black text-xs">{activeReport.threatsRemoved}</span>
                              </div>
                              <div className="glass-panel rounded-xl p-3 flex flex-col justify-center gap-1.5">
                                <span className="text-[10px] text-slate-500 font-bold uppercase">Duration</span>
                                <span className="text-white font-black text-xs">
                                  {activeReport.duration >= 60 ? `${Math.floor(activeReport.duration / 60)}m ${activeReport.duration % 60}s` : `${activeReport.duration}s`}
                                </span>
                              </div>
                              <div className="glass-panel rounded-xl p-3 flex flex-col justify-center gap-1.5">
                                <span className="text-[10px] text-slate-500 font-bold uppercase">Avg CPU Usage</span>
                                <span className="text-white font-black text-xs">{activeReport.cpuUsage}%</span>
                              </div>
                              <div className="glass-panel rounded-xl p-3 flex flex-col justify-center gap-1.5">
                                <span className="text-[10px] text-slate-500 font-bold uppercase">Date Evaluated</span>
                                <span className="text-slate-400 font-black text-xs">
                                  {new Date(activeReport.date).toLocaleDateString()}
                                </span>
                              </div>
                            </div>
                          </div>

                          {/* Threats table list */}
                          <div className="glass-panel rounded-2xl p-5 flex flex-col gap-4 border border-slate-800">
                            <span className="font-bold text-white border-b border-slate-850 pb-2">Detected Suspicious Artifacts Log</span>
                            <div className="overflow-x-auto">
                              <table className="w-full text-left text-xs border-collapse">
                                <thead>
                                  <tr className="border-b border-slate-800 text-slate-400 uppercase font-semibold">
                                    <th className="py-2 px-3">File details</th>
                                    <th className="py-2 px-3">Category</th>
                                    <th className="py-2 px-3">Hash</th>
                                    <th className="py-2 px-3">Impact score</th>
                                    <th className="py-2 px-3">Status</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {(() => {
                                    try {
                                      const threats = JSON.parse(activeReport.detailsJson);
                                      if (!threats || threats.length === 0) {
                                        return (
                                          <tr>
                                            <td colSpan={5} className="py-6 text-center text-slate-500 italic">
                                              Zero malicious artifacts flagged in this scan. Complete security verified.
                                            </td>
                                          </tr>
                                        );
                                      }
                                      return threats.map((t: any, i: number) => (
                                        <tr 
                                          key={i} 
                                          onClick={async () => {
                                            if (electronAPI && t.filePath) {
                                              try {
                                                const fullRes = await electronAPI.runMultiLayerScan(t.filePath);
                                                setActiveAnalysis(fullRes);
                                                setCurrentAnimLayer(6);
                                              } catch {
                                                alert("This file has been quarantined and isolated by the EDR containment engine.");
                                              }
                                            }
                                          }}
                                          className="border-b border-slate-800/40 hover:bg-slate-900/10 cursor-pointer transition"
                                        >
                                          <td className="py-3 px-3">
                                            <div className="flex flex-col">
                                              <span className="text-white font-bold">{t.fileName}</span>
                                              <span className="text-[10px] text-slate-500 truncate max-w-[240px]" title={t.filePath}>{t.filePath}</span>
                                            </div>
                                          </td>
                                          <td className="py-3 px-3">
                                            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold border border-red-500/20 bg-red-500/5 text-red-400">
                                              {t.type || 'Malware'}
                                            </span>
                                          </td>
                                          <td className="py-3 px-3 font-mono text-[10px] text-slate-400">
                                            {t.hash ? `${t.hash.slice(0, 8)}...${t.hash.slice(-8)}` : 'N/A'}
                                          </td>
                                          <td className="py-3 px-3 text-white font-bold">{t.finalScore}%</td>
                                          <td className="py-3 px-3 text-slate-450">{t.status || 'Detected'}</td>
                                        </tr>
                                      ));
                                    } catch {
                                      return (
                                        <tr>
                                          <td colSpan={5} className="py-6 text-center text-slate-500 italic">
                                            Error parsing scan threat reports metadata.
                                          </td>
                                        </tr>
                                      );
                                    }
                                  })()}
                                </tbody>
                              </table>
                            </div>
                          </div>

                        </div>

                        {/* RIGHT COLUMN: DETAILED DIAGNOSTICS */}
                        <div className="w-full lg:w-[420px] flex flex-col gap-6">
                          {renderAiLayerAnalysis()}
                        </div>

                      </div>

                    </div>
                  )}

                  {/* SUBTAB 3: SCAN HISTORY REPORTS LOG */}
                  {scannerSubTab === 'history' && (
                    <div className="flex flex-col gap-6 animate-fadeIn font-mono text-xs text-slate-300">
                      <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                        <h3 className="text-sm font-bold text-white uppercase tracking-wider">Scan History & Reports Log</h3>
                        <button
                          onClick={() => setScannerSubTab('options')}
                          className="py-1.5 px-3 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-300 text-xs font-semibold"
                        >
                          Back to Scan Center
                        </button>
                      </div>

                      <div className="glass-panel rounded-2xl overflow-hidden border border-slate-800">
                        <div className="overflow-x-auto">
                          <table className="w-full text-left text-xs border-collapse">
                            <thead>
                              <tr className="border-b border-slate-800 text-slate-400 uppercase font-semibold">
                                <th className="py-3 px-5">Date</th>
                                <th className="py-3 px-5">Scan Type</th>
                                <th className="py-3 px-5">Duration</th>
                                <th className="py-3 px-5">Files Evaluated</th>
                                <th className="py-3 px-5">Threats Detected</th>
                                <th className="py-3 px-5">Threats Removed</th>
                                <th className="py-3 px-5">Security Score</th>
                                <th className="py-3 px-5">Action</th>
                              </tr>
                            </thead>
                            <tbody>
                              {scanHistory.length === 0 ? (
                                  <tr>
                                    <td colSpan={8} className="py-12 text-center text-slate-500 italic">
                                      Zero scans recorded in history log database.
                                    </td>
                                  </tr>
                                ) : (
                                  scanHistory.map((h: any) => (
                                    <tr key={h.id} className="border-b border-slate-800/60 hover:bg-slate-900/20 transition">
                                      <td className="py-3.5 px-5 text-slate-300 font-mono">
                                        {new Date(h.date).toLocaleString()}
                                      </td>
                                      <td className="py-3.5 px-5 font-bold text-white">{h.scanType}</td>
                                      <td className="py-3.5 px-5 text-slate-450">
                                        {h.duration >= 60 ? `${Math.floor(h.duration / 60)}m ${h.duration % 60}s` : `${h.duration}s`}
                                      </td>
                                      <td className="py-3.5 px-5 text-slate-450">{h.filesScanned}</td>
                                      <td className="py-3.5 px-5 text-red-400 font-bold">{h.threatsFound}</td>
                                      <td className="py-3.5 px-5 text-cyan-400 font-bold">{h.threatsRemoved}</td>
                                      <td className="py-3.5 px-5">
                                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                          h.securityScore >= 70 ? 'text-green-400 border-green-500/20 bg-green-500/5' : 'text-red-400 border-red-500/20 bg-red-500/5'
                                        }`}>
                                          {h.securityScore}%
                                        </span>
                                      </td>
                                      <td className="py-3.5 px-5">
                                        <button
                                          onClick={() => {
                                            setActiveReport(h);
                                            setScannerSubTab('results');
                                          }}
                                          className="py-1 px-2.5 rounded border border-[#00E5FF]/20 bg-cyan-500/5 hover:bg-cyan-500/15 text-[#00E5FF] transition font-bold"
                                        >
                                          View Report
                                        </button>
                                      </td>
                                    </tr>
                                  ))
                                )}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {/* VIEW: SETTINGS */}
          {activeTab === 'settings' && (
            <div className="flex flex-col gap-6 animate-fadeIn font-mono text-xs text-slate-350">
              <div className="flex flex-col gap-1.5 text-left">
                <h2 className="text-xl font-bold text-white uppercase tracking-wider">SentinelAI Preferences</h2>
                <p className="text-slate-500">Configure security engines, system tray integration, and threat containment parameters.</p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 max-w-5xl">
                
                {/* CATEGORY 1: GENERAL SYSTEM PREFERENCES */}
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4 border border-slate-800/80">
                  <h3 className="text-sm font-bold text-white border-b border-slate-800 pb-2 uppercase tracking-wide">General Preferences</h3>
                  
                  <div className="flex items-center justify-between p-3 bg-slate-900/30 rounded-xl border border-slate-850">
                    <div className="flex flex-col gap-1">
                      <span className="text-white font-bold">Launch at Startup</span>
                      <span className="text-[10px] text-slate-500">Automatically launch SentinelAI in tray on system boot</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('startWithWindows', !settings.startWithWindows)}
                      className={`w-10 h-5 flex items-center rounded-full p-0.5 transition ${settings.startWithWindows ? 'bg-[#00E5FF]' : 'bg-slate-700'}`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full transition ${settings.startWithWindows ? 'translate-x-5' : ''}`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between p-3 bg-slate-900/30 rounded-xl border border-slate-850">
                    <div className="flex flex-col gap-1">
                      <span className="text-white font-bold">Minimize to System Tray</span>
                      <span className="text-[10px] text-slate-500">Clicking "X" hides window to tray instead of exiting</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('minimizeToTray', !settings.minimizeToTray)}
                      className={`w-10 h-5 flex items-center rounded-full p-0.5 transition ${settings.minimizeToTray ? 'bg-[#00E5FF]' : 'bg-slate-700'}`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full transition ${settings.minimizeToTray ? 'translate-x-5' : ''}`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between p-3 bg-slate-900/30 rounded-xl border border-slate-850">
                    <div className="flex flex-col gap-1">
                      <span className="text-white font-bold">Automatic Security Updates</span>
                      <span className="text-[10px] text-slate-500">Keep definitions and heuristics database up to date</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('autoUpdates', !settings.autoUpdates)}
                      className={`w-10 h-5 flex items-center rounded-full p-0.5 transition ${settings.autoUpdates ? 'bg-[#00E5FF]' : 'bg-slate-700'}`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full transition ${settings.autoUpdates ? 'translate-x-5' : ''}`} />
                    </button>
                  </div>
                </div>

                {/* CATEGORY 2: EDR LAYERED SHIELD PROTECTION */}
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4 border border-slate-800/80">
                  <h3 className="text-sm font-bold text-white border-b border-slate-800 pb-2 uppercase tracking-wide">Shield Protections</h3>
                  
                  <div className="flex items-center justify-between p-2.5 bg-slate-900/30 rounded-xl border border-slate-850">
                    <div className="flex flex-col gap-0.5">
                      <span className="text-white font-bold">Real-Time Protection</span>
                      <span className="text-[10px] text-slate-500">Continuous file path scanning</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('realTimeProtection', !settings.realTimeProtection)}
                      className={`w-10 h-5 flex items-center rounded-full p-0.5 transition ${settings.realTimeProtection ? 'bg-[#00E5FF]' : 'bg-slate-700'}`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full transition ${settings.realTimeProtection ? 'translate-x-5' : ''}`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between p-2.5 bg-slate-900/30 rounded-xl border border-slate-850">
                    <div className="flex flex-col gap-0.5">
                      <span className="text-white font-bold">Anti-Ransomware Blocker</span>
                      <span className="text-[10px] text-slate-500">Shield rapid directory encrypts</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('ransomwareShield', !settings.ransomwareShield)}
                      className={`w-10 h-5 flex items-center rounded-full p-0.5 transition ${settings.ransomwareShield ? 'bg-[#00E5FF]' : 'bg-slate-700'}`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full transition ${settings.ransomwareShield ? 'translate-x-5' : ''}`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between p-2.5 bg-slate-900/30 rounded-xl border border-slate-850">
                    <div className="flex flex-col gap-0.5">
                      <span className="text-white font-bold">Removable USB Shield</span>
                      <span className="text-[10px] text-slate-500">Auto-check USB insert payloads</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('usbProtection', !settings.usbProtection)}
                      className={`w-10 h-5 flex items-center rounded-full p-0.5 transition ${settings.usbProtection ? 'bg-[#00E5FF]' : 'bg-slate-700'}`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full transition ${settings.usbProtection ? 'translate-x-5' : ''}`} />
                    </button>
                  </div>
                </div>

                {/* CATEGORY 3: HEURISTICS & AUTO-CONTAINMENT */}
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4 border border-slate-800/80">
                  <h3 className="text-sm font-bold text-white border-b border-slate-800 pb-2 uppercase tracking-wide">Scanning Engines</h3>
                  
                  <div className="flex flex-col gap-2">
                    <div className="flex justify-between text-[10px] font-bold">
                      <span className="text-slate-400">Heuristics Sensitivity</span>
                      <span className="text-[#00E5FF]">{settings.aiSensitivity}%</span>
                    </div>
                    <input
                      type="range"
                      min="10"
                      max="100"
                      value={settings.aiSensitivity}
                      onChange={(e) => handleUpdateSetting('aiSensitivity', parseInt(e.target.value))}
                      className="w-full accent-[#00E5FF] cursor-pointer"
                    />
                    <div className="flex justify-between text-[8px] text-slate-600 font-bold">
                      <span>MINIMAL</span>
                      <span>BALANCED</span>
                      <span>AGGRESSIVE</span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between p-2.5 bg-slate-900/30 rounded-xl border border-slate-850 mt-1">
                    <div className="flex flex-col gap-0.5">
                      <span className="text-white font-bold">Auto-Quarantine</span>
                      <span className="text-[10px] text-slate-500">Isolate malicious files automatically</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('autoQuarantine', !settings.autoQuarantine)}
                      className={`w-10 h-5 flex items-center rounded-full p-0.5 transition ${settings.autoQuarantine ? 'bg-[#00E5FF]' : 'bg-slate-700'}`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full transition ${settings.autoQuarantine ? 'translate-x-5' : ''}`} />
                    </button>
                  </div>
                </div>

                {/* CATEGORY 4: NOTIFICATIONS & ALERTS */}
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4 border border-slate-800/80">
                  <h3 className="text-sm font-bold text-white border-b border-slate-800 pb-2 uppercase tracking-wide">Alert Preferences</h3>
                  
                  <div className="flex items-center justify-between p-3 bg-slate-900/30 rounded-xl border border-slate-850">
                    <div className="flex flex-col gap-1">
                      <span className="text-white font-bold">Desktop Notifications</span>
                      <span className="text-[10px] text-slate-500">Show tray toast alerts for security incidents</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('desktopNotifications', !settings.desktopNotifications)}
                      className={`w-10 h-5 flex items-center rounded-full p-0.5 transition ${settings.desktopNotifications ? 'bg-[#00E5FF]' : 'bg-slate-700'}`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full transition ${settings.desktopNotifications ? 'translate-x-5' : ''}`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between p-3 bg-slate-900/30 rounded-xl border border-slate-850">
                    <div className="flex flex-col gap-1">
                      <span className="text-white font-bold">Email Alerts</span>
                      <span className="text-[10px] text-slate-500">Send logs to registered admin email address</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('emailAlerts', !settings.emailAlerts)}
                      className={`w-10 h-5 flex items-center rounded-full p-0.5 transition ${settings.emailAlerts ? 'bg-[#00E5FF]' : 'bg-slate-700'}`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full transition ${settings.emailAlerts ? 'translate-x-5' : ''}`} />
                    </button>
                  </div>
                </div>

                {/* CATEGORY 5: INTELLIGENCE & PRIVACY */}
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4 border border-slate-800/80 lg:col-span-2">
                  <h3 className="text-sm font-bold text-white border-b border-slate-800 pb-2 uppercase tracking-wide">Threat Intel & Privacy</h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="flex flex-col gap-2">
                      <label className="text-[10px] text-slate-400 font-bold">VirusTotal API Key (Verification Layer)</label>
                      <div className="flex items-center gap-3 bg-slate-900/60 p-2.5 rounded-xl border border-slate-800">
                        <input
                          type={showApiKey ? 'text' : 'password'}
                          placeholder="Enter VirusTotal API key..."
                          value={settings.virusTotalApiKey}
                          onChange={(e) => handleUpdateSetting('virusTotalApiKey', e.target.value)}
                          className="bg-transparent border-none outline-none text-xs text-slate-200 w-full placeholder-slate-650 font-mono"
                        />
                        <button 
                          onClick={() => setShowApiKey(!showApiKey)}
                          className="text-slate-500 hover:text-slate-350"
                        >
                          {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>

                    <div className="flex flex-col gap-3 justify-center pt-2">
                      <div className="flex items-center justify-between p-2.5 bg-slate-900/30 rounded-xl border border-slate-850">
                        <div className="flex flex-col gap-0.5">
                          <span className="text-white font-bold">Share Threat Signatures</span>
                          <span className="text-[10px] text-slate-500">Contribute isolated logs to security net</span>
                        </div>
                        <button
                          onClick={() => handleUpdateSetting('shareIntel', !settings.shareIntel)}
                          className={`w-10 h-5 flex items-center rounded-full p-0.5 transition ${settings.shareIntel ? 'bg-[#00E5FF]' : 'bg-slate-700'}`}
                        >
                          <div className={`bg-slate-900 w-4 h-4 rounded-full transition ${settings.shareIntel ? 'translate-x-5' : ''}`} />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

              </div>
            </div>
          )}

        </div>
      </main>

      {/* 4-STEP ONBOARDING WIZARD OVERLAY */}
      {settings.firstTimeUser && (
        <div className="fixed inset-0 z-50 bg-[#070D18]/95 flex items-center justify-center p-4 backdrop-blur-md">
          <div className="glass-panel w-full max-w-lg rounded-3xl p-8 border border-slate-800 shadow-[0_0_50px_rgba(0,229,255,0.1)] flex flex-col gap-6 text-slate-350">
            {/* Step Indicators */}
            <div className="flex items-center justify-center gap-3">
              {[1, 2, 3, 4].map(s => (
                <div 
                  key={s} 
                  className={`h-1.5 rounded-full transition-all duration-300 ${
                    onboardingStep === s 
                      ? 'w-8 bg-[#00E5FF]' 
                      : onboardingStep > s 
                        ? 'w-3 bg-green-500' 
                        : 'w-3 bg-slate-800'
                  }`}
                />
              ))}
            </div>

            {/* Step 1: Welcome */}
            {onboardingStep === 1 && (
              <div className="flex flex-col items-center text-center gap-4 animate-fadeIn font-mono">
                <div className="p-4 rounded-full bg-cyan-500/10 border border-[#00E5FF]/20 text-[#00E5FF] animate-pulse">
                  <Shield className="w-12 h-12" />
                </div>
                <h2 className="text-xl font-bold text-white uppercase tracking-wider">Welcome to SentinelAI</h2>
                <p className="text-xs text-slate-400 max-w-sm leading-relaxed">
                  SentinelAI provides state-of-the-art Endpoint Detection & Response (EDR). Let's initialize your shields.
                </p>
                <button 
                  onClick={() => setOnboardingStep(2)}
                  className="mt-4 w-full py-3 rounded-xl bg-cyan-500 hover:bg-[#00E5FF] text-[#0B1220] font-black uppercase text-xs transition"
                >
                  Configure Shield
                </button>
              </div>
            )}

            {/* Step 2: Protection configuration toggles */}
            {onboardingStep === 2 && (
              <div className="flex flex-col gap-4 animate-fadeIn font-mono">
                <div className="text-center flex flex-col gap-1.5">
                  <h2 className="text-xl font-bold text-white uppercase tracking-wider">Shield Settings</h2>
                  <p className="text-xs text-slate-400">Enable default security shield components</p>
                </div>
                <div className="flex flex-col gap-3 py-2">
                  <div className="flex items-center justify-between p-3 bg-slate-900/40 rounded-xl border border-slate-800">
                    <div className="flex flex-col">
                      <span className="text-xs font-bold text-white">Real-Time Protection</span>
                      <span className="text-[10px] text-slate-500">Continuous path scanning</span>
                    </div>
                    <button 
                      onClick={() => handleUpdateSetting('realTimeProtection', !settings.realTimeProtection)}
                      className={`w-10 h-5 flex items-center rounded-full p-0.5 transition ${settings.realTimeProtection ? 'bg-[#00E5FF]' : 'bg-slate-700'}`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full transition ${settings.realTimeProtection ? 'translate-x-5' : ''}`} />
                    </button>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-slate-900/40 rounded-xl border border-slate-800">
                    <div className="flex flex-col">
                      <span className="text-xs font-bold text-white">Heuristic AI Engine</span>
                      <span className="text-[10px] text-slate-500">Detect zero-day variants</span>
                    </div>
                    <button 
                      onClick={() => handleUpdateSetting('aiDetection', !settings.aiDetection)}
                      className={`w-10 h-5 flex items-center rounded-full p-0.5 transition ${settings.aiDetection ? 'bg-[#00E5FF]' : 'bg-slate-700'}`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full transition ${settings.aiDetection ? 'translate-x-5' : ''}`} />
                    </button>
                  </div>
                </div>
                <button 
                  onClick={() => {
                    setOnboardingStep(3);
                    let progress = 0;
                    const interval = setInterval(() => {
                      progress += 5;
                      setOnboardingScanProgress(progress);
                      if (progress >= 100) {
                        clearInterval(interval);
                        setTimeout(() => setOnboardingStep(4), 400);
                      }
                    }, 100);
                  }}
                  className="w-full py-3 rounded-xl bg-cyan-500 hover:bg-[#00E5FF] text-[#0B1220] font-black uppercase text-xs transition"
                >
                  Start Quick Scan
                </button>
              </div>
            )}

            {/* Step 3: Initial scan progression */}
            {onboardingStep === 3 && (
              <div className="flex flex-col items-center text-center gap-5 animate-fadeIn font-mono">
                <div className="p-3 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-[#00E5FF] animate-spin">
                  <RefreshCw className="w-8 h-8" />
                </div>
                <div className="flex flex-col gap-1.5 w-full">
                  <h2 className="text-xl font-bold text-white uppercase tracking-wider">Analyzing System</h2>
                  <p className="text-xs text-slate-400">Scanning common high-risk vectors ({onboardingScanProgress}%)</p>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div className="h-full bg-[#00E5FF] transition-all duration-100" style={{ width: `${onboardingScanProgress}%` }} />
                </div>
              </div>
            )}

            {/* Step 4: Final Checklist & Start */}
            {onboardingStep === 4 && (
              <div className="flex flex-col items-center text-center gap-4 animate-fadeIn font-mono">
                <div className="p-4 rounded-full bg-green-500/10 border border-green-500/30 text-green-400">
                  <Shield className="w-12 h-12" />
                </div>
                <h2 className="text-xl font-bold text-white uppercase tracking-wider">Initialization Complete</h2>
                <div className="flex flex-col gap-2.5 text-left w-full bg-slate-900/30 p-4 rounded-xl border border-slate-850 my-2">
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-green-400 font-bold">✔</span>
                    <span className="text-slate-350">Real-Time file integrity filters active</span>
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-green-400 font-bold">✔</span>
                    <span className="text-slate-350">AI heuristics engine verified</span>
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-green-400 font-bold">✔</span>
                    <span className="text-slate-350">Auto-containment vault armed</span>
                  </div>
                </div>
                <button 
                  onClick={() => handleUpdateSetting('firstTimeUser', false)}
                  className="w-full py-3 rounded-xl bg-green-500 hover:bg-green-400 text-[#0B1220] font-black uppercase text-xs transition"
                >
                  Activate Protection
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* AUTO-UPDATER CHECK DIALOG OVERLAY */}
      {isCheckingForUpdates && (
        <div className="fixed inset-0 z-50 bg-[#070D18]/90 flex items-center justify-center p-4 backdrop-blur-sm">
          <div className="glass-panel w-full max-w-sm rounded-2xl p-6 border border-slate-800 shadow-[0_0_30px_rgba(0,229,255,0.08)] flex flex-col items-center text-center gap-4 text-slate-350 font-mono">
            <RefreshCw className="w-10 h-10 animate-spin text-[#00E5FF]" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">Definition Updates</h3>
            <p className="text-xs text-slate-400">{updaterStepText}</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
