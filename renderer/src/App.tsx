import React, { useEffect, useState, useRef } from 'react';
import { 
  Shield, Cpu, Network, History, FileText, Settings as SettingsIcon, 
  Trash2, RotateCcw, AlertTriangle, Search, RefreshCw, 
  Terminal, HardDrive, Play, FolderOpen, Eye, EyeOff, Upload,
  Layers, Lock, Laptop, Pause
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

interface Settings {
  aiSensitivity: number;
  realTimeProtection: boolean;
  networkProtection: boolean;
  autoQuarantine: boolean;
  notifications: boolean;
  startWithWindows: boolean;
  virusTotalApiKey: string;
}

interface ProcessTelemetry {
  pid: number;
  parentPid: number;
  name: string;
  commandLine: string;
  memoryUsage: number;
  cpuUsage: number;
  suspicious: boolean;
  reasons: string[];
}

interface NetworkConnection {
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

interface RegistryEvent {
  action: 'Added (Startup)' | 'Modified' | 'Deleted';
  key: string;
  name: string;
  value: string;
  time: string;
  status: string;
}

interface FileEvent {
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
  const [activeTab, setActiveTab] = useState<'dashboard' | 'live' | 'threats' | 'quarantine' | 'scanner' | 'settings'>('dashboard');
  const [liveSubTab, setLiveSubTab] = useState<'processes' | 'network' | 'files' | 'registry' | 'usb'>('processes');

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
    virusTotalApiKey: ''
  });

  // Live Streams
  const [processes, setProcesses] = useState<ProcessTelemetry[]>([]);
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [fileEvents, setFileEvents] = useState<FileEvent[]>([]);
  const [registryEvents, setRegistryEvents] = useState<RegistryEvent[]>([]);
  const [usbEvents, setUsbEvents] = useState<UsbEvent[]>([]);

  // Search Filters
  const [searchQuery, setSearchQuery] = useState('');

  // Scanning State
  const [scanType, setScanType] = useState<string>('Quick Scan');
  const [scanStatus, setScanStatus] = useState<string>('System Idle');
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [isScanPaused, setIsScanPaused] = useState<boolean>(false);
  const [selectedScanPath, setSelectedScanPath] = useState<string>('C:\\');
  const [isDragOver, setIsDragOver] = useState(false);

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
      const cleanFile = electronAPI.onFileEvent((event: FileEvent) => {
        setFileEvents(prev => [event, ...prev].slice(0, 100)); // Limit to 100 entries
      });

      const cleanProcess = electronAPI.onProcessUpdate((procList: ProcessTelemetry[]) => {
        setProcesses(procList);
      });

      const cleanNetwork = electronAPI.onNetworkUpdate((connList: NetworkConnection[]) => {
        // Map process names from PID list
        const updated = connList.map((conn: NetworkConnection) => {
          const match = processes.find(p => p.pid === conn.pid);
          return {
            ...conn,
            processName: match ? match.name : 'Unknown'
          };
        });
        setConnections(updated);
      });

      const cleanRegistry = electronAPI.onRegistryEvent((events: RegistryEvent[]) => {
        setRegistryEvents(prev => [...events, ...prev].slice(0, 100));
      });

      const cleanUsb = electronAPI.onUsbEvent((event: UsbEvent) => {
        setUsbEvents(prev => [event, ...prev].slice(0, 50));
      });

      const cleanScan = electronAPI.onScanStatusUpdate((update: { status: string; progress: number }) => {
        setScanStatus(update.status);
        setScanProgress(update.progress);
        
        if (update.status === 'Scan Paused') {
          setIsScanPaused(true);
        } else if (update.progress === 100 || update.status.includes('finished') || update.status.includes('Idle')) {
          setIsScanPaused(false);
          if (update.progress === 100 || update.status.includes('finished')) {
            setTimeout(() => {
              setScanStatus(prev => (prev.includes('finished') || prev.includes('Scan finished') ? 'System Idle' : prev));
            }, 15000);
          }
        }
        
        // Refresh databases if threat list updated
        electronAPI.getIncidents().then((data: Incident[]) => setIncidents(data));
        electronAPI.getQuarantine().then((data: QuarantinedFile[]) => setQuarantineList(data));
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

      // Quick scan tray menu trigger listener
      const cleanTrayScan = electronAPI.onTriggerQuickScan(() => {
        handleQuickScan();
      });

      return () => {
        cleanFile();
        cleanProcess();
        cleanNetwork();
        cleanRegistry();
        cleanUsb();
        cleanScan();
        cleanIncident();
        cleanTrayScan();
      };
    }
  }, [processes, settings.notifications]);

  // Load system specs on mount
  useEffect(() => {
    if (electronAPI && electronAPI.getSystemSpecs) {
      electronAPI.getSystemSpecs().then((specs: any) => {
        if (specs) {
          setSystemSpecs(specs);
        }
      }).catch((err: any) => {
        console.error('Failed to load system specs:', err);
      });
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

  const handleQuickScan = () => {
    setScanType('Quick Scan');
    setIsScanPaused(false);
    if (electronAPI) {
      electronAPI.runSystemScan(selectedScanPath);
    }
  };

  const handleDeepScan = () => {
    setScanType('Deep Scan');
    setIsScanPaused(false);
    if (electronAPI) {
      // Scan root path
      electronAPI.runSystemScan('C:\\');
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
    setScanType('Custom Directory Scan');
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
        // Refresh lists
        electronAPI.getQuarantine().then((data: QuarantinedFile[]) => setQuarantineList(data));
        electronAPI.getIncidents().then((data: Incident[]) => setIncidents(data));
      } else {
        alert(`Failed to restore file: ${result.error}`);
      }
    }
  };

  const handleDeleteQuarantine = async (id: string) => {
    if (electronAPI) {
      const success = await electronAPI.deleteQuarantine(id);
      if (success) {
        // Refresh lists
        electronAPI.getQuarantine().then((data: QuarantinedFile[]) => setQuarantineList(data));
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
      
      // If start with windows toggled
      if (key === 'startWithWindows') {
        await electronAPI.toggleAutoStart(value);
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

        // Run analysis using file path
        if (electronAPI) {
          setScanProgress(70);
          // Query scan directory or trigger scan directly
          // We'll run scan on this specific file
          await electronAPI.runSystemScan(filePath);
          setScanProgress(100);
          setScanStatus('System Idle');
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
            onClick={() => setActiveTab('live')}
            className={`flex items-center gap-3.5 px-4 py-3 rounded-xl text-sm font-medium transition ${
              activeTab === 'live' 
                ? 'bg-cyan-500/10 text-white border border-[#00E5FF]/30 shadow-[0_0_15px_rgba(0,229,255,0.1)]' 
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
            }`}
          >
            <Cpu className="w-4 h-4" />
            Live Monitoring
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
          <p className="text-[10px] text-slate-500 font-mono">Telemetry Streams: Active</p>
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
          {activeTab === 'dashboard' && (
            <div className="flex flex-col gap-6 animate-fadeIn">
              
              {/* TOP STATS CARDS */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-5">
                <div className="glass-panel rounded-2xl p-5 flex flex-col gap-3 relative overflow-hidden">
                  <div className="absolute top-0 right-0 p-3 opacity-10">
                    <Shield className="w-16 h-16 text-[#00E5FF]" />
                  </div>
                  <span className="text-xs font-semibold tracking-wider text-slate-400">AGENT STATUS</span>
                  <span className="text-2xl font-bold text-white flex items-center gap-2">
                    {settings.realTimeProtection ? 'ACTIVE' : 'WARNING'}
                  </span>
                  <span className="text-[10px] font-mono text-cyan-400">Real-time protection running</span>
                </div>

                <div className="glass-panel rounded-2xl p-5 flex flex-col gap-3 relative overflow-hidden">
                  <div className="absolute top-0 right-0 p-3 opacity-10">
                    <Cpu className="w-16 h-16 text-emerald-400" />
                  </div>
                  <span className="text-xs font-semibold tracking-wider text-slate-400">ACTIVE PROCESSES</span>
                  <span className="text-2xl font-bold text-white font-mono">{processes.length || 0}</span>
                  <span className="text-[10px] font-mono text-emerald-400">Polling WMI telemetries</span>
                </div>

                <div className="glass-panel rounded-2xl p-5 flex flex-col gap-3 relative overflow-hidden">
                  <div className="absolute top-0 right-0 p-3 opacity-10">
                    <Network className="w-16 h-16 text-purple-400" />
                  </div>
                  <span className="text-xs font-semibold tracking-wider text-slate-400">ESTABLISHED CONNS</span>
                  <span className="text-2xl font-bold text-white font-mono">
                    {connections.filter(c => c.state === 'ESTABLISHED').length || 0}
                  </span>
                  <span className="text-[10px] font-mono text-purple-400">Netstat connections monitored</span>
                </div>

                <div className="glass-panel rounded-2xl p-5 flex flex-col gap-3 relative overflow-hidden">
                  <div className="absolute top-0 right-0 p-3 opacity-10">
                    <AlertTriangle className="w-16 h-16 text-red-400" />
                  </div>
                  <span className="text-xs font-semibold tracking-wider text-slate-400">THREATS INTERCEPTED</span>
                  <span className="text-2xl font-bold text-red-500 font-mono">{totalBlockedCount}</span>
                  <span className="text-[10px] font-mono text-red-400">{activeThreatsCount} items unresolved</span>
                </div>
              </div>

              {/* CHARTS & GRAPHICS ROW */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                
                {/* CYBER HEALTH / AI ENGINE DIAL */}
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4">
                  <h3 className="text-sm font-semibold tracking-wider text-slate-300">AI DETECTOR INTENSITY</h3>
                  <div className="flex flex-col items-center justify-center flex-1 py-4">
                    <div className="relative w-36 h-36 flex items-center justify-center">
                      {/* SVG Progress Ring */}
                      <svg className="w-full h-full transform -rotate-90">
                        <circle cx="72" cy="72" r="60" stroke="rgba(255,255,255,0.05)" strokeWidth="10" fill="transparent" />
                        <circle cx="72" cy="72" r="60" stroke="#00E5FF" strokeWidth="10" fill="transparent"
                          strokeDasharray={2 * Math.PI * 60}
                          strokeDashoffset={2 * Math.PI * 60 * (1 - settings.aiSensitivity / 100)}
                          strokeLinecap="round"
                          className="transition-all duration-1000"
                        />
                      </svg>
                      <div className="absolute flex flex-col items-center justify-center">
                        <span className="text-4xl font-bold font-mono text-white">{settings.aiSensitivity}%</span>
                        <span className="text-[9px] font-mono text-slate-500">SENSITIVITY</span>
                      </div>
                    </div>
                    <p className="text-xs text-slate-400 text-center mt-3">
                      Higher sensitivity enables aggressive heuristics to block zero-day unpackers.
                    </p>
                  </div>
                </div>

                {/* AI CLASSIFICATION CHART */}
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4">
                  <h3 className="text-sm font-semibold tracking-wider text-slate-300">THREAT CLASSES DETECTED</h3>
                  <div className="flex flex-col gap-3 justify-center flex-1">
                    {/* Simulated threat statistics based on logged incidents */}
                    {[
                      { label: 'Trojans / Backdoors', count: incidents.filter(i => i.type === 'TROJAN').length, color: 'bg-red-500' },
                      { label: 'Ransomware / Lockers', count: incidents.filter(i => i.type === 'RANSOMWARE').length, color: 'bg-orange-500' },
                      { label: 'Spyware / InfoStealers', count: incidents.filter(i => i.type === 'SPYWARE').length, color: 'bg-yellow-500' },
                      { label: 'Cryptominers', count: incidents.filter(i => i.type === 'CRYPTOMINER').length, color: 'bg-purple-500' },
                      { label: 'Suspicious Processes', count: incidents.filter(i => i.type.includes('PROCESS')).length, color: 'bg-cyan-500' }
                    ].map((item, idx) => {
                      const total = incidents.length || 1;
                      const pct = Math.round((item.count / total) * 100) || 0;
                      return (
                        <div key={idx} className="flex flex-col gap-1 text-xs">
                          <div className="flex justify-between font-mono">
                            <span className="text-slate-400">{item.label}</span>
                            <span className="text-white font-bold">{item.count} ({pct}%)</span>
                          </div>
                          <div className="w-full h-2 bg-slate-800/80 rounded-full overflow-hidden">
                            <div className={`h-full ${item.color} rounded-full`} style={{ width: `${pct || 2}%` }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* LIVE TELEMETRY TICKER */}
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4 lg:col-span-1">
                  <div className="flex justify-between items-center">
                    <h3 className="text-sm font-semibold tracking-wider text-slate-300">LIVE SYSTEM LOGS</h3>
                    <Terminal className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="flex-1 bg-black/40 border border-slate-900 rounded-xl p-4 font-mono text-[10px] overflow-y-auto max-h-[180px] flex flex-col gap-1.5">
                    {fileEvents.length === 0 && (
                      <span className="text-slate-500 italic">Waiting for file system modifications...</span>
                    )}
                    {fileEvents.map((evt, idx) => (
                      <div key={idx} className="flex flex-wrap gap-1 leading-relaxed border-b border-slate-900/50 pb-1">
                        <span className="text-slate-500">[{evt.time}]</span>
                        <span className="text-cyan-400 font-bold">{evt.action}:</span>
                        <span className="text-slate-300 break-all select-all flex-1">{evt.path.split('\\').pop()}</span>
                        <span className={`font-semibold ${evt.status === 'Safe' ? 'text-green-400' : 'text-red-400 animate-pulse'}`}>
                          ({evt.status})
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

              </div>

              {/* RECENT INCIDENTS PANEL */}
              <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4">
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
          )}

          {/* VIEW: LIVE MONITORING */}
          {activeTab === 'live' && (
            <div className="flex flex-col gap-6 animate-fadeIn">
              <div className="flex flex-col gap-2">
                <h2 className="text-xl font-bold text-white">Live Endpoint Telemetry Monitor</h2>
                <p className="text-xs text-slate-400">Real-time telemetry queries monitoring processes, active network connections, and system persistency</p>
              </div>

              {/* TABS MENU */}
              <div className="flex border-b border-slate-800">
                {[
                  { id: 'processes', label: 'Active Processes', icon: Cpu, count: processes.length },
                  { id: 'network', label: 'Active Connections', icon: Network, count: connections.length },
                  { id: 'files', label: 'File Modifications', icon: FileText, count: fileEvents.length },
                  { id: 'registry', label: 'Registry Run entries', icon: HardDrive, count: registryEvents.length },
                  { id: 'usb', label: 'Removable USB', icon: HardDrive, count: usbEvents.length }
                ].map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setLiveSubTab(tab.id as any)}
                    className={`flex items-center gap-2 px-6 py-3 border-b-2 font-medium text-xs transition ${
                      liveSubTab === tab.id 
                        ? 'border-[#00E5FF] text-[#00E5FF] bg-cyan-500/5' 
                        : 'border-transparent text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <tab.icon className="w-4 h-4" />
                    {tab.label}
                    <span className="px-1.5 py-0.5 rounded-full bg-slate-800 text-[10px] text-slate-400 font-mono">
                      {tab.count}
                    </span>
                  </button>
                ))}
              </div>

              {/* SEARCH FILTER */}
              <div className="flex items-center gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
                <Search className="w-4 h-4 text-slate-400" />
                <input
                  type="text"
                  placeholder="Filter active telemetries by name, PID, path, or IP address..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-transparent border-none outline-none text-xs text-slate-200 w-full placeholder-slate-500"
                />
              </div>

              {/* LIVE VIEW: PROCESSES */}
              {liveSubTab === 'processes' && (
                <div className="glass-panel rounded-2xl overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                          <th className="py-3 px-4">PID</th>
                          <th className="py-3 px-4">PPID</th>
                          <th className="py-3 px-4">Name</th>
                          <th className="py-3 px-4">Command line arguments</th>
                          <th className="py-3 px-4">Working set (RAM)</th>
                          <th className="py-3 px-4 text-right">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {processes.length === 0 ? (
                          <tr>
                            <td colSpan={6} className="py-8 text-center text-slate-500 italic">
                              Polling process details...
                            </td>
                          </tr>
                        ) : (
                          processes
                            .filter(p => p.name.toLowerCase().includes(searchQuery.toLowerCase()) || p.pid.toString().includes(searchQuery))
                            .map((proc) => (
                              <tr key={proc.pid} className={`border-b border-slate-800/60 hover:bg-slate-900/20 transition ${
                                proc.suspicious ? 'bg-red-500/5' : ''
                              }`}>
                                <td className="py-3 px-4 font-mono text-slate-400">{proc.pid}</td>
                                <td className="py-3 px-4 font-mono text-slate-500">{proc.parentPid}</td>
                                <td className="py-3 px-4 font-bold text-white flex items-center gap-2">
                                  {proc.name}
                                  {proc.suspicious && (
                                    <span className="px-1.5 py-0.2 text-[8px] font-bold rounded bg-red-500/20 text-red-400 border border-red-500/30">
                                      SUSPICIOUS
                                    </span>
                                  )}
                                </td>
                                <td className="py-3 px-4 font-mono text-slate-400 max-w-sm truncate" title={proc.commandLine}>
                                  {proc.commandLine || <span className="text-slate-600 italic">N/A</span>}
                                </td>
                                <td className="py-3 px-4 font-mono text-slate-400">{proc.memoryUsage} MB</td>
                                <td className="py-3 px-4 text-right">
                                  {proc.suspicious ? (
                                    <span className="text-red-400 font-semibold" title={proc.reasons.join(', ')}>Terminated</span>
                                  ) : (
                                    <span className="text-green-400">Running</span>
                                  )}
                                </td>
                              </tr>
                            ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* LIVE VIEW: NETWORK CONNECTIONS */}
              {liveSubTab === 'network' && (
                <div className="glass-panel rounded-2xl overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                          <th className="py-3 px-4">Protocol</th>
                          <th className="py-3 px-4">PID</th>
                          <th className="py-3 px-4">Local socket</th>
                          <th className="py-3 px-4">Remote address</th>
                          <th className="py-3 px-4">Remote Port</th>
                          <th className="py-3 px-4">Socket State</th>
                          <th className="py-3 px-4 text-right">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {connections.length === 0 ? (
                          <tr>
                            <td colSpan={7} className="py-8 text-center text-slate-500 italic">
                              Polling network socket details...
                            </td>
                          </tr>
                        ) : (
                          connections
                            .filter(c => c.remoteAddress.includes(searchQuery) || c.pid.toString().includes(searchQuery) || c.processName.toLowerCase().includes(searchQuery.toLowerCase()))
                            .map((conn, idx) => (
                              <tr key={idx} className={`border-b border-slate-800/60 hover:bg-slate-900/20 transition ${
                                conn.suspicious ? 'bg-red-500/5' : ''
                              }`}>
                                <td className="py-3 px-4 font-mono text-[#00E5FF] font-bold">{conn.protocol}</td>
                                <td className="py-3 px-4 font-mono text-slate-400">{conn.pid}</td>
                                <td className="py-3 px-4 font-mono text-slate-400">{conn.localAddress}:{conn.localPort}</td>
                                <td className="py-3 px-4 font-bold text-white font-mono">{conn.remoteAddress}</td>
                                <td className="py-3 px-4 font-mono text-slate-300">{conn.remotePort || '*'}</td>
                                <td className="py-3 px-4 font-mono text-slate-500">{conn.state}</td>
                                <td className="py-3 px-4 text-right">
                                  {conn.suspicious ? (
                                    <span className="text-red-400 font-semibold">Blocked</span>
                                  ) : (
                                    <span className="text-green-400">Allowed</span>
                                  )}
                                </td>
                              </tr>
                            ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* LIVE VIEW: FILE MODIFICATIONS */}
              {liveSubTab === 'files' && (
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4 font-mono text-xs">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <span className="font-semibold text-slate-300">File Integrity Monitor Stream</span>
                    <span className="text-[10px] text-slate-500">Auto-refresh active</span>
                  </div>
                  <div className="flex flex-col gap-2.5 max-h-[450px] overflow-y-auto pr-2">
                    {fileEvents.length === 0 ? (
                      <span className="text-slate-500 italic">No filesystem events recorded yet. Modify files in Downloads/Desktop folders to test.</span>
                    ) : (
                      fileEvents
                        .filter(f => f.path.toLowerCase().includes(searchQuery.toLowerCase()))
                        .map((evt, idx) => (
                          <div key={idx} className="p-3.5 rounded-lg bg-slate-900/40 border border-slate-800/80 flex items-center justify-between gap-4">
                            <div className="flex flex-col gap-1 truncate">
                              <span className="text-white font-semibold truncate" title={evt.path}>{evt.path}</span>
                              <span className="text-[10px] text-slate-500">Action: {evt.action} | Recorded: {evt.time}</span>
                            </div>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              evt.status === 'Safe' ? 'text-green-400 border-green-500/20 bg-green-500/5' : 'text-red-400 border-red-500/20 bg-red-500/5 animate-pulse'
                            }`}>
                              {evt.status.toUpperCase()}
                            </span>
                          </div>
                        ))
                    )}
                  </div>
                </div>
              )}

              {/* LIVE VIEW: REGISTRY MODIFICATIONS */}
              {liveSubTab === 'registry' && (
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4 font-mono text-xs">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <span className="font-semibold text-slate-300">Registry Persistence Keys Monitor</span>
                    <span className="text-[10px] text-slate-500">Checking Run & RunOnce Registry Subtrees</span>
                  </div>
                  <div className="flex flex-col gap-2.5 max-h-[450px] overflow-y-auto pr-2">
                    {registryEvents.length === 0 ? (
                      <span className="text-slate-500 italic">No startup registry changes detected. Cache initialized and active.</span>
                    ) : (
                      registryEvents
                        .filter(r => r.name.toLowerCase().includes(searchQuery.toLowerCase()) || r.value.toLowerCase().includes(searchQuery.toLowerCase()))
                        .map((evt, idx) => (
                          <div key={idx} className="p-3.5 rounded-lg bg-slate-900/40 border border-slate-800/80 flex flex-col gap-2">
                            <div className="flex justify-between items-start">
                              <span className="text-[#00E5FF] font-semibold">{evt.action}</span>
                              <span className="text-[10px] text-slate-500">{evt.time}</span>
                            </div>
                            <div className="flex flex-col gap-1 text-[11px] text-slate-400">
                              <div>Key: <span className="text-white font-mono break-all">{evt.key}</span></div>
                              <div>Name: <span className="text-white font-mono">{evt.name}</span></div>
                              <div>Value: <span className="text-yellow-400 font-mono break-all">{evt.value}</span></div>
                            </div>
                          </div>
                        ))
                    )}
                  </div>
                </div>
              )}

              {/* LIVE VIEW: USB MONITOR */}
              {liveSubTab === 'usb' && (
                <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4 font-mono text-xs">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <span className="font-semibold text-slate-300">USB Mass Storage Volume Event Log</span>
                    <span className="text-[10px] text-slate-500">Win32_VolumeChangeEvent handler</span>
                  </div>
                  <div className="flex flex-col gap-2.5 max-h-[450px] overflow-y-auto pr-2">
                    {usbEvents.length === 0 ? (
                      <span className="text-slate-500 italic">Zero USB insertion events detected. Ready for USB insertions.</span>
                    ) : (
                      usbEvents.map((evt, idx) => (
                        <div key={idx} className="p-3.5 rounded-lg bg-slate-900/40 border border-slate-800/80 flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <HardDrive className={`w-5 h-5 ${evt.action === 'Inserted' ? 'text-green-400' : 'text-red-400'}`} />
                            <div className="flex flex-col">
                              <span className="text-white font-semibold">
                                USB Drive {evt.action} : {evt.letter} {evt.label ? `(${evt.label})` : ''}
                              </span>
                              <span className="text-[10px] text-slate-500">Recorded: {evt.time}</span>
                            </div>
                          </div>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            evt.action === 'Inserted' ? 'text-green-400 border-green-500/20 bg-green-500/5' : 'text-red-400 border-red-500/20 bg-red-500/5'
                          }`}>
                            {evt.action.toUpperCase()}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}

            </div>
          )}

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

          {/* VIEW: THREAT SCANNER */}
          {activeTab === 'scanner' && (
            <div className="flex flex-col gap-6 animate-fadeIn">
              <div className="flex flex-col gap-2">
                <h2 className="text-xl font-bold text-white">Threat Intelligence Scanning Panel</h2>
                <p className="text-xs text-slate-400">Initiate custom directory scans, fast signature sweeps, or static PE analyses on suspicious modules</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                
                {/* SCAN MODES CARDS */}
                <div className="glass-panel rounded-2xl p-5 flex flex-col justify-between gap-4">
                  <div className="flex flex-col gap-2">
                    <div className="p-2 rounded-lg bg-green-500/10 border border-green-500/20 w-fit text-green-400">
                      <Play className="w-4 h-4" />
                    </div>
                    <h3 className="text-sm font-bold text-white">Quick System Scan</h3>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Scans active user directories (Desktop, Documents, Downloads) for execution bypass vectors.
                    </p>
                  </div>
                  <button
                    onClick={handleQuickScan}
                    disabled={scanStatus.includes('Scanning')}
                    className="w-full py-2 rounded-lg bg-cyan-500 text-[#0B1220] hover:bg-[#00E5FF]/80 transition text-xs font-bold font-mono uppercase tracking-wider disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Launch scan
                  </button>
                </div>

                <div className="glass-panel rounded-2xl p-5 flex flex-col justify-between gap-4">
                  <div className="flex flex-col gap-2">
                    <div className="p-2 rounded-lg bg-[#00E5FF]/10 border border-[#00E5FF]/20 w-fit text-[#00E5FF]">
                      <Shield className="w-4 h-4" />
                    </div>
                    <h3 className="text-sm font-bold text-white">Deep Directory Sweep</h3>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Performs recursive traversal across the entire C:\ drive, including AppData.
                    </p>
                  </div>
                  <button
                    onClick={handleDeepScan}
                    disabled={scanStatus.includes('Scanning')}
                    className="w-full py-2 rounded-lg bg-cyan-500 text-[#0B1220] hover:bg-[#00E5FF]/80 transition text-xs font-bold font-mono uppercase tracking-wider disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Launch deep scan
                  </button>
                </div>

                <div className="glass-panel rounded-2xl p-5 flex flex-col justify-between gap-4">
                  <div className="flex flex-col gap-2">
                    <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20 w-fit text-purple-400">
                      <FolderOpen className="w-4 h-4" />
                    </div>
                    <h3 className="text-sm font-bold text-white">Custom Directory Scan</h3>
                    <p className="text-xs text-slate-400 leading-relaxed font-mono text-slate-500 break-all">
                      Path: {selectedScanPath}
                    </p>
                  </div>
                  <div className="flex gap-2.5">
                    <button
                      onClick={handleSelectFolder}
                      className="py-2 px-3 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-300 text-xs font-bold"
                    >
                      Browse
                    </button>
                    <button
                      onClick={handleCustomScan}
                      disabled={scanStatus.includes('Scanning')}
                      className="flex-1 py-2 rounded-lg bg-cyan-500 text-[#0B1220] hover:bg-[#00E5FF]/80 transition text-xs font-bold font-mono uppercase tracking-wider disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Scan directory
                    </button>
                  </div>
                </div>

              </div>

              {/* ACTIVE SCAN PROGRESS BAR */}
              {scanStatus !== 'System Idle' && (
                <div className={`glass-panel rounded-2xl p-6 flex flex-col gap-4 ${(scanProgress === 100 || scanStatus.includes('finished') || isScanPaused) ? '' : 'animate-pulse'}`}>
                  <div className="flex justify-between items-center text-xs font-mono">
                    <span className={`font-semibold ${
                      (scanProgress === 100 || scanStatus.includes('finished')) 
                        ? 'text-green-400 font-semibold' 
                        : isScanPaused 
                          ? 'text-amber-400 font-semibold' 
                          : 'text-[#00E5FF]'
                    }`}>
                      {scanType} {(scanProgress === 100 || scanStatus.includes('finished')) ? '(Completed)' : isScanPaused ? '(Paused)' : '(Active)'}
                    </span>
                    <div className="flex items-center gap-3">
                      {scanProgress < 100 && !scanStatus.includes('finished') ? (
                        <>
                          <button
                            onClick={handleToggleScanPause}
                            className={`px-2 py-0.5 rounded border text-[10px] font-bold font-mono transition-all duration-200 ${
                              isScanPaused
                                ? 'border-green-500/30 bg-green-500/10 text-green-400 hover:bg-green-500/20'
                                : 'border-amber-500/30 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20'
                            }`}
                          >
                            {isScanPaused ? 'RESUME SCAN' : 'PAUSE SCAN'}
                          </button>

                          <button
                            onClick={handleCancelScan}
                            className="px-2 py-0.5 rounded border border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20 text-[10px] font-bold font-mono transition-all duration-200"
                          >
                            STOP SCAN
                          </button>
                        </>
                      ) : (
                        <button
                          onClick={() => {
                            setScanStatus('System Idle');
                            setScanProgress(0);
                          }}
                          className="px-2 py-0.5 rounded border border-slate-700 hover:bg-slate-800 text-[10px] font-bold font-mono text-slate-300 transition"
                        >
                          DISMISS
                        </button>
                      )}
                      <span className="text-white font-bold">{scanProgress}%</span>
                    </div>
                  </div>
                  <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full transition-all duration-300 ${
                      (scanProgress === 100 || scanStatus.includes('finished')) 
                        ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]' 
                        : isScanPaused 
                          ? 'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]' 
                          : 'bg-[#00E5FF] glow-cyan'
                    }`} style={{ width: `${scanProgress}%` }} />
                  </div>
                  <p className={`text-[10px] font-mono truncate ${
                    (scanProgress === 100 || scanStatus.includes('finished')) 
                      ? 'text-green-400/80 font-semibold' 
                      : isScanPaused 
                        ? 'text-amber-400/80' 
                        : 'text-slate-400'
                  }`}>
                    {isScanPaused ? 'Scan execution halted. Press Resume to continue.' : scanStatus}
                  </p>
                </div>
              )}

              {/* DRAG AND DROP TARGET ZONE */}
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
                    Drag any file or folder to trigger instant YARA pattern and AI classification scans.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* VIEW: SETTINGS */}
          {activeTab === 'settings' && (
            <div className="flex flex-col gap-6 animate-fadeIn">
              <div className="flex flex-col gap-2">
                <h2 className="text-xl font-bold text-white">Agent Configurations Settings</h2>
                <p className="text-xs text-slate-400">Fine-tune the heuristics thresholds, notification behaviors, and threat intelligence API scopes</p>
              </div>

              <div className="glass-panel rounded-2xl p-6 flex flex-col gap-6 max-w-3xl">
                
                {/* 1. PROTECTION TOGGLES */}
                <div className="flex flex-col gap-4">
                  <h3 className="text-sm font-bold text-slate-200 border-b border-slate-800 pb-2">Active EDR Modules</h3>
                  
                  <div className="flex items-center justify-between p-3 bg-slate-900/30 rounded-xl border border-slate-800/80">
                    <div className="flex flex-col">
                      <span className="text-sm font-semibold text-white">Real-Time Process Blocking</span>
                      <span className="text-xs text-slate-500">Terminates processes executing suspicious command flags in real-time</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('realTimeProtection', !settings.realTimeProtection)}
                      className={`w-12 h-6 flex items-center rounded-full p-1 transition-all duration-300 ${
                        settings.realTimeProtection ? 'bg-[#00E5FF]' : 'bg-slate-700'
                      }`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full shadow-md transform transition-all duration-300 ${
                        settings.realTimeProtection ? 'translate-x-6' : ''
                      }`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between p-3 bg-slate-900/30 rounded-xl border border-slate-800/80">
                    <div className="flex flex-col">
                      <span className="text-sm font-semibold text-white">Network Protection Shield</span>
                      <span className="text-xs text-slate-500">Filters active socket connections, blocking connections to malicious servers/IPs</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('networkProtection', !settings.networkProtection)}
                      className={`w-12 h-6 flex items-center rounded-full p-1 transition-all duration-300 ${
                        settings.networkProtection ? 'bg-[#00E5FF]' : 'bg-slate-700'
                      }`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full shadow-md transform transition-all duration-300 ${
                        settings.networkProtection ? 'translate-x-6' : ''
                      }`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between p-3 bg-[#0E1726]/30 rounded-xl border border-slate-800/80">
                    <div className="flex flex-col">
                      <span className="text-sm font-semibold text-white">Auto-Quarantine Threats</span>
                      <span className="text-xs text-slate-500">Encrypts and quarantines malicious files instantly upon detection</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('autoQuarantine', !settings.autoQuarantine)}
                      className={`w-12 h-6 flex items-center rounded-full p-1 transition-all duration-300 ${
                        settings.autoQuarantine ? 'bg-[#00E5FF]' : 'bg-slate-700'
                      }`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full shadow-md transform transition-all duration-300 ${
                        settings.autoQuarantine ? 'translate-x-6' : ''
                      }`} />
                    </button>
                  </div>
                </div>

                {/* 2. AI SENSITIVITY RANGE SLIDER */}
                <div className="flex flex-col gap-4">
                  <h3 className="text-sm font-bold text-slate-200 border-b border-slate-800 pb-2">AI Behavioral Classifier Sensitivity</h3>
                  <div className="flex flex-col gap-2">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-400">Detection sensitivity</span>
                      <span className="text-[#00E5FF] font-bold">{settings.aiSensitivity}%</span>
                    </div>
                    <input
                      type="range"
                      min="10"
                      max="100"
                      value={settings.aiSensitivity}
                      onChange={(e) => handleUpdateSetting('aiSensitivity', parseInt(e.target.value))}
                      className="w-full accent-[#00E5FF] cursor-pointer"
                    />
                    <div className="flex justify-between text-[9px] text-slate-600 font-mono">
                      <span>LOW (10%)</span>
                      <span>BALANCED (60%)</span>
                      <span>AGGRESSIVE (100%)</span>
                    </div>
                  </div>
                </div>

                {/* 3. VIRUSTOTAL API INTEGRATION */}
                <div className="flex flex-col gap-4">
                  <h3 className="text-sm font-bold text-slate-200 border-b border-slate-800 pb-2">VirusTotal Threat Intelligence</h3>
                  <div className="flex flex-col gap-2">
                    <label className="text-xs text-slate-400">VirusTotal API Key (Verification Layer)</label>
                    <div className="flex items-center gap-3 bg-slate-900/60 p-2.5 rounded-xl border border-slate-800">
                      <input
                        type={showApiKey ? 'text' : 'password'}
                        placeholder="Enter your VirusTotal public API key..."
                        value={settings.virusTotalApiKey}
                        onChange={(e) => handleUpdateSetting('virusTotalApiKey', e.target.value)}
                        className="bg-transparent border-none outline-none text-xs text-slate-200 w-full placeholder-slate-600 font-mono"
                      />
                      <button 
                        onClick={() => setShowApiKey(!showApiKey)}
                        className="text-slate-500 hover:text-slate-300"
                      >
                        {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                </div>

                {/* 4. OS SETTINGS */}
                <div className="flex flex-col gap-4">
                  <h3 className="text-sm font-bold text-slate-200 border-b border-slate-800 pb-2">Agent System Settings</h3>
                  
                  <div className="flex items-center justify-between p-3 bg-slate-900/30 rounded-xl border border-slate-800/80">
                    <div className="flex flex-col">
                      <span className="text-sm font-semibold text-white">Launch at Startup</span>
                      <span className="text-xs text-slate-500">Auto-runs SentinelAI EDR agent in system tray upon Windows login</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('startWithWindows', !settings.startWithWindows)}
                      className={`w-12 h-6 flex items-center rounded-full p-1 transition-all duration-300 ${
                        settings.startWithWindows ? 'bg-[#00E5FF]' : 'bg-slate-700'
                      }`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full shadow-md transform transition-all duration-300 ${
                        settings.startWithWindows ? 'translate-x-6' : ''
                      }`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between p-3 bg-slate-900/30 rounded-xl border border-slate-800/80">
                    <div className="flex flex-col">
                      <span className="text-sm font-semibold text-white">Desktop Notifications</span>
                      <span className="text-xs text-slate-500">Pushes OS system tray alerts when threats are quarantined or blocked</span>
                    </div>
                    <button
                      onClick={() => handleUpdateSetting('notifications', !settings.notifications)}
                      className={`w-12 h-6 flex items-center rounded-full p-1 transition-all duration-300 ${
                        settings.notifications ? 'bg-[#00E5FF]' : 'bg-slate-700'
                      }`}
                    >
                      <div className={`bg-slate-900 w-4 h-4 rounded-full shadow-md transform transition-all duration-300 ${
                        settings.notifications ? 'translate-x-6' : ''
                      }`} />
                    </button>
                  </div>
                </div>

              </div>
            </div>
          )}

        </div>
      </main>
    </div>
  );
};

export default App;
