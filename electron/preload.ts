import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('electronAPI', {
  // DB & Incidents
  getIncidents: () => ipcRenderer.invoke('get-incidents'),
  clearIncidents: () => ipcRenderer.invoke('clear-incidents'),
  
  // Quarantine
  getQuarantine: () => ipcRenderer.invoke('get-quarantine'),
  restoreQuarantine: (id: string) => ipcRenderer.invoke('restore-quarantine', id),
  deleteQuarantine: (id: string) => ipcRenderer.invoke('delete-quarantine', id),
  
  // Settings
  getSettings: () => ipcRenderer.invoke('get-settings'),
  updateSettings: (settings: any) => ipcRenderer.invoke('update-settings', settings),
  
  // Custom folder scans
  selectFolder: () => ipcRenderer.invoke('select-folder'),
  runSystemScan: (path: string) => ipcRenderer.invoke('run-system-scan', path),
  
  // Real-time Update Listeners
  onFileEvent: (callback: (data: any) => void) => {
    const subscription = (_event: any, data: any) => callback(data);
    ipcRenderer.on('file-event', subscription);
    return () => ipcRenderer.removeListener('file-event', subscription);
  },
  onProcessUpdate: (callback: (data: any) => void) => {
    const subscription = (_event: any, data: any) => callback(data);
    ipcRenderer.on('process-update', subscription);
    return () => ipcRenderer.removeListener('process-update', subscription);
  },
  onNetworkUpdate: (callback: (data: any) => void) => {
    const subscription = (_event: any, data: any) => callback(data);
    ipcRenderer.on('network-update', subscription);
    return () => ipcRenderer.removeListener('network-update', subscription);
  },
  onRegistryEvent: (callback: (data: any) => void) => {
    const subscription = (_event: any, data: any) => callback(data);
    ipcRenderer.on('registry-event', subscription);
    return () => ipcRenderer.removeListener('registry-event', subscription);
  },
  onUsbEvent: (callback: (data: any) => void) => {
    const subscription = (_event: any, data: any) => callback(data);
    ipcRenderer.on('usb-event', subscription);
    return () => ipcRenderer.removeListener('usb-event', subscription);
  },
  onScanStatusUpdate: (callback: (data: any) => void) => {
    const subscription = (_event: any, data: any) => callback(data);
    ipcRenderer.on('scan-status-update', subscription);
    return () => ipcRenderer.removeListener('scan-status-update', subscription);
  },
  onIncidentDetected: (callback: (data: any) => void) => {
    const subscription = (_event: any, data: any) => callback(data);
    ipcRenderer.on('incident-detected', subscription);
    return () => ipcRenderer.removeListener('incident-detected', subscription);
  },
  onTriggerQuickScan: (callback: () => void) => {
    const subscription = () => callback();
    ipcRenderer.on('trigger-quick-scan', subscription);
    return () => ipcRenderer.removeListener('trigger-quick-scan', subscription);
  }
});
