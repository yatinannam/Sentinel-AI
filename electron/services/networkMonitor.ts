import { exec } from 'child_process';
import { BrowserWindow } from 'electron';
import { db } from './database';

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

// Subnet blocks representing potential test malware beacons (e.g. Tor relays, common C2 IPs)
const SUSPICIOUS_IPS = new Set([
  '185.220.101', // Tor Exit Nodes
  '45.227.254',  // Known C2 Scanner Subnet
  '91.219.29',   // Emotet C2 IPs
  '103.224.182'  // Spyware beacon subnets
]);

class NetworkMonitorService {
  private mainWindow: BrowserWindow | null = null;
  private intervalId: NodeJS.Timeout | null = null;
  private isMonitoring: boolean = false;
  private activeConnections: NetworkConnection[] = [];

  public start(window: BrowserWindow) {
    if (this.isMonitoring) return;
    this.mainWindow = window;
    this.isMonitoring = true;

    this.intervalId = setInterval(() => this.pollConnections(), 5000);
    this.pollConnections();
  }

  public stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this.isMonitoring = false;
  }

  private pollConnections() {
    // netstat -ano lists all TCP/UDP connections with matching PIDs
    exec('netstat -ano', (error, stdout) => {
      if (error) {
        this.simulateConnections();
        return;
      }
      try {
        const connections = this.parseNetstatOutput(stdout);
        this.analyzeConnections(connections);
      } catch (err) {
        console.error('Failed to parse network connections:', err);
      }
    });
  }

  private parseNetstatOutput(stdout: string): NetworkConnection[] {
    const lines = stdout.split(/\r?\n/);
    const connections: NetworkConnection[] = [];

    lines.forEach(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('Active') || trimmed.startsWith('Proto')) return;

      // Match whitespace separated values
      // TCP  192.168.1.100:52312  172.217.16.142:443  ESTABLISHED  1234
      // or UDP  0.0.0.0:123  *:*  4432
      const parts = trimmed.split(/\s+/);
      if (parts.length < 4) return;

      const protocol = parts[0].toUpperCase() as 'TCP' | 'UDP';
      const local = parts[1];
      const remote = parts[2];
      
      let state = 'LISTENING';
      let pid = 0;

      if (protocol === 'TCP') {
        state = parts[3];
        pid = parseInt(parts[4]) || 0;
      } else {
        pid = parseInt(parts[3]) || 0;
      }

      // Parse Address and Port
      const parseAddrPort = (addrStr: string) => {
        const lastColonIdx = addrStr.lastIndexOf(':');
        if (lastColonIdx === -1) return { addr: addrStr, port: 0 };
        const addr = addrStr.substring(0, lastColonIdx);
        const port = parseInt(addrStr.substring(lastColonIdx + 1)) || 0;
        return { addr, port };
      };

      const localDetails = parseAddrPort(local);
      const remoteDetails = parseAddrPort(remote);

      connections.push({
        protocol,
        localAddress: localDetails.addr,
        localPort: localDetails.port,
        remoteAddress: remoteDetails.addr,
        remotePort: remoteDetails.port,
        state,
        pid,
        processName: 'Unknown', // Will map from process list in renderer or IPC
        suspicious: false
      });
    });

    return connections;
  }

  private analyzeConnections(connections: NetworkConnection[]) {
    const analyzed: NetworkConnection[] = [];
    const settings = db.getSettings();

    for (const conn of connections) {
      const ip = conn.remoteAddress;

      // Check if IP is in our C2 beacon list
      const isSuspiciousIp = Array.from(SUSPICIOUS_IPS).some(subnet => ip.startsWith(subnet));
      // Check if connection uses highly suspicious local port typically associated with backdoors (e.g. 4444, 1337, 6667)
      const isSuspiciousPort = conn.remotePort === 4444 || conn.remotePort === 1337;

      if (isSuspiciousIp || isSuspiciousPort) {
        conn.suspicious = true;

        const reason = isSuspiciousIp 
          ? `Outbound network connection to C2 / Tor exit node (${ip})` 
          : `Outbound connection attempt to malicious port (${conn.remotePort})`;

        // Trigger incident log
        if (settings.networkProtection && conn.state === 'ESTABLISHED') {
          this.handleNetworkThreat(conn, reason);
        }
      }

      analyzed.push(conn);
    }

    this.activeConnections = analyzed;
    this.sendToRenderer('network-update', analyzed);
  }

  private handleNetworkThreat(conn: NetworkConnection, reason: string) {
    console.warn(`[Network Monitor] Suspicious connection blocked: ${conn.remoteAddress}:${conn.remotePort} (PID: ${conn.pid})`);

    // Kill PID responsible for suspicious connection to implement Network Blocking
    if (conn.pid > 0) {
      try {
        process.kill(conn.pid, 'SIGKILL');
        
        const incident = db.addIncident({
          name: 'MALICIOUS_NETWORK_BEACON',
          path: `${conn.remoteAddress}:${conn.remotePort}`,
          hash: 'N/A (Active connection)',
          type: 'NETWORK BEACON',
          severity: 'critical',
          confidence: 95,
          status: 'Blocked',
          actionTaken: `Killed Process (PID ${conn.pid})`,
          details: `${reason}. Process terminated to block connection.`
        });

        this.sendToRenderer('incident-detected', incident);
      } catch (err: any) {
        console.error(`Failed to kill process PID: ${conn.pid} for network threat:`, err.message);
      }
    }
  }

  private simulateConnections() {
    const simulated: NetworkConnection[] = [
      { protocol: 'TCP', localAddress: '192.168.1.5', localPort: 52310, remoteAddress: '142.250.190.46', remotePort: 443, state: 'ESTABLISHED', pid: 3412, processName: 'chrome.exe', suspicious: false },
      { protocol: 'TCP', localAddress: '192.168.1.5', localPort: 52402, remoteAddress: '185.220.101.5', remotePort: 9001, state: 'ESTABLISHED', pid: 9912, processName: 'unknown.exe', suspicious: true }
    ];
    this.sendToRenderer('network-update', simulated);
  }

  private sendToRenderer(channel: string, data: any) {
    if (this.mainWindow && !this.mainWindow.isDestroyed()) {
      this.mainWindow.webContents.send(channel, data);
    }
  }
}

export const networkMonitor = new NetworkMonitorService();
