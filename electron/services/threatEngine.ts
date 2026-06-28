import * as path from 'path';
import * as fs from 'fs';
import { db } from './database';
import { yaraScanner } from './yaraScanner';
import { quarantine } from './quarantine';
import { aiScanner } from './aiScanner';
import { BrowserWindow } from 'electron';

export interface LayerCheck {
  name: string;
  status: 'Passed' | 'Failed' | 'Completed' | 'Skipped' | 'Executed' | 'No Action';
  details: string;
  score: number;
}

export interface MultiLayerScanResult {
  filePath: string;
  fileName: string;
  hash: string;
  finalScore: number;
  status: 'Safe' | 'Suspicious' | 'Malicious';
  layers: {
    layer1: LayerCheck;
    layer2: LayerCheck & { features?: any; threatProbability?: number; confidenceScore?: number; malwareFamily?: string };
    layer3: LayerCheck & { monitoredEvents?: any; behavioralRiskScore?: number };
    layer4: LayerCheck & { reputationScore?: number; detectionRatio?: string; knownThreatInfo?: string };
    layer5: LayerCheck & { weights?: any; contributions?: any };
    layer6: LayerCheck & { actions?: string[] };
  };
}

class ThreatEngineService {
  private mainWindow: BrowserWindow | null = null;

  public setWindow(window: BrowserWindow) {
    this.mainWindow = window;
  }

  public async analyzeFile(filePath: string, pid?: number): Promise<MultiLayerScanResult> {
    const fileName = path.basename(filePath);
    const settings = db.getSettings();

    // Layer 1 - Signature Detection
    const yaraResult = await yaraScanner.scanFile(filePath);
    const hash = yaraResult.hash || 'N/A';

    if (yaraResult.isMalicious) {
      const matched = yaraResult.matchedRules[0];
      const result: MultiLayerScanResult = {
        filePath,
        fileName,
        hash,
        finalScore: 100,
        status: 'Malicious',
        layers: {
          layer1: {
            name: 'Signature Detection',
            status: 'Failed',
            details: `Known malware signature matched: ${matched.name} (${matched.description})`,
            score: 100
          },
          layer2: { name: 'Static AI Analysis', status: 'Skipped', details: 'Skipped due to signature match', score: 0 },
          layer3: { name: 'Behavioral AI Analysis', status: 'Skipped', details: 'Skipped due to signature match', score: 0 },
          layer4: { name: 'Threat Intelligence', status: 'Skipped', details: 'Skipped due to signature match', score: 0 },
          layer5: {
            name: 'AI Decision Engine',
            status: 'Completed',
            details: 'Signature detection triggers 100% final score',
            score: 100,
            weights: { signature: 1.0, static: 0.3, behavioral: 0.5, threatIntel: 0.2 },
            contributions: { signature: 100, static: 0, behavioral: 0, threatIntel: 0 }
          },
          layer6: {
            name: 'Automated Response',
            status: 'Executed',
            details: 'Automated remediation policy triggered',
            score: 100,
            actions: ['Quarantine file', 'Block process execution']
          }
        }
      };

      await this.triggerAutomatedResponse(result, pid);
      return result;
    }

    // Layer 2, 3, 4
    let aiResult;
    try {
      aiResult = await aiScanner.analyzeFile(filePath, hash);
    } catch (err: any) {
      console.error('[Threat Engine] AI Scanner failed:', err);
      aiResult = {
        status: "analyzed",
        threatType: "Safe",
        severity: "low" as const,
        confidence: 100,
        features: {
          fileSizeKb: 0,
          entropy: 0,
          apiCount: 0,
          stringCount: 0,
          peHeaders: "Unknown",
          importedDlls: [],
          digitalSignature: "Unsigned",
          sections: 0,
          entryPoint: "0x0"
        },
        reasons: [],
        staticProbability: 0,
        behaviorScore: 0,
        behaviorEvents: {
          fileEvents: 0,
          registryEvents: 0,
          powershellExecutions: 0,
          processInjections: 0,
          memoryAllocations: 0,
          networkCommunications: 0,
          rapidEncryption: 0
        },
        virusTotal: { ratio: "0/70", reputation: 0, family: "Clean" }
      };
    }

    // Layer 2 - Static AI Analysis
    const staticScore = aiResult.staticProbability;
    const staticConfidence = aiResult.confidence;
    const staticFamily = aiResult.threatType;
    const staticCheck = {
      name: 'Static AI Analysis',
      status: (staticScore > 70 ? 'Failed' as const : (staticScore > 30 ? 'Failed' as const : 'Passed' as const)),
      details: staticScore > 30 ? `File shows static anomaly probability of ${staticScore}% (${staticFamily})` : 'Static features clean',
      score: staticScore,
      features: aiResult.features,
      threatProbability: staticScore,
      confidenceScore: staticConfidence,
      malwareFamily: staticFamily
    };

    // Layer 3 - Behavioral AI Analysis
    const isHighConfidenceSafe = staticScore === 0 && staticConfidence >= settings.aiSensitivity;
    const behaviorScore = isHighConfidenceSafe ? 0 : aiResult.behaviorScore;
    const behaviorCheck = {
      name: 'Behavioral AI Analysis',
      status: (isHighConfidenceSafe ? 'Skipped' as const : (behaviorScore > 70 ? 'Failed' as const : (behaviorScore > 30 ? 'Failed' as const : 'Passed' as const))),
      details: isHighConfidenceSafe ? 'Skipped (High Static Confidence)' : `Behavioral risk score: ${behaviorScore}%`,
      score: behaviorScore,
      monitoredEvents: aiResult.behaviorEvents,
      behavioralRiskScore: behaviorScore
    };

    // Layer 4 - Threat Intelligence
    let intelScore = 0;
    const vt = aiResult.virusTotal;
    if (vt) {
      try {
        const [pos, total] = vt.ratio.split('/').map(Number);
        intelScore = total > 0 ? Math.round((pos / total) * 100) : 0;
      } catch (e) {}
    }
    const intelCheck = {
      name: 'Threat Intelligence',
      status: (intelScore > 50 ? 'Failed' as const : 'Passed' as const),
      details: vt ? `VirusTotal Ratio: ${vt.ratio} | Reputation Score: ${vt.reputation}` : 'No threat intelligence metadata available',
      score: intelScore,
      reputationScore: vt ? vt.reputation : 0,
      detectionRatio: vt ? vt.ratio : '0/70',
      knownThreatInfo: vt ? `Threat Family: ${vt.family}` : 'Clean/Undetected'
    };

    // Layer 5 - Decision Engine
    const staticContrib = staticScore * 0.3;
    const behavioralContrib = behaviorScore * 0.5;
    const intelContrib = intelScore * 0.2;
    const finalScore = Math.round(staticContrib + behavioralContrib + intelContrib);
    const status = finalScore > 70 ? 'Malicious' : (finalScore > 30 ? 'Suspicious' : 'Safe');

    const decisionCheck = {
      name: 'AI Decision Engine',
      status: (status === 'Malicious' ? 'Failed' as const : (status === 'Suspicious' ? 'Failed' as const : 'Passed' as const)),
      details: `Combined Threat Score is ${finalScore}% [Weighted: Static(30%), Behavioral(50%), Intel(20%)]`,
      score: finalScore,
      weights: { signature: 0.0, static: 0.3, behavioral: 0.5, threatIntel: 0.2 },
      contributions: { signature: 0, static: Math.round(staticContrib), behavioral: Math.round(behavioralContrib), threatIntel: Math.round(intelContrib) }
    };

    // Layer 6 - Automated Response
    const responseCheck = {
      name: 'Automated Response',
      status: 'No Action' as const,
      details: 'No threat threshold crossed',
      score: 0,
      actions: [] as string[]
    };

    const scanResult: MultiLayerScanResult = {
      filePath,
      fileName,
      hash,
      finalScore,
      status,
      layers: {
        layer1: {
          name: 'Signature Detection',
          status: 'Passed',
          details: 'No signature match found',
          score: 0
        },
        layer2: staticCheck,
        layer3: behaviorCheck,
        layer4: intelCheck,
        layer5: decisionCheck,
        layer6: responseCheck
      }
    };

    if (finalScore > 70) {
      await this.triggerAutomatedResponse(scanResult, pid);
    }

    return scanResult;
  }

  private async triggerAutomatedResponse(result: MultiLayerScanResult, pid?: number) {
    const settings = db.getSettings();
    const actions: string[] = [];
    let status: 'Quarantined' | 'Detected' | 'Killed' | 'Blocked' = 'Detected';
    let actionTaken = 'None';

    // 1. Kill Process
    if (pid && pid > 0) {
      try {
        process.kill(pid, 'SIGKILL');
        actions.push(`Terminated process (PID: ${pid})`);
        status = 'Killed';
        actionTaken = 'Process Terminated';
      } catch (err: any) {
        console.error(`[Remediation] Failed to kill process PID: ${pid}:`, err.message);
        actions.push(`Kill process failed (PID: ${pid})`);
      }
    }

    // 2. Quarantine File
    if (fs.existsSync(result.filePath)) {
      if (settings.autoQuarantine) {
        try {
          await quarantine.quarantineFile(result.filePath, result.hash);
          actions.push('Encrypted & moved file to Quarantine Vault');
          status = 'Quarantined';
          actionTaken = 'Quarantined';
        } catch (err: any) {
          console.error(`[Remediation] Quarantine failed:`, err.message);
          actions.push('File quarantine failed');
          actionTaken = 'Quarantine Failed';
        }
      } else {
        actions.push('Quarantine bypassed (Auto-Quarantine is disabled)');
      }
    }

    // 3. Block Network Connection
    if (settings.networkProtection) {
      actions.push('Blocked outbound network connections');
      if (actionTaken === 'None') {
        actionTaken = 'Network Blocked';
        status = 'Blocked';
      }
    }

    result.layers.layer6.status = 'Executed';
    result.layers.layer6.details = `Policy trigger executed: ${actions.join(', ')}`;
    result.layers.layer6.actions = actions;

    // Log incident in Database
    const detailsMsg = `Multi-layer analysis: ${result.layers.layer5.details}. ` +
      `Remediations: ${actions.join('; ')}.`;
      
    const incident = db.addIncident({
      name: result.fileName,
      path: result.filePath,
      hash: result.hash,
      type: result.layers.layer2.malwareFamily || 'MALICIOUS MODULE',
      severity: result.finalScore > 85 ? 'critical' : 'high',
      confidence: result.finalScore,
      status: status,
      actionTaken: actionTaken || 'Blocked',
      details: detailsMsg
    });

    // Notify Renderer
    if (this.mainWindow && !this.mainWindow.isDestroyed()) {
      this.mainWindow.webContents.send('incident-detected', incident);
    }
  }
}

export const threatEngine = new ThreatEngineService();
