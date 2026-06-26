import { spawn } from 'child_process';
import * as path from 'path';
import { db } from './database';
import { quarantine } from './quarantine';
import { yaraScanner } from './yaraScanner';

export interface AiAnalysisResult {
  status: string;
  threatType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  features: {
    fileSizeKb: number;
    entropy: number;
    apiCount: number;
    stringCount: number;
  };
  reasons: string[];
  virusTotal?: {
    ratio: string;
    reputation: number;
    family: string;
  } | null;
  error?: string;
}

class AiScannerService {
  private pythonPath: string = 'python'; // Default, can be overridden in settings

  /**
   * Performs AI classification and VirusTotal verification using python backend
   */
  public analyzeFile(filePath: string, fileHash: string): Promise<AiAnalysisResult> {
    return new Promise((resolve) => {
      const settings = db.getSettings();
      const pythonScript = path.join(__dirname, '../python-ai/inference.py');

      const payload = {
        filePath: filePath,
        apiKey: settings.virusTotalApiKey || null
      };

      console.log(`[AI Scanner] Spawning Python process to analyze: ${path.basename(filePath)}`);
      
      const pyProcess = spawn(this.pythonPath, [pythonScript]);
      
      let stdoutData = '';
      let stderrData = '';

      pyProcess.stdout.on('data', (data) => {
        stdoutData += data.toString();
      });

      pyProcess.stderr.on('data', (data) => {
        stderrData += data.toString();
      });

      pyProcess.on('close', (code) => {
        if (code !== 0) {
          console.error(`Python analyzer exited with code ${code}. Stderr: ${stderrData}`);
          resolve(this.getFallbackResult(filePath, fileHash, `Python process exit code: ${code}`));
          return;
        }

        try {
          const result = JSON.parse(stdoutData.trim()) as AiAnalysisResult;
          resolve(result);
        } catch (parseErr: any) {
          console.error('Failed to parse Python response:', parseErr.message, stdoutData);
          resolve(this.getFallbackResult(filePath, fileHash, `JSON Parse Error: ${parseErr.message}`));
        }
      });

      pyProcess.on('error', (err) => {
        console.error('Failed to start Python process:', err.message);
        resolve(this.getFallbackResult(filePath, fileHash, `Spawn Error: ${err.message}`));
      });

      // Write payload to stdin and close stdin to signal EOF to python script
      pyProcess.stdin.write(JSON.stringify(payload));
      pyProcess.stdin.end();
    });
  }

  /**
   * Fallback heuristics if python execution fails
   */
  private async getFallbackResult(filePath: string, fileHash: string, errorMsg: string): Promise<AiAnalysisResult> {
    console.log(`[AI Scanner] Python offline (${errorMsg}). Running local static fallback engine.`);

    // Perform YARA check
    const yaraResult = await yaraScanner.scanFile(filePath);
    
    if (yaraResult.isMalicious) {
      const matched = yaraResult.matchedRules[0];
      return {
        status: "analyzed",
        threatType: matched.category.toUpperCase(),
        severity: matched.severity,
        confidence: 85,
        features: { fileSizeKb: 0, entropy: 0, apiCount: 1, stringCount: 1 },
        reasons: [`Local signature match: ${matched.description}`, `Python engine offline: ${errorMsg}`]
      };
    }

    return {
      status: "analyzed",
      threatType: "Safe",
      severity: "low",
      confidence: 100,
      features: { fileSizeKb: 0, entropy: 0, apiCount: 0, stringCount: 0 },
      reasons: ["Local signatures clean. Python engine offline."]
    };
  }
}

export const aiScanner = new AiScannerService();
