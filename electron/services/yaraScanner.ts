import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

interface YaraRule {
  name: string;
  description: string;
  category: 'trojan' | 'ransomware' | 'hacktool' | 'persistence';
  severity: 'medium' | 'high' | 'critical';
  strings: string[]; // Strings or hex patterns to look for
}

// Built-in basic EDR signature rules for common Windows attacks
const YARA_RULES: YaraRule[] = [
  {
    name: "Suspicious_PowerShell_Execution",
    description: "Detects hidden PowerShell bypass or download cradles",
    category: "hacktool",
    severity: "high",
    strings: [
      "powershell.exe",
      "-executionpolicy bypass",
      "-ep bypass",
      "-windowstyle hidden",
      "-w hidden",
      "downloadstring",
      "invoke-expression",
      "iex("
    ]
  },
  {
    name: "Process_Injection_API",
    description: "Detects Windows APIs commonly abused for DLL/process injection",
    category: "trojan",
    severity: "critical",
    strings: [
      "VirtualAllocEx",
      "WriteProcessMemory",
      "CreateRemoteThread",
      "QueueUserAPC",
      "NtCreateThreadEx"
    ]
  },
  {
    name: "Ransomware_File_Encryption",
    description: "Detects encryption behavior patterns or volume shadow deletion",
    category: "ransomware",
    severity: "critical",
    strings: [
      "vssadmin.exe delete shadows",
      "wmic shadowcopy delete",
      ".locked",
      ".crypto",
      "DecryptAllYourFiles"
    ]
  },
  {
    name: "Registry_Persistence_Mechanism",
    description: "Detects registry modification targeting startup run keys",
    category: "persistence",
    severity: "medium",
    strings: [
      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "SYSTEM\\CurrentControlSet\\Services"
    ]
  }
];

export interface YaraScanResult {
  isMalicious: boolean;
  matchedRules: Array<{
    name: string;
    description: string;
    category: string;
    severity: 'medium' | 'high' | 'critical';
  }>;
  hash: string;
}

class YaraScannerService {
  /**
   * Scans a file on disk against built-in signature rules.
   */
  public async scanFile(filePath: string): Promise<YaraScanResult> {
    const result: YaraScanResult = {
      isMalicious: false,
      matchedRules: [],
      hash: ''
    };

    try {
      if (!fs.existsSync(filePath)) {
        return result;
      }

      // 1. Calculate file hash (SHA-256)
      const fileBuffer = fs.readFileSync(filePath);
      const hashSum = crypto.createHash('sha256');
      hashSum.update(fileBuffer);
      result.hash = hashSum.digest('hex');

      // Check file size (only scan small to medium files in memory to avoid locking UI)
      const stats = fs.statSync(filePath);
      if (stats.size > 20 * 1024 * 1024) {
        // Skip files larger than 20MB for signature scan in memory
        return result;
      }

      const contentString = fileBuffer.toString('utf8');
      const contentLower = contentString.toLowerCase();

      // 2. Perform signature matching
      for (const rule of YARA_RULES) {
        let matchCount = 0;
        
        for (const str of rule.strings) {
          if (contentLower.includes(str.toLowerCase())) {
            matchCount++;
          }
        }

        // Rule triggers if a significant threshold of its strings are matched
        // For process injection or shadow copy deletion, single matches are enough.
        const threshold = rule.category === 'persistence' || rule.category === 'hacktool' ? 2 : 1;
        if (matchCount >= threshold) {
          result.isMalicious = true;
          result.matchedRules.push({
            name: rule.name,
            description: rule.description,
            category: rule.category,
            severity: rule.severity
          });
        }
      }
    } catch (error) {
      console.error(`YARA scanning error for file ${filePath}:`, error);
    }

    return result;
  }
}

export const yaraScanner = new YaraScannerService();
