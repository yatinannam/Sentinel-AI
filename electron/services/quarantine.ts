import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';
import { db, QuarantinedFile } from './database';

const XOR_KEY = 0x5A; // XOR key used to encrypt the quarantined file and render it inert

class QuarantineService {
  private quarantineDir: string;

  constructor() {
    const userDataPath = app ? app.getPath('userData') : './';
    this.quarantineDir = path.join(userDataPath, 'Quarantine');
    this.init();
  }

  private init() {
    if (!fs.existsSync(this.quarantineDir)) {
      fs.mkdirSync(this.quarantineDir, { recursive: true });
    }
  }

  /**
   * Encrypts a file using XOR and saves it in the quarantine directory.
   */
  private xorEncryptDecrypt(srcPath: string, destPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const readStream = fs.createReadStream(srcPath);
      const writeStream = fs.createWriteStream(destPath);

      readStream.on('data', (chunk: any) => {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const encrypted = Buffer.alloc(buf.length);
        for (let i = 0; i < buf.length; i++) {
          encrypted[i] = buf[i] ^ XOR_KEY;
        }
        writeStream.write(encrypted);
      });

      readStream.on('end', () => {
        writeStream.end();
        resolve();
      });

      readStream.on('error', (err) => reject(err));
      writeStream.on('error', (err) => reject(err));
    });
  }

  /**
   * Quarantines a file.
   */
  public async quarantineFile(filePath: string, hash: string): Promise<QuarantinedFile> {
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    const stats = fs.statSync(filePath);
    const fileName = path.basename(filePath);
    const fileId = `q_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`;
    const quarantineFileName = `${fileId}.quarantine`;
    const quarantinePath = path.join(this.quarantineDir, quarantineFileName);

    // Securely encrypt and move the file
    await this.xorEncryptDecrypt(filePath, quarantinePath);

    // Delete the original file
    fs.unlinkSync(filePath);

    const quarantinedEntry: QuarantinedFile = {
      id: fileId,
      originalPath: filePath,
      quarantinePath: quarantinePath,
      hash: hash,
      size: stats.size,
      date: new Date().toISOString()
    };

    db.addQuarantine(quarantinedEntry);
    return quarantinedEntry;
  }

  /**
   * Restores a file from quarantine to its original location.
   */
  public async restoreFile(fileId: string): Promise<string> {
    const list = db.getQuarantine();
    const entry = list.find(f => f.id === fileId);

    if (!entry) {
      throw new Error(`Quarantined file details not found for ID: ${fileId}`);
    }

    if (!fs.existsSync(entry.quarantinePath)) {
      db.removeQuarantine(fileId);
      throw new Error(`Quarantined backup file does not exist on disk.`);
    }

    const destDir = path.dirname(entry.originalPath);
    if (!fs.existsSync(destDir)) {
      fs.mkdirSync(destDir, { recursive: true });
    }

    // Decrypt and move it back
    await this.xorEncryptDecrypt(entry.quarantinePath, entry.originalPath);

    // Delete quarantine file
    fs.unlinkSync(entry.quarantinePath);

    // Remove from DB
    db.removeQuarantine(fileId);

    return entry.originalPath;
  }

  /**
   * Permanently deletes a quarantined file from disk.
   */
  public deleteFile(fileId: string): boolean {
    const list = db.getQuarantine();
    const entry = list.find(f => f.id === fileId);

    if (!entry) {
      return false;
    }

    if (fs.existsSync(entry.quarantinePath)) {
      fs.unlinkSync(entry.quarantinePath);
    }

    db.removeQuarantine(fileId);
    return true;
  }
}

export const quarantine = new QuarantineService();
