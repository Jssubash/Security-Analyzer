import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import AdmZip from 'adm-zip';

export interface ExtractionLimits {
  maxSizeBytes: number; // default 500MB
  maxFileCount: number; // default 15,000
}

export interface ExtractionResult {
  workspaceDir: string;
  primaryMprPath?: string;
  projectPackageXmlPath?: string;
  sha256: string;
  extractedSizeBytes: number;
  fileCount: number;
  files: string[];
}

export class SafeExtractor {
  private limits: ExtractionLimits;

  constructor(limits?: Partial<ExtractionLimits>) {
    this.limits = {
      maxSizeBytes: limits?.maxSizeBytes ?? 500 * 1024 * 1024,
      maxFileCount: limits?.maxFileCount ?? 15000,
    };
  }

  public extractArchive(archivePath: string, targetWorkspaceDir: string): ExtractionResult {
    if (!fs.existsSync(archivePath)) {
      throw new Error(`Archive not found at path: ${archivePath}`);
    }

    // Compute SHA-256 of original archive
    const fileBuffer = fs.readFileSync(archivePath);
    const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    fs.mkdirSync(targetWorkspaceDir, { recursive: true });

    let zip = new AdmZip(archivePath);
    let entries = zip.getEntries();

    // Check if the archive simply wraps a .mpk file (common in Mendix project distributions)
    const mpkEntry = entries.find((e) => e.entryName.toLowerCase().endsWith('.mpk') && !e.isDirectory);
    if (mpkEntry && entries.filter((e) => !e.isDirectory).length <= 3) {
      // It's a container zip wrapping the real mpk. Extract the mpk into a buffer and unpack that!
      const mpkBuffer = mpkEntry.getData();
      zip = new AdmZip(mpkBuffer);
      entries = zip.getEntries();
    }

    let totalExtractedBytes = 0;
    let fileCount = 0;
    const extractedFiles: string[] = [];

    for (const entry of entries) {
      const entryPath = entry.entryName;

      // 1. Path traversal guard
      this.validateSafePath(entryPath);

      if (entry.isDirectory) {
        continue;
      }

      fileCount++;
      if (fileCount > this.limits.maxFileCount) {
        throw new Error(`Extraction aborted: exceeded maximum file count limit of ${this.limits.maxFileCount}`);
      }

      totalExtractedBytes += entry.header.size;
      if (totalExtractedBytes > this.limits.maxSizeBytes) {
        throw new Error(
          `Extraction aborted: decompressed size exceeded limit of ${this.limits.maxSizeBytes / (1024 * 1024)} MB`
        );
      }

      // Filter out git, temp, and deployment binaries from cluttering design workspace if desirable
      // But preserve all design-time sources (mpr, xml, javasource, javascriptsource, themesource, vendorlib)
      const targetFilePath = path.join(targetWorkspaceDir, entryPath);
      const parentDir = path.dirname(targetFilePath);
      if (!fs.existsSync(parentDir)) {
        fs.mkdirSync(parentDir, { recursive: true });
      }

      fs.writeFileSync(targetFilePath, entry.getData());
      extractedFiles.push(entryPath);
    }

    // Find primary .mpr
    let primaryMprPath: string | undefined;
    const mprFiles = extractedFiles.filter((f) => f.toLowerCase().endsWith('.mpr') && !f.includes('.mendix-cache'));
    if (mprFiles.length > 0) {
      // Pick the main project MPR (prefer one at root or with largest size)
      mprFiles.sort((a, b) => {
        const sizeA = fs.statSync(path.join(targetWorkspaceDir, a)).size;
        const sizeB = fs.statSync(path.join(targetWorkspaceDir, b)).size;
        return sizeB - sizeA;
      });
      primaryMprPath = path.join(targetWorkspaceDir, mprFiles[0]);
    }

    let projectPackageXmlPath: string | undefined;
    const packageXml = extractedFiles.find((f) => path.basename(f).toLowerCase() === 'package.xml');
    if (packageXml) {
      projectPackageXmlPath = path.join(targetWorkspaceDir, packageXml);
    }

    return {
      workspaceDir: targetWorkspaceDir,
      primaryMprPath,
      projectPackageXmlPath,
      sha256,
      extractedSizeBytes: totalExtractedBytes,
      fileCount,
      files: extractedFiles,
    };
  }

  private validateSafePath(entryPath: string): void {
    const normalized = path.normalize(entryPath).replace(/^(\.\.[\/\\])+/, '');
    if (entryPath.includes('..') || path.isAbsolute(entryPath) || /^[a-zA-Z]:/.test(entryPath)) {
      throw new Error(`Security Violation: Zip path traversal detected in entry "${entryPath}"`);
    }
  }

  public cleanup(workspaceDir: string): void {
    if (fs.existsSync(workspaceDir)) {
      fs.rmSync(workspaceDir, { recursive: true, force: true });
    }
  }
}
