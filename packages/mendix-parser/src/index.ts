/**
 * Parse a Mendix project into the Application IR.
 *
 * Two entry points, because they answer different questions:
 *
 * - `parseMendixProject` takes an `.mpk`/`.zip`, unpacks it under the archive limits, and
 *   cleans up after itself. This is what the API uses.
 * - `parseExtractedProject` takes a directory that already contains the `.mpr` and
 *   `mprcontents/`. This is what the tests use, and what makes the parser testable against
 *   a real project without a fixture archive in the repository.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { ApplicationIR } from '@mendix-analyzer/application-ir';

import { buildApplicationIr } from './build-ir.js';
import { SafeExtractor, ExtractionLimits } from './extractor.js';

export * from './extractor.js';
export * from './build-ir.js';

export * from './bson/reader.js';
export * from './bson/accessors.js';
export * from './bson/unit-index.js';
export * from './mpr/containment.js';
export * from './model/model-graph.js';

export * from './extract/types.js';
export * from './extract/security.js';
export * from './extract/domain-model.js';
export * from './extract/pages.js';
export * from './extract/microflows.js';
export * from './extract/constants.js';
export * from './extract/project.js';
export * from './extract/filesystem.js';

export interface ParseOptions {
  extractionLimits?: Partial<ExtractionLimits>;
  customWorkspaceDir?: string;
  keepExtracted?: boolean;
}

/**
 * Parse an already-extracted project directory.
 *
 * @param projectRoot directory holding the `.mpr` and its `mprcontents/`
 * @param mprPath the primary `.mpr`; located inside `projectRoot` when omitted
 */
export function parseExtractedProject(projectRoot: string, mprPath?: string): ApplicationIR {
  const resolvedMpr = mprPath ?? findPrimaryMpr(projectRoot);
  if (!resolvedMpr) {
    throw new Error(
      `No .mpr file found in ${projectRoot}. The model lives in the .mpr and its ` +
        'mprcontents/ directory; without them nothing can be analysed.'
    );
  }
  return buildApplicationIr(path.dirname(resolvedMpr), resolvedMpr).ir;
}

/**
 * Main parser entry point. Takes a Mendix ZIP/MPK path, safely unpacks it, and constructs
 * the Application IR.
 */
export async function parseMendixProject(
  archivePath: string,
  options?: ParseOptions
): Promise<ApplicationIR> {
  const extractor = new SafeExtractor(options?.extractionLimits);
  const workspaceDir =
    options?.customWorkspaceDir ||
    path.join(
      os.tmpdir(),
      'mendix-analyzer',
      `ws-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`
    );

  try {
    const extraction = extractor.extractArchive(archivePath, workspaceDir);
    const mprPath = extraction.primaryMprPath ?? findPrimaryMpr(extraction.workspaceDir);
    if (!mprPath) {
      // Failing here is the honest outcome: an archive with no .mpr is not a Mendix project,
      // and returning an empty IR would be reported as a project with no security problems.
      throw new Error(
        `The archive ${path.basename(archivePath)} contains no .mpr file, so it is not a ` +
          'Mendix project export.'
      );
    }

    return buildApplicationIr(path.dirname(mprPath), mprPath, {
      sha256: extraction.sha256,
      extractedSizeBytes: extraction.extractedSizeBytes,
      fileCount: extraction.fileCount,
    }).ir;
  } finally {
    if (!options?.keepExtracted) {
      try {
        extractor.cleanup(workspaceDir);
      } catch {
        // A locked file on Windows must not turn a successful analysis into a failure.
      }
    }
  }
}

/** Locate the project `.mpr`, preferring the largest when several are present. */
function findPrimaryMpr(root: string): string | undefined {
  const candidates: string[] = [];

  const walk = (dir: string, depth: number): void => {
    if (depth > 3) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'mprcontents' || entry.name.startsWith('.')) continue;
        walk(full, depth + 1);
      } else if (entry.name.toLowerCase().endsWith('.mpr')) {
        candidates.push(full);
      }
    }
  };

  walk(root, 0);
  if (candidates.length === 0) return undefined;

  return candidates.sort((a, b) => sizeOf(b) - sizeOf(a))[0];
}

function sizeOf(file: string): number {
  try {
    return fs.statSync(file).size;
  } catch {
    return 0;
  }
}
