/**
 * Facts that genuinely live on disk rather than in the model: Java and JavaScript action
 * sources, third-party JARs, and widget packages.
 *
 * These are the only things the old parser was right to read from the filesystem. Its
 * mistake was using the same directories to invent *model* content — treating every
 * `javasource/<module>/proxies/*.java` as an entity (72 for a project with 8) and every
 * `javascriptsource/<module>/actions/*.js` as a nanoflow (73 for a project with 15).
 * A JavaScript action file is evidence of a JavaScript action; it is not a nanoflow.
 *
 * Directory names are lowercased by Studio Pro's code generator, so they are matched back
 * to real module names case-insensitively. A directory with no matching module is reported
 * under its own name rather than being dropped, because a stale generated directory is
 * itself worth seeing.
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, join } from 'node:path';

import type {
  CustomCodeModel,
  JavaActionSummary,
  JavaScriptActionSummary,
} from '@mendix-analyzer/application-ir';

import type { ModelGraph } from '../model/model-graph.js';
import { analyzed } from './types.js';
import type { Extraction } from './types.js';

/** A Java action source big enough to be worth reading is still bounded. */
const MAX_JAVA_SOURCE_BYTES = 2 * 1024 * 1024;

export function extractCustomCode(
  projectRoot: string,
  graph: ModelGraph
): Extraction<CustomCodeModel> {
  const notes: string[] = [];
  const resolveModule = moduleNameResolver(graph);

  return analyzed(
    {
      javaActions: readJavaActions(projectRoot, resolveModule, notes),
      javaScriptActions: readJavaScriptActions(projectRoot, resolveModule),
      vendorJars: readLibraries(projectRoot),
      widgetPackages: readPackages(join(projectRoot, 'widgets'), '.mpk'),
    },
    notes
  );
}

/**
 * Map a generated source directory back to its module.
 *
 * Returns the directory name unchanged when no module matches, so the caller can tell a
 * real module's actions from leftovers of a module that has since been deleted.
 */
function moduleNameResolver(graph: ModelGraph): (dirName: string) => string {
  const byLowerName = new Map<string, string>();
  for (const info of graph.modules) byLowerName.set(info.name.toLowerCase(), info.name);
  return (dirName) => byLowerName.get(dirName.toLowerCase()) ?? dirName;
}

function readJavaActions(
  projectRoot: string,
  resolveModule: (dirName: string) => string,
  notes: string[]
): JavaActionSummary[] {
  const actions: JavaActionSummary[] = [];
  for (const dirName of subdirectories(join(projectRoot, 'javasource'))) {
    const actionsDir = join(projectRoot, 'javasource', dirName, 'actions');
    for (const file of filesWithExtension(actionsDir, '.java')) {
      const sourceFile = `javasource/${dirName}/actions/${file}`;
      const source = readTextFile(join(actionsDir, file), notes, sourceFile);
      actions.push({
        name: basename(file, '.java'),
        module: resolveModule(dirName),
        sourceFile,
        usesExternalLibraries: source ? importedPackages(source) : [],
        hasRegexXssSanitizer: source ? usesRegexXssSanitizer(source) : undefined,
      });
    }
  }
  return actions;
}

function readJavaScriptActions(
  projectRoot: string,
  resolveModule: (dirName: string) => string
): JavaScriptActionSummary[] {
  const actions: JavaScriptActionSummary[] = [];
  for (const dirName of subdirectories(join(projectRoot, 'javascriptsource'))) {
    const actionsDir = join(projectRoot, 'javascriptsource', dirName, 'actions');
    for (const file of filesWithExtension(actionsDir, '.js')) {
      actions.push({
        name: basename(file, '.js'),
        module: resolveModule(dirName),
        sourceFile: `javascriptsource/${dirName}/actions/${file}`,
      });
    }
  }
  return actions;
}

/**
 * Third-party JARs, from both directories Mendix has used for them: `userlib` is current,
 * `vendorlib` is where older projects put them. Reading only one would report a project
 * with dozens of dependencies as having none.
 */
function readLibraries(projectRoot: string): { name: string; sizeBytes: number }[] {
  return [
    ...readPackages(join(projectRoot, 'userlib'), '.jar'),
    ...readPackages(join(projectRoot, 'vendorlib'), '.jar'),
  ];
}

function readPackages(dir: string, extension: string): { name: string; sizeBytes: number }[] {
  const packages: { name: string; sizeBytes: number }[] = [];
  for (const file of filesWithExtension(dir, extension)) {
    try {
      packages.push({ name: file, sizeBytes: statSync(join(dir, file)).size });
    } catch {
      // A file that vanished between listing and stat is not worth a note.
    }
  }
  return packages;
}

/**
 * Detect hand-rolled regex XSS filtering.
 *
 * A regex is the wrong tool for stripping script from HTML, so its presence is the finding.
 * The check is deliberately narrow — a sanitiser that calls a library is not flagged.
 */
function usesRegexXssSanitizer(source: string): boolean {
  if (!/replaceAll\s*\(|replaceFirst\s*\(|Pattern\.compile/.test(source)) return false;
  return /<\s*script|javascript:|onerror\s*=|xss/i.test(source);
}

/** Non-JDK, non-Mendix imports, as a rough dependency signal for the Security category. */
function importedPackages(source: string): string[] {
  const packages = new Set<string>();
  for (const match of source.matchAll(/^\s*import\s+(?:static\s+)?([\w.]+)/gm)) {
    const imported = match[1];
    if (/^(java|javax|jakarta|com\.mendix)\./.test(imported)) continue;
    const parts = imported.split('.');
    packages.add(parts.slice(0, Math.min(3, parts.length - 1)).join('.') || imported);
  }
  return [...packages].sort();
}

function subdirectories(dir: string): string[] {
  if (!existsSync(dir)) return [];
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name);
  } catch {
    return [];
  }
}

function filesWithExtension(dir: string, extension: string): string[] {
  if (!existsSync(dir)) return [];
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isFile() && e.name.endsWith(extension))
      .map((e) => e.name);
  } catch {
    return [];
  }
}

function readTextFile(path: string, notes: string[], label: string): string | undefined {
  try {
    if (statSync(path).size > MAX_JAVA_SOURCE_BYTES) {
      notes.push(`${label} is too large to inspect, so its contents were not analysed`);
      return undefined;
    }
    return readFileSync(path, 'utf8');
  } catch {
    notes.push(`${label} could not be read`);
    return undefined;
  }
}
