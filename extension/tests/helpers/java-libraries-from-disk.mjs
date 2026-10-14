/**
 * The Java library inventory of an app on disk, mirroring `JavaLibraryScanner.cs`: the jars in
 * `userlib/` and `vendorlib/` with their pom.properties and identifying manifest attributes, the
 * `.RequiredLib` markers, and `vendorlib/vendorlib-sbom.json` reduced to coordinates and graph.
 *
 * Jars are read with a minimal zip reader (central directory + raw inflate), enough for the
 * stored and deflated entries jars use.
 */

import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { inflateRawSync } from 'node:zlib';

const MANIFEST_KEYS = [
  'Implementation-Title', 'Implementation-Version', 'Implementation-Vendor', 'Implementation-Vendor-Id',
  'Bundle-SymbolicName', 'Bundle-Version', 'Bundle-Name', 'Automatic-Module-Name',
];

export function zipEntries(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('not a zip file');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const entries = [];
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break;
    const method = buf.readUInt16LE(p + 10);
    const compressed = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    entries.push({
      name,
      size,
      read() {
        const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
        const data = buf.subarray(start, start + compressed);
        return (method === 0 ? data : inflateRawSync(data)).toString('utf8');
      },
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function properties(text) {
  const map = {};
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line[0] === '#' || line[0] === '!') continue;
    const eq = line.search(/[=:]/);
    if (eq > 0) map[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
  }
  return map;
}

function manifest(text) {
  const map = {};
  let last;
  for (const raw of text.replace(/\r\n/g, '\n').split('\n')) {
    if (raw.length === 0) break;
    if (raw[0] === ' ' && last) { map[last] += raw.slice(1); continue; }
    const colon = raw.indexOf(':');
    if (colon <= 0) continue;
    last = raw.slice(0, colon).trim();
    map[last] = raw.slice(colon + 1).trim();
  }
  return map;
}

function readJar(file, folder, fileName) {
  const buf = readFileSync(file);
  const node = { folder, fileName, sizeBytes: statSync(file).size, sha256: createHash('sha256').update(buf).digest('hex') };
  try {
    const poms = [];
    let nested = 0;
    for (const entry of zipEntries(buf)) {
      if (/^META-INF\/maven\/.+\/pom\.properties$/i.test(entry.name)) {
        const p = properties(entry.read());
        if (p.artifactId) poms.push({ groupId: p.groupId, artifactId: p.artifactId, version: p.version, path: entry.name });
      } else if (entry.name.toUpperCase() === 'META-INF/MANIFEST.MF') {
        const m = manifest(entry.read());
        node.manifest = Object.fromEntries(MANIFEST_KEYS.filter((k) => m[k] !== undefined).map((k) => [k, m[k]]));
      } else if (entry.name.toLowerCase().endsWith('.jar')) {
        nested++;
      }
    }
    node.pomProperties = poms;
    if (nested > 0) node.nestedJars = nested;
  } catch (err) {
    node.unreadable = err.message;
  }
  return node;
}

export function javaLibrariesFromDisk(projectRoot) {
  const jars = [];
  const requiredLibMarkers = [];
  for (const folder of ['userlib', 'vendorlib']) {
    const dir = join(projectRoot, folder);
    if (!existsSync(dir)) continue;
    for (const fileName of readdirSync(dir).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }))) {
      if (fileName.toLowerCase().endsWith('.jar')) jars.push(readJar(join(dir, fileName), folder, fileName));
      else if (folder === 'userlib' && fileName.toLowerCase().endsWith('.requiredlib')) {
        const stem = fileName.slice(0, -'.RequiredLib'.length);
        const split = stem.toLowerCase().lastIndexOf('.jar.');
        if (split > 0) requiredLibMarkers.push({ jarFileName: stem.slice(0, split + 4), module: stem.slice(split + 5) });
      }
    }
  }
  const result = { scanned: true, jars, requiredLibMarkers };
  const sbomFile = join(projectRoot, 'vendorlib', 'vendorlib-sbom.json');
  if (existsSync(sbomFile)) {
    const doc = JSON.parse(readFileSync(sbomFile, 'utf8'));
    result.sbom = {
      components: (doc.components ?? []).map((c) => ({
        ref: c['bom-ref'] ?? c.purl,
        group: c.group,
        name: c.name,
        version: c.version,
        sha256: (c.hashes ?? []).find((h) => h.alg === 'SHA-256')?.content,
      })),
      dependencies: (doc.dependencies ?? []).map((d) => ({ ref: d.ref, dependsOn: d.dependsOn ?? [] })),
    };
  }
  return result;
}
