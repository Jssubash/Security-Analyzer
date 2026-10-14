/**
 * Builds the Studio Pro import package for the extension: an add-on module `SecurityAnalyser` that
 * carries the extension in `extensions/SecurityAnalyzer`, exported as `release/SecurityAnalyser-<version>.mxmodule`.
 *
 *   npm run package                        (builds first, then packages)
 *   node extension/scripts/package-module.mjs [--mx "<path to mx.exe>"]
 *
 * An extension reaches other apps inside an add-on module (Studio Pro: module Settings ▸ Export ▸
 * Add-on module, Extension name). This script does the same without the Studio Pro UI:
 *
 *   1. creates a throw-away Mendix 10.24 app in `.package/host` (10.24 so the package imports into
 *      10.24 and every later version);
 *   2. imports `extension/packaging/SecurityAnalyser.mpk`, an empty source module;
 *   3. copies the built extension (manifest.json, SecurityAnalyzer.dll, wwwroot) into the app;
 *   4. marks the module as an add-on carrying that extension, by editing its ModuleSettings unit
 *      (ExportLevel Protected, ProtectedModuleType AddOn, ExtensionName, Version) and its
 *      ContentsHash in the .mpr — what Studio Pro writes when the boxes are ticked. Both .mpr
 *      formats are handled: unit contents in `mprcontents/` files (v2), or in the Unit table (v1),
 *      which is how `mx module-import` saves the app;
 *   5. runs `mx check`, exports with `mx create-module-package`, and verifies the result.
 *
 * Only Studio Pro's own `mx.exe` is used. Nothing outside this repository is written.
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { inflateRawSync } from 'node:zlib';

const MODULE = 'SecurityAnalyser';
const EXTENSION = 'SecurityAnalyzer';
const MENDIX_LINE = '10.24.';

const here = dirname(fileURLToPath(import.meta.url));
const extensionDir = resolve(here, '..');
const repoRoot = resolve(extensionDir, '..');
const version = JSON.parse(readFileSync(join(extensionDir, 'package.json'), 'utf8')).version;
const built = join(extensionDir, 'dotnet', 'bin', 'Release', 'net8.0');
const template = join(extensionDir, 'packaging', `${MODULE}.mpk`);
const work = join(repoRoot, '.package', 'host');
const exportDir = join(repoRoot, '.package', 'out');
const releaseDir = join(repoRoot, 'release');

function fail(message) {
  console.error(`package-module: ${message}`);
  process.exit(1);
}

function step(text) {
  console.log(`• ${text}`);
}

// ------------------------------------------------------------------ find mx.exe

function findMx() {
  const arg = process.argv.indexOf('--mx');
  if (arg > 0 && process.argv[arg + 1]) return process.argv[arg + 1];
  if (process.env.MENDIX_MX) return process.env.MENDIX_MX;
  const base = join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Mendix');
  if (!existsSync(base)) return undefined;
  const candidates = readdirSync(base)
    .filter((d) => d.startsWith(MENDIX_LINE) && existsSync(join(base, d, 'modeler', 'mx.exe')))
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  return candidates.length > 0 ? join(base, candidates.at(-1), 'modeler', 'mx.exe') : undefined;
}

const mx = findMx();
if (!mx || !existsSync(mx)) {
  fail(`Studio Pro ${MENDIX_LINE}x was not found. Install it, or pass --mx "<path to mx.exe>" (or set MENDIX_MX).`);
}

function runMx(args) {
  try {
    return execFileSync(mx, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) {
    fail(`mx ${args[0]} failed:\n${(err.stdout ?? '') + (err.stderr ?? '')}`.trim());
  }
}

// ------------------------------------------------------------------ check the build

for (const file of ['manifest.json', `${EXTENSION}.dll`, join('wwwroot', 'index.html'), join('wwwroot', 'app.js')]) {
  if (!existsSync(join(built, file))) fail(`${join(built, file)} is missing — run "npm run build" first.`);
}
if (!existsSync(template)) fail(`the module template ${template} is missing.`);

// ------------------------------------------------------------------ 1–3. host app with module and extension

step(`Mendix tools: ${mx}`);
rmSync(join(repoRoot, '.package'), { recursive: true, force: true });
step('creating a temporary Mendix app');
runMx(['create-project', '--app-name', 'SecurityAnalyserHost', '--output-dir', work]);
const mpr = join(work, 'SecurityAnalyserHost.mpr');
step(`importing the ${MODULE} module`);
runMx(['module-import', template, mpr]);

step('adding the built extension');
const target = join(work, 'extensions', EXTENSION);
mkdirSync(join(target, 'wwwroot'), { recursive: true });
cpSync(join(built, 'manifest.json'), join(target, 'manifest.json'));
cpSync(join(built, `${EXTENSION}.dll`), join(target, `${EXTENSION}.dll`));
cpSync(join(built, 'wwwroot'), join(target, 'wwwroot'), { recursive: true });

// ------------------------------------------------------------------ 4. mark the module as an add-on with the extension

/** Minimal BSON: the element types Mendix units use. Values keep their type tag for re-encoding. */
function decode(buf, at = 0) {
  const size = buf.readInt32LE(at);
  const end = at + size;
  const items = [];
  let i = at + 4;
  while (i < end - 1) {
    const type = buf[i++];
    const zero = buf.indexOf(0, i);
    const key = buf.toString('utf8', i, zero);
    i = zero + 1;
    let value;
    switch (type) {
      case 0x01: value = buf.readDoubleLE(i); i += 8; break;
      case 0x02: { const n = buf.readInt32LE(i); value = buf.toString('utf8', i + 4, i + 3 + n); i += 4 + n; break; }
      case 0x03: case 0x04: { value = decode(buf, i); i += buf.readInt32LE(i); break; }
      case 0x05: { const n = buf.readInt32LE(i); value = { subtype: buf[i + 4], data: buf.subarray(i + 5, i + 5 + n) }; i += 5 + n; break; }
      case 0x08: value = buf[i] === 1; i += 1; break;
      case 0x09: case 0x12: value = buf.readBigInt64LE(i); i += 8; break;
      case 0x0a: value = null; break;
      case 0x10: value = buf.readInt32LE(i); i += 4; break;
      default: fail(`unsupported BSON element type ${type} at "${key}"`);
    }
    items.push({ type, key, value });
  }
  return items;
}

function encode(items) {
  const parts = [];
  for (const { type, key, value } of items) {
    parts.push(Buffer.from([type]), Buffer.from(`${key}\0`, 'utf8'));
    switch (type) {
      case 0x01: { const b = Buffer.alloc(8); b.writeDoubleLE(value); parts.push(b); break; }
      case 0x02: { const s = Buffer.from(`${value}\0`, 'utf8'); const n = Buffer.alloc(4); n.writeInt32LE(s.length); parts.push(n, s); break; }
      case 0x03: case 0x04: parts.push(encode(value)); break;
      case 0x05: { const n = Buffer.alloc(4); n.writeInt32LE(value.data.length); parts.push(n, Buffer.from([value.subtype]), value.data); break; }
      case 0x08: parts.push(Buffer.from([value ? 1 : 0])); break;
      case 0x09: case 0x12: { const b = Buffer.alloc(8); b.writeBigInt64LE(value); parts.push(b); break; }
      case 0x0a: break;
      case 0x10: { const b = Buffer.alloc(4); b.writeInt32LE(value); parts.push(b); break; }
    }
  }
  const body = Buffer.concat(parts);
  const size = Buffer.alloc(4);
  size.writeInt32LE(body.length + 5);
  return Buffer.concat([size, body, Buffer.from([0])]);
}

const get = (items, key) => items.find((x) => x.key === key)?.value;

/** The .mxunit file of a unit id stored as .NET GUID bytes. */
function unitFile(id) {
  const b = Buffer.from(id);
  const hex = (from, to, reverse) => {
    const part = [...b.subarray(from, to)];
    return (reverse ? part.reverse() : part).map((x) => x.toString(16).padStart(2, '0')).join('');
  };
  const guid = `${hex(0, 4, true)}-${hex(4, 6, true)}-${hex(6, 8, true)}-${hex(8, 10)}-${hex(10, 16)}`;
  return join(work, 'mprcontents', guid.slice(0, 2), guid.slice(2, 4), `${guid}.mxunit`);
}

step(`marking ${MODULE} as an add-on module carrying the ${EXTENSION} extension (version ${version})`);
const db = new DatabaseSync(mpr);
// MPR v1 keeps each unit's BSON in the Unit table; v2 keeps it in mprcontents/ files.
const inTable = db.prepare("SELECT name FROM pragma_table_info('Unit') WHERE name = 'Contents'").all().length > 0;
const units = db.prepare(`SELECT UnitID, ContainerID${inTable ? ', Contents' : ''} FROM Unit`).all();
const readUnit = (u) => {
  if (inTable) return u.Contents ? { doc: decode(Buffer.from(u.Contents)) } : undefined;
  const file = unitFile(u.UnitID);
  return existsSync(file) ? { file, doc: decode(readFileSync(file)) } : undefined;
};
const moduleUnit = units.find((u) => {
  const unit = readUnit(u);
  return unit && /^Projects\$Module(Impl)?$/.test(get(unit.doc, '$Type')) && get(unit.doc, 'Name') === MODULE;
});
if (!moduleUnit) fail(`module ${MODULE} was not found in the host app.`);
const settingsUnit = units
  .filter((u) => u.ContainerID && Buffer.from(u.ContainerID).equals(Buffer.from(moduleUnit.UnitID)))
  .map((u) => ({ u, unit: readUnit(u) }))
  .find(({ unit }) => unit && get(unit.doc, '$Type') === 'Projects$ModuleSettings');
if (!settingsUnit) fail(`the ModuleSettings of ${MODULE} were not found.`);

const wanted = { ExportLevel: 'Protected', ProtectedModuleType: 'AddOn', ExtensionName: EXTENSION, Version: version };
for (const [key, value] of Object.entries(wanted)) {
  const item = settingsUnit.unit.doc.find((x) => x.key === key);
  if (!item || item.type !== 0x02) fail(`ModuleSettings has no text property ${key}.`);
  item.value = value;
}
const data = encode(settingsUnit.unit.doc);
const hash = createHash('sha256').update(data).digest('base64');
if (inTable) {
  db.prepare('UPDATE Unit SET Contents = ?, ContentsHash = ? WHERE UnitID = ?').run(data, hash, settingsUnit.u.UnitID);
} else {
  writeFileSync(settingsUnit.unit.file, data);
  db.prepare('UPDATE Unit SET ContentsHash = ? WHERE UnitID = ?').run(hash, settingsUnit.u.UnitID);
}
db.close();

// ------------------------------------------------------------------ 5. check, export, verify

step('checking the app (mx check)');
const check = runMx(['check', mpr]);
if (!/contains: 0 errors/.test(check)) fail(`mx check reported errors:\n${check}`);

step('exporting the add-on module package');
mkdirSync(exportDir, { recursive: true });
runMx(['create-module-package', mpr, MODULE, '--package-dir', exportDir]);
const exported = join(exportDir, `${MODULE}.mxmodule`);
if (!existsSync(exported)) fail(`the export did not produce ${exported}.`);

/** Entries of a zip file, read from its central directory. */
function zipEntries(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) fail('the package is not a zip file.');
  const entries = [];
  let p = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < buf.readUInt16LE(eocd + 10); n++) {
    const method = buf.readUInt16LE(p + 10);
    const compressed = buf.readUInt32LE(p + 20);
    const nameLength = buf.readUInt16LE(p + 28);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLength);
    entries.push({
      name,
      read() {
        const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
        const raw = buf.subarray(start, start + compressed);
        return method === 0 ? raw : inflateRawSync(raw);
      },
    });
    p += 46 + nameLength + buf.readUInt16LE(p + 30) + buf.readUInt16LE(p + 32);
  }
  return entries;
}

step('verifying the package');
const entries = zipEntries(readFileSync(exported));
const names = entries.map((e) => e.name);
for (const required of [`extensions/${EXTENSION}/manifest.json`, `extensions/${EXTENSION}/${EXTENSION}.dll`, `extensions/${EXTENSION}/wwwroot/app.js`]) {
  if (!names.includes(required)) fail(`the package lacks ${required}.`);
}
const packageXml = entries.find((e) => e.name === 'package.xml')?.read().toString('utf8') ?? '';
if (!packageXml.includes(`<extension name="${EXTENSION}" />`)) fail('package.xml does not declare the extension.');
// A build path compiled into a file would publish the developer's user name and folder layout.
const userName = process.env.USERNAME;
if (userName) {
  const leaks = entries.filter((e) => e.name.startsWith('extensions/')).filter((e) => {
    const content = e.read();
    return [`Users\\${userName}`, `Users/${userName}`].some((s) => content.includes(Buffer.from(s)) || content.includes(Buffer.from(s, 'utf16le')));
  });
  if (leaks.length > 0) fail(`these files contain a local user path: ${leaks.map((e) => e.name).join(', ')}`);
}

mkdirSync(releaseDir, { recursive: true });
const output = join(releaseDir, `${MODULE}-${version}.mxmodule`);
rmSync(output, { force: true });
renameSync(exported, output);
rmSync(join(repoRoot, '.package'), { recursive: true, force: true });

const kb = Math.round(statSync(output).size / 1024);
console.log(`\nPackage ready: ${output} (${kb} KB)`);
console.log(`Import it in Studio Pro 10.24 or later: right-click the app ▸ Import module package, then trust the extension.`);
