/**
 * The widget packages of an app on disk, mirroring `WidgetScanner.cs`: each `widgets/*.mpk` with
 * its `<clientModule name version>` and the id, name and platform of every widget inside.
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { zipEntries } from './java-libraries-from-disk.mjs';

const attr = (tag, name) => new RegExp(`\\s${name}="([^"]*)"`).exec(tag)?.[1] ?? null;

export function widgetsFromDisk(projectRoot) {
  const dir = join(projectRoot, 'widgets');
  const packages = [];
  if (!existsSync(dir)) return { scanned: true, packages };
  for (const fileName of readdirSync(dir).filter((f) => f.toLowerCase().endsWith('.mpk')).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }))) {
    const node = { fileName };
    try {
      const entries = zipEntries(readFileSync(join(dir, fileName)));
      const pkg = entries.find((e) => e.name === 'package.xml');
      if (pkg) {
        const tag = /<clientModule\b[^>]*>/.exec(pkg.read())?.[0] ?? '';
        node.name = attr(tag, 'name');
        node.version = attr(tag, 'version');
      }
      node.widgets = [];
      const deps = new Map();
      const fromText = new Map();
      for (const e of entries) {
        const base = e.name.split('/').pop().toLowerCase();
        if (base === 'dependencies.json') {
          try {
            for (const item of JSON.parse(e.read())) {
              for (const [name, v] of Object.entries(item)) {
                if (!v?.version) continue;
                const key = `${name}@${v.version}`;
                const transitive = v.transitive === true && (deps.get(key)?.transitive ?? true);
                deps.set(key, { name, version: v.version, transitive });
              }
            }
          } catch {}
          continue;
        }
        if (base === 'dependencies.txt') {
          let name;
          for (const raw of e.read().split('\n')) {
            const line = raw.trim();
            if (line.startsWith('Name:')) name = line.slice(5).trim();
            else if (line.startsWith('Version:') && name) { const version = line.slice(8).trim(); fromText.set(`${name}@${version}`, { name, version, transitive: false }); name = undefined; }
          }
          continue;
        }
        if (e.name.includes('/') || !e.name.toLowerCase().endsWith('.xml') || e.name === 'package.xml') continue;
        const xml = e.read();
        const tag = /<widget\b[^>]*>/.exec(xml)?.[0] ?? '';
        const id = attr(tag, 'id');
        if (!id) continue;
        node.widgets.push({ id, name: /<name>\s*([^<]*?)\s*<\/name>/.exec(xml)?.[1] ?? null, pluginWidget: attr(tag, 'pluginWidget') === 'true', supportedPlatform: attr(tag, 'supportedPlatform') });
      }
      node.dependencies = [...(deps.size > 0 ? deps : fromText).values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
    } catch (err) {
      node.unreadable = err.message;
    }
    packages.push(node);
  }
  return { scanned: true, packages };
}
