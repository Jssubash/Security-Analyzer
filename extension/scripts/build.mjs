/**
 * Build the two outputs of the TypeScript side:
 *
 *   dist/analyzer.cjs     the analyzer as a Node module, for the tests
 *   dotnet/wwwroot/       the pane's web page (index.html, app.js, app.css), which the C#
 *                         project copies next to the extension DLL and serves to the web view
 */

import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { build } from 'esbuild';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const wwwroot = join(root, 'dotnet', 'wwwroot');
mkdirSync(wwwroot, { recursive: true });

await build({
  entryPoints: [join(root, 'src', 'index.ts')],
  outfile: join(root, 'dist', 'analyzer.cjs'),
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node20',
  logLevel: 'warning',
});

await build({
  entryPoints: [join(root, 'src', 'ui', 'main.ts')],
  outfile: join(wwwroot, 'app.js'),
  bundle: true,
  platform: 'browser',
  format: 'iife',
  // Studio Pro hosts the pane in WebView2, which is evergreen Chromium.
  target: 'chrome110',
  minify: true,
  sourcemap: false,
  logLevel: 'warning',
});

await build({
  entryPoints: [join(root, 'src', 'ui', 'styles.css')],
  outfile: join(wwwroot, 'app.css'),
  bundle: true,
  minify: true,
  logLevel: 'warning',
});

copyFileSync(join(root, 'src', 'ui', 'index.html'), join(wwwroot, 'index.html'));
console.log('built dist/analyzer.cjs and dotnet/wwwroot/{index.html,app.js,app.css}');
