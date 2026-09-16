// Builds self-contained ESM bundles for browser-side dependencies into
// site/public/vendor/. The site maps the bare specifiers to these files via
// an import map in index.html, so no third-party CDN is involved at runtime
// — every byte the page executes ships from this repository.
import { build } from 'esbuild';
import { mkdirSync } from 'node:fs';

const targets = [
  ['vendor-entries/hash-wasm.js', 'site/public/vendor/hash-wasm.js', 'esm'],
  ['vendor-entries/noble-pq.js', 'site/public/vendor/noble-pq.js', 'esm'],
  ['vendor-entries/qrcode.js', 'site/public/vendor/qrcode.js', 'esm'],
  // Classic (non-module) worker script — works in every worker-capable browser.
  ['vendor-entries/kd-worker-entry.js', 'site/public/vendor/kd-worker.js', 'iife'],
];

mkdirSync('site/public/vendor', { recursive: true });

for (const [entry, outfile, format] of targets) {
  await build({
    entryPoints: [entry],
    bundle: true,
    format,
    outfile,
    minify: false, // auditable, readable output is a feature
    target: ['es2020'],
    logLevel: 'info',
  });
  console.log(`built ${outfile}`);
}
