// Builds dist-drop/: a flat static bundle for hosts that only serve
// root-level files (e.g. Cloudflare Drop). Everything the app needs —
// lib, Argon2id WASM, post-quantum crypto, QR encoder — is bundled into a
// single bundle.js; the EFF wordlist moves to the root.
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs';

const outdir = 'dist-drop';
mkdirSync(outdir, { recursive: true });

// 1) one self-contained JS bundle (node:* stays external — guarded at runtime)
await build({
  entryPoints: ['vendor-entries/site-entry.js'],
  bundle: true,
  format: 'esm',
  outfile: `${outdir}/bundle.js`,
  minify: false, // auditable, readable output is a feature
  target: ['es2020'],
  external: ['node:*'],
  logLevel: 'info',
});

// 2) index.html variant: no import map (no bare specifiers left), no hashes
// needed (no inline scripts), script src points at bundle.js
let html = readFileSync('site/public/index.html', 'utf8');
html = html.replace(/<script type="importmap">[\s\S]*?<\/script>\s*/, '');
html = html.replace(
  '<script type="module" src="/app.js"></script>',
  '<script type="module" src="/bundle.js"></script>'
);
html = html.replace(
  /script-src 'self' '[^']*' 'wasm-unsafe-eval'/,
  "script-src 'self' 'wasm-unsafe-eval'"
);
writeFileSync(`${outdir}/index.html`, html);

// 3) root-level static files
copyFileSync('site/public/style.css', `${outdir}/style.css`);
copyFileSync('site/public/favicon.svg', `${outdir}/favicon.svg`);
copyFileSync('site/public/data/eff-large.txt', `${outdir}/eff-large.txt`);
copyFileSync('site/public/deep-v1.json.gz', `${outdir}/deep-v1.json.gz`);
copyFileSync('site/public/deep-v2.json.gz', `${outdir}/deep-v2.json.gz`);

console.log(`drop build ready in ${outdir}/ (index.html, bundle.js, style.css, favicon.svg, eff-large.txt, deep-v1.json.gz, deep-v2.json.gz)`);
