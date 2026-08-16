import esbuild from 'esbuild';

// Bundles the plugin (and the shared crypto lib + hash-wasm) into one file.
esbuild
  .build({
    entryPoints: ['src/plugin.js'],
    bundle: true,
    format: 'cjs',
    platform: 'browser',
    outfile: 'dist/main.js',
    external: ['obsidian', 'electron', 'node:zlib'],
    logLevel: 'info',
  })
  .catch(() => process.exit(1));
