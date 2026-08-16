# Obsidian plugin

Seal a selected URL straight from the editor: the command prompts for a
password and copies a sealed Magic Router link to the clipboard.

## Build

1. From the repository root: `npm install` (uses the shared crypto lib and
   its `hash-wasm` dependency).
2. `cd integrations/obsidian && node esbuild.config.mjs`
3. Copy `manifest.json` and `dist/main.js` into
   `<vault>/.obsidian/plugins/seal-link/` and enable the plugin.

Set `HOST` in `src/plugin.js` to your deployment origin first.

The plugin runs the exact same envelope code as the web app — links it
creates open on any Magic Router instance.
