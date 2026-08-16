# Raycast extension

`seal <url>` → opens your Magic Router instance with the URL prefilled.

## Install

1. `cd integrations/raycast && npm install`
2. Set `HOST` in `src/index.ts` to your deployment origin.
3. `npm run dev` (Raycast dev mode, requires the Raycast CLI) or
   `npx raycast ext build` and import the extension.

The command accepts an argument, or falls back to selected text, then the
clipboard. All encryption happens on the sealer page itself.
