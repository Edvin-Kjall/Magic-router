# Integrations

All integrations are thin wrappers: they prefill the sealer page — all crypto stays in
the browser, so every integration is trivially auditable.

| Integration | What it does | Where |
|---|---|---|
| Bookmarklet | Seal the current page in two clicks | `integrations/bookmarklet.js` |
| Raycast | `seal <url>` → opens sealer prefilled | `integrations/raycast/` |
| iOS Shortcut | Share-sheet action → opens sealer prefilled | `integrations/ios-shortcut/` |
| Slack | `/seal https://…` → ephemeral prefilled link (signed, stateless) | `integrations/slack/` + `site/worker.js` `/api/slack` |
| Obsidian | "Seal link" command on a selection, copies sealed link | `integrations/obsidian/` |

Each folder has its own README with setup steps. Remember to replace `YOUR-HOST`
with your deployment origin (or a self-hosted instance).
