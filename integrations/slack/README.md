# Slack slash command

`/seal https://example.com` → an ephemeral reply with a link that opens your
sealer with the URL prefilled. The whole interaction is stateless — the
Worker verifies the request and answers; it stores nothing.

## Setup

1. Create a Slack app at https://api.slack.com/apps.
2. Add a **Slash Command**: command `/seal`, request URL
   `https://YOUR-HOST/api/slack`, with "Escape channels, users, and links"
   enabled.
3. Note the app's **Signing Secret**.
4. Set it on your Worker:
   ```
   npx wrangler secret put SLACK_SIGNING_SECRET
   ```
   (paste the signing secret; also set the optional `PUBLIC_HOST` var in
   `wrangler.toml` if the Worker runs behind a custom domain)
5. Install the app to your workspace, type `/seal https://…` and seal away.

## How the endpoint works

`site/worker.js` → `POST /api/slack`:

- verifies the `x-slack-signature` HMAC (SHA-256 over `v0:<ts>:<body>`)
  with the signing secret, rejects requests older than 5 minutes;
- extracts the first URL from the command text;
- replies with an ephemeral Slack message linking to `/?url=<url>`.

No Slack message content is stored by the Worker.
