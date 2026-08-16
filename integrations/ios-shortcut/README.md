# iOS Shortcut

Seal any URL from the share sheet or the Shortcuts app.

## Recipe (5 actions)

1. **Receive**: `URLs` from *Share Sheet* (and *Shortcuts*).
2. **URL**: pass the input through (ensures a URL type).
3. **URL Encode**: `URL Encode` on the URL.
4. **Text**: `https://YOUR-HOST/?url=<URL-Encoded Text>`.
5. **Open URLs**: open the text.

Replace `YOUR-HOST` with your deployment origin.

What this does: hands the URL to the sealer page (prefilled). Choosing the
password, time-lock, signing identity etc. still happens in the browser —
cryptography never runs inside the Shortcut, which keeps the shortcut
trivially auditable.

## Variant: "Seal from Safari page"

Same recipe, but replace step 1 with the *Get URL of Current Web Page*
action so the shortcut works while browsing (needs to run from the share
sheet of Safari).
