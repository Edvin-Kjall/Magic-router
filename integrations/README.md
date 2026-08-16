# Bookmarklet

Seal the page you are looking at in two clicks.

1. Deploy Magic Router (see the root README) and note its origin, e.g.
   `https://magic-router.yourname.workers.dev`.
2. Edit `bookmarklet.js`: set `HOST` to that origin.
3. Remove newlines and comments so it fits on one line (a minifier works;
   a manual join works too).
4. Create a new browser bookmark whose **URL** is the whole
   `javascript:(...)` one-liner.
5. On any page, click the bookmarklet — your sealer opens with the page URL
   prefilled, ready for a password, time-lock, signature, whatever.

The bookmarklet only prefills; all crypto still happens inside the sealer
page in your browser.
