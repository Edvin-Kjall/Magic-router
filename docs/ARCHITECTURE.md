# Magic Router — Architecture Map

Complete map of the project: what exists, how it fits together, and how data flows.

## One-paragraph summary

Magic Router is a **stateless encrypted link service**. A destination URL (or secret
text) is encrypted client-side with AES-256-GCM and the entire ciphertext envelope
rides inside the link itself — in the URL `#fragment`, which browsers never send to
servers, or in a `/_u/…` path segment. The Cloudflare Worker serves one static page
and three tiny API routes; it stores nothing, sees nothing, and has no database.
An optional "premium" mode stores *ciphertext only* in KV to add burn-after-read,
enforced expiry, fetch counters, and vanity slugs.

## Repository layout

```
├── site/
│   ├── worker.js               The Worker: asset serving + /api/prove, /api/health,
│   │                           /api/slack, /api/link/* (premium). ~215 lines.
│   └── public/                 Static assets (served via ASSETS binding)
│       ├── index.html          Single-page app shell + CSP meta + import map
│       ├── app.js              All UI logic (~795 lines)
│       ├── style.css           All styling
│       ├── _headers            Security + cache headers for static assets
│       ├── favicon.svg
│       ├── app.js → lib/       Shared isomorphic crypto core (browser + Node)
│       │   ├── envelope.js     THE format: seal/open/encode/decode/sign (~1269 lines)
│       │   ├── dict.js         URL dictionary compressor (core/extended/deep tiers)
│       │   ├── kd.js           Argon2id / PBKDF2 key derivation (+ Web Worker offload)
│       │   ├── aes.js          AES-256-GCM helpers (IV-carrying and IV-less)
│       │   ├── shamir.js       GF(2^8) Shamir secret sharing (m-of-n)
│       │   ├── timelock.js     RSW puzzle (modular squaring) + legacy SHA-256 chain + rate estimation
│       │   └── b64.js          base64url/bytes/hex/UTF-8 helpers
│       ├── vendor/             esbuild-bundled deps (no CDN at runtime)
│       │   ├── hash-wasm.js    Argon2id WASM
│       │   ├── noble-pq.js     ML-KEM-768 + ML-DSA-65 (@noble/post-quantum)
│       │   ├── qrcode.js       QR encoder
│       │   └── kd-worker.js    Classic worker script: Argon2id off the main thread
│       ├── data/eff-large.txt  EFF large wordlist (7776 words → passphrases)
│       ├── deep-v1.json(.gz)   FROZEN deep dictionary (legacy u2. links)
│       └── deep-v2.json(.gz)   Current deep dictionary (u3. links; ~100 KB gz)
├── cli/seal.mjs                `seal` CLI — same lib, Node 20+ (~339 lines)
├── vendor-entries/             esbuild entry points for vendor/ + dist-drop bundle
├── scripts/
│   ├── build-vendor.mjs        Builds site/public/vendor/* via esbuild
│   ├── build-drop.mjs          Builds dist-drop/ flat static bundle (Cloudflare Drop)
│   ├── gen-dict.mjs            Regenerates dict.js + deep-v2 from data/ (append-only)
│   └── run-tests.sh            Test runner (also used by CI)
├── spec/ENVELOPE.md            Formal wire-format spec, v1–v6 + plain u0–u3
├── docs/PREMIUM.md             Optional stateful tier design + API
├── docs/INTEGRATIONS.md        Integration index
├── integrations/               bookmarklet · Raycast · iOS Shortcut · Slack · Obsidian
├── tests/                      node:test suites (lib, cli, worker)
├── data/                       Source domain lists for gen-dict.mjs
├── dist-drop/                  Prebuilt flat bundle (committed for drop hosts)
├── .github/workflows/          test.yml (CI), deploy.yml (manual wrangler deploy)
├── wrangler.toml               Worker config: assets, PREMIUM var, optional KV
└── package.json                deps: @noble/post-quantum, hash-wasm, qrcode; dev: esbuild, wrangler
```

## Request flow (Worker)

`site/worker.js` exports one `fetch` handler:

| Route | Method | Purpose |
|---|---|---|
| `/api/prove` | GET | Echoes exactly what the server saw (headers, path, no fragment) — the "prove it" page data source |
| `/api/health` | GET | `{ ok, stateless, premium }` |
| `/api/slack` | POST | Slack slash command; verifies `x-slack-signature` HMAC-SHA256 (`v0:<ts>:<body>`, 5-min freshness window), replies ephemeral with a `/#prefill=` link |
| `/api/link` | POST | Premium only: store `{envelope}` or `{url}` under a slug (ciphertext or plaintext redirect) |
| `/api/link/<slug>` | GET | Premium: return envelope + meta (fetches, burn, exp); enforces expiry + burn-after-read |
| `/api/link/<slug>` | DELETE | Premium: revoke (unauthenticated — documented) |
| everything else | * | `env.ASSETS.fetch(request)` → static files, SPA fallback serves index.html for `/_u/…` and `/s/…` |

`wrangler.toml`: `run_worker_first = ["/api/*"]` — only API paths reach the worker
code; everything else is served straight from assets.

## Link formats (all live in envelope.js + spec/ENVELOPE.md)

**Sealed (encrypted) envelopes:**

| Prefix | Version | Encoding |
|---|---|---|
| `s3.` | v3 | `FLAG || maybe-deflate(JSON)` — verbose keys, IV-carrying |
| `s4.` | v4 | same, compact JSON keys |
| `s5.` | v5 | compact keys, IV-less GCM, "direct" mode (payload encrypted under the single method's key) |
| `s6.` | v6 | **current** — pure binary, no JSON/compression; typical 1-password link ≈ 80 chars |

A `.<embedded-password>` tail after the envelope = auto-open mode (documented
obfuscation — the link is the credential).

**Plain (unencrypted) short links:**

| Prefix | Meaning |
|---|---|
| `u1.` | base64url(flags ‖ maybe-deflate(dict-compressed URL)) — embedded dictionaries |
| `u2.` | same, indexes frozen deep-v1 table |
| `u3.` | same, indexes current deep-v2 table |
| `u0.` | raw mode — flags char + URL verbatim minus `https://`/`www.`; the "can't compress" fallback. Invariant: a plain link is never longer than the URL itself |

**Legacy:** `v1.`/`v2.` = `salt.iv.ct` — PBKDF2 / Argon2id over deflate-compressed
plaintext. Still openable.

## Cryptography inventory

| Piece | Algorithm | Where |
|---|---|---|
| Payload | AES-256-GCM, random 256-bit key; zero IV in ≥v5 (single-use keys) | envelope.js, aes.js |
| Password KDF | Argon2id 64 MiB/3/1 (fast 8 MiB/1/1 for tests), 16 B salt | kd.js (hash-wasm, Web Worker) |
| Legacy KDF | PBKDF2-SHA256 210 000 iters | kd.js |
| Passkey | WebAuthn PRF (`hmac-secret`); 32 B salt; fragment = key XOR PRF | envelope.js |
| Recipient keypair | Hybrid X25519 (WebCrypto) + ML-KEM-768 (noble); key = SHA-256("x25519"‖ssX‖"mlkem768"‖ssM) | envelope.js |
| Thresholds | Shamir over GF(2⁸)/0x11b, per-byte polynomials, share index `xi` | shamir.js |
| Time-lock | RSW puzzle: `b = 2^(2^n) mod N` folded into the payload key; sealer shortcuts via φ(N), opener runs n sequential squarings. Legacy SHA-256 chain links still decode. | timelock.js |
| Signatures | Ed25519 + optional ML-DSA-65 over canonical serialization (fixed key order, v=3 domain separator) | envelope.js |
| Payload compression | URL dictionary (core 1-B tokens / extended 3-B / deep 2–3-B) + deflate-raw, flag-byte tiered | dict.js |

## Data flow

**Seal (browser/CLI):** payload → optional dict+deflate pre-compression → random K
encrypts (AES-GCM) → K wrapped once per unlock method (Argon2id / embed / PRF /
hybrid pub) or Shamir-split for m-of-n → optional RSW time-lock fold on K → optional
signature → binary-encode → `s6.<b64url>` → URL `/#…` or `/_u/…`.

**Open:** extract fragment → decode envelope → show meta (host preview, note,
expiry, signatures, threshold) → collect credentials → unwrap K (or reconstruct
via Shamir) → solve time-lock puzzle → AES-GCM open → restore payload → **confirm screen**
with Safe Browsing check → `location.replace` to destination (http(s) only).

**Hosted (premium):** `/s/<slug>` page → `GET /api/link/<slug>` → envelope → same
open flow. `{url}` rows are plaintext short-mode redirects (no encryption).

## Web app (index.html + app.js)

- 4 views: `create` (default), `open`, `advanced`, `about` (Security/prove-it).
- Strict CSP meta (self + hash-pinned importmap + `wasm-unsafe-eval`), `no-referrer`.
- Import map binds `hash-wasm`, `@noble/post-quantum/*`, `qrcode` to `/vendor/*`.
- Argon2id runs in `/vendor/kd-worker.js` (falls back inline if the worker fails).
- Deep dictionary: `ensureDeepDict()` fetches `/deep-v2.json.gz` once, caches via
  Cache API, gunzips via DecompressionStream; Node reads the file from disk.
- Passphrase generator: EFF list, 8 words ≈ 103 bits.
- Fragment `#prefill=` (never sent) or legacy `?url=` seeds the create form.
- `route()` on load detects `/s/<slug>` (hosted), `/_u/…` (path link), `#…`
  (fragment link), `#prefill=…` (prefill), plain `u0–u3.` (instant redirect).

## CLI (`seal`, cli/seal.mjs)

`create` (--url/--text, --password×n, --embed, --recipient, --threshold, --delay,
--expires, --note, --sign, --pq, --preview, --host, --path, --qr, --json) ·
`open` (link, --password×n, --key, --json) · `keygen --recipient|--identity` ·
`info` · `passphrase`. Loads deep-v1/v2 tables from disk; same envelope lib.

## Integrations

All are thin prefills around `/#prefill=` — zero crypto in the integration except
Obsidian (bundles the real lib). Slack is the only server-side piece (`/api/slack`).

## Build & CI

- `npm run vendor` — esbuild → `site/public/vendor/*` (unminified = auditable).
- `npm run drop` — esbuild flat bundle → `dist-drop/` for root-only static hosts.
- `node scripts/gen-dict.mjs` — rebuilds dict.js + deep-v2 (append-only invariant;
  deep-v1 frozen forever).
- `npm test` — node:test, 50 tests across lib / cli (spawns the real CLI) / worker
  (calls `worker.fetch` with a mock KV).
- GitHub Actions: `test.yml` on push/PR; `deploy.yml` manual `wrangler deploy`.

## Trust boundaries

1. **Server sees:** page fetches, API metadata. Never fragments, passwords, or
   plaintext destinations (premium stores ciphertext only).
2. **Link holder sees:** salt/IV/ciphertext + opt-in public meta (host, note, exp).
3. **Credential holder:** gets plaintext after confirm screen.
4. Known limits (documented in SECURITY.md): no revocation for stateless links, no
   brute-force rate limiting, time-lock is a hardware-dependent duration not a
   calendar date, embedded links are credentials.
