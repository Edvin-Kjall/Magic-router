# Production-readiness upgrades

Findings from a full audit (see ARCHITECTURE.md), grouped by area. Each item lists
the problem, the fix, and status. Everything below has been implemented.

## Envelope / parser hardening (`site/public/lib/`)

| # | Problem | Fix | Status |
|---|---|---|---|
| E1 | `binaryDecode` reads past the end silently (`subarray` clamps, `u8()` returns `undefined` → NaN iterations, mis-decoded wrappers) | Bounds-checked reader: any read past the end throws `SealError('malformed link')`; trailing bytes after the payload are rejected | ✅ done |
| E2 | Malformed `s3./s4./s5.` envelopes (bad base64, non-JSON, missing `wrap`/`payload`) throw raw `SyntaxError`/`TypeError` — ugly UI, inconsistent CLI errors | Every decode path ends in `validateEnvelope()`: `t` must be url/text, `wrap` an array with known kinds, `payload.ct` a string, `thr` sane (`m ≤ n`, `n = wrap count`, `xi ∈ [1,n]`, unique). Parse failures wrapped in `SealError` | ✅ done |
| E3 | `wrapCount` is a u8 — a crafted link with 200 wrappers × N password candidates triggers hundreds of Argon2id runs (tab-freezing DoS) | Cap at 64 wrappers (far above any legit use) — decode rejects earlier | ✅ done |
| E4 | Decompression bomb: `inflateMaybe` on a crafted `s3.`/`u1.` link can expand to gigabytes → OOM | Cap inflated output at 4 MiB (streams capped chunk-wise; Node `maxOutputLength`) | ✅ done |
| E5 | `binaryEncode` silently produces corrupt envelopes for bad field lengths (salt ≠ 16 B, pub `m` ≠ 1088 B, cid > 255 B, exp/time out of u48 range, sig alg unknown) | Strict per-field length/range validation → `SealError` | ✅ done |
| E6 | `meta.time.n` is u48 — a hostile link can claim a 9 000-year grind and freeze the page | Cap at 2⁴² rounds (~51 days at 1 M h/s; legit max from the UI is 1 day) → `SealError` | ✅ done |
| E7 | `decodePlainUrl('u0.')` on an empty/garbage body decodes nonsense instead of failing | Guards + wrapped errors → `SealError` | ✅ done |
| E8 | `seal({expiry: 'junk'})` throws a raw `RangeError` | Wrapped → `SealError('invalid expiry')` | ✅ done |
| E9 | Time-lock showed an ETA but the progress bar never moved (`#timelock-bar` unwired) | `hashChain` takes `onProgress(done, total)`; browser path yields every 4 096 rounds so the bar paints; `open()` threads it through | ✅ done |
| E10 | Time-lock was a skippable UI delay — patching the JS opened instantly, and a hash chain invites ASIC speedup | **RSW puzzle:** payload key folded with `b = 2^(2^n) mod N` (1024-bit RSA modulus generated per session, φ(N) never leaves the sealer's memory). Seal is instant via the trapdoor; the opener MUST run `n` sequential squarings — skipping yields a wrong key → AES-GCM auth failure. New meta-flag bit 5 carries `{n, N, salt}` in v6 (`nLen+N` varint field); `{n, salt}` alone still means the legacy chain so old links open. Squaring-rate estimator calibrates `n` and the ETA; modulus is pre-generated in the background at page load | ✅ done |
| E11 | Tampered time-lock (forged modulus) produced a raw `OperationError` — "The operation failed for an operation-specific reason" | Payload-decrypt failure wrapped in `SealError('this link failed verification…')` | ✅ done |
| E12 | Hostile RSW parameters: 8192-bit modulus → minutes of BigInt burn per squaring; 64-bit modulus → factorable | Modulus bounded to 512–4096 bits at encode AND decode; malformed `N` fails closed | ✅ done |
| E13 | Tracking params (`utm_*`, `fbclid`, `gclid`, Amazon/X/TikTok junk) added 50–200 uncompressible high-entropy chars to real shared links | `trackers.js`: ~300-name global blocklist + per-host rules distilled from the AdGuard URL Tracking filter, stripped before encryption. Default-on (`strip: false` / `--no-strip` / toggle to disable); surgical on the raw string so unstripped URLs stay byte-identical | ✅ done |
| E14 | Keypair wrap used a hand-rolled SHA-256 combiner | **X-Wing** (`ml_kem768_x25519`, draft-connolly-cfrg-xwing-kem): standardized SHA3-256 combiner, 32-byte decap seed. New `pubx` wrapper kind (binary kind bits widened to 0-2; old decoders fail closed). v1 key files still seal/open via the legacy `pub` path | ✅ done |
| E15 | Keypair links were ~1 530 chars — too long to paste comfortably | Opt-in classical-only `pubc` wrap (X25519 alone, `SHA-256("mr-x25519"‖ss)`): ~90 chars, clearly labeled "no post-quantum floor" in UI + CLI + docs | ✅ done |
| E16 | The CSP `script-src` sha256 covered the inline importmap but was never re-synced when X-Wing added entries — the site loaded but bound **zero** handlers (every form submitted natively) | Hash recomputed; a lib test now recomputes the hash from `index.html` and fails CI on drift. (External `src=` importmaps were tried and rejected — patchy support) | ✅ done |
| E17 | Premium mode was fully coded but dark — no KV bound, and `POST /api/link` was an unauthenticated store anyone could fill | Enabled: `SEAL_KV` bound + `PREMIUM=true`. Creation is human-gated by **Turnstile** (lazy-loaded widget, action `host_link`, siteverify checks success+action+hostname allowlist, fail closed); the CLI uses a `STORE_TOKEN` bearer instead. Documented KV's ~60s edge-cache window for revoke/burn propagation | ✅ done |

## Worker hardening (`site/worker.js`)

| # | Problem | Fix | Status |
|---|---|---|---|
| W1 | Any thrown error → opaque HTML 500 from the runtime | Top-level try/catch → JSON `{error}` 500, `console.error` structured | ✅ done |
| W2 | Premium GET responses had no `Cache-Control` — a burned or expired link could be served from a shared/browser cache, and the fetch counter miscounts | `Cache-Control: no-store` + `X-Content-Type-Options: nosniff` on all API JSON | ✅ done |
| W3 | `/api/link/<slug>` regex was unbounded — a 1 MB path hits KV with an oversized key | Slug regex capped `{3,64}` (same as create rule) | ✅ done |
| W4 | `premiumCreate`: `new Date(body.exp).toISOString()` throws on junk → 500; no body-size limit; non-string slug coerced weirdly | Validate `exp` → 400; `Content-Length` > 20 KiB → 413; slug must be a string | ✅ done |
| W5 | **Embedded-password tails could be stored server-side.** `POST {envelope: "s6.….password"}` passed the regex → the server would hold a plaintext password, breaking the core guarantee | Any `.` after the `sN.` prefix → 400 "envelope must not carry an embedded password tail" | ✅ done |
| W6 | Unauthenticated plaintext **open redirect**: `POST {url}` let anyone mint `your.host/s/x → anywhere` — a phishing amplifier on your domain | Short-redirect mode now requires `ALLOW_REDIRECTS = "true"` (opt-in, documented in PREMIUM.md) | ✅ done |
| W7 | Slack: `Math.abs(now - Number(ts)) > 300` — `NaN > 300` is false, so a non-numeric timestamp skipped the freshness check (signature still required, but sloppy) | `Number.isFinite` guard → 401 | ✅ done |
| W8 | Slack URL match could capture Slack's `<url|label>` brackets | Strip `<…>` and `|label` | ✅ done |
| W9 | Cross-site forms could POST/DELETE premium links (no Origin check) | Mutating `/api/*` calls with a foreign `Origin` → 403 (browsers always send it on form/fetch posts; CLI/Slack send none) | ✅ done |
| W10 | Burn/expiry deleted `link:` but orphaned `meta:` keys in KV forever | `meta:` deleted alongside | ✅ done |
| W11 | No observability | `observability.enabled` + traces at 1 % sampling in wrangler.toml (logs can only ever contain paths/headers — fragments never arrive) | ✅ done |
| W12 | `/api/health` didn't advertise capabilities | Returns `{ ok, stateless, premium, redirects }` so clients can feature-detect | ✅ done |

## Headers (`site/public/_headers`)

| # | Problem | Fix | Status |
|---|---|---|---|
| H1 | No `frame-ancestors` (meta CSP can't express it; XFO alone is legacy) | `Content-Security-Policy: frame-ancestors 'none'` header alongside `X-Frame-Options: DENY` | ✅ done |
| H2 | No Permissions-Policy / CORP | `Permissions-Policy` disables camera/mic/geo/etc.; `Cross-Origin-Resource-Policy: same-origin` | ✅ done |

## Web app (`site/public/app.js`, `index.html`)

| # | Problem | Fix | Status |
|---|---|---|---|
| U1 | **Premium was server-only**: the UI could open `/s/` links but could never create them — the whole premium feature was unreachable from the product | When `/api/health` reports premium, the result view gets a "Get a short hosted link" button → `POST /api/link` → `/s/<slug>` + copy. Hidden for embedded-password links (tails can't be hosted) | ✅ done |
| U2 | Burn-after-read invisible: opener wasn't told the link just burned | "burns after this open" shown pre-unlock; after unlock, a burn notice | ✅ done |
| U3 | No way to request burn/expiry enforcement on hosted links | Advanced: "Burn after first read" switch → `burn: true` on the hosted POST; the existing Expires field doubles as the server-enforced `exp` | ✅ done |
| U4 | Unlock button stayed live during open → double-submit = double Argon2id | Disabled while any open is in flight | ✅ done |
| U5 | Time-lock grind invisible | Progress bar wired (E9) + live ETA | ✅ done |

## CLI (`cli/seal.mjs`)

| # | Problem | Fix | Status |
|---|---|---|---|
| C1 | `seal open https://host/s/<slug>` failed — no hosted-link support | Detects `/s/` URLs → fetches `GET /api/link/<slug>` → handles `redirect`, `410 gone/expired`, then unlocks as usual | ✅ done |
| C2 | CLI couldn't create hosted links | `--store` (with `--host`) POSTs the envelope to `/api/link`; `--slug <s>` vanity, `--burn` flag, `--expires` doubles as server-enforced `exp` | ✅ done |
| C3 | `--embed` + `--store` would silently produce an unopenable hosted link | Fails loudly: embedded tails can't be stored | ✅ done |

## Tests / build

| # | Problem | Fix | Status |
|---|---|---|---|
| T1 | `node --test "tests/*.test.mjs"` relies on Node ≥21 glob handling — `engines` promises ≥20 | `node --test tests/` (directory form works on Node 20+) in package.json + run-tests.sh | ✅ done |
| T2 | No coverage for malformed/truncated/oversized envelopes, Slack signature flow, premium protections, hosted CLI open, timelock progress, RSW round-trip/signatures/hostile moduli | +22 tests across lib/cli/worker suites (50 → 72) | ✅ done |
| T3 | `site/public/vendor/kd-worker.js` untracked while its siblings are committed | Rebuilt via `npm run vendor`; note for commit | ✅ done |

## Deliberately NOT done (with reasons)

- **Brotli payload compression** — benchmarked: loses to the deep dictionary on every
  realistic URL (its block overhead exceeds the dictionary's head start under ~200 B)
  and would cost a ~1.1 MB lazy WASM for a ~10 % win on rare long non-dictionary
  URLs. The "never longer" gate makes it safe but the dependency cost is not.
- **Rate limiting premium creates** — real per-IP limits need state (Durable Object /
  Turnstile). Premium is opt-in and ciphertext-only; documented as an open endpoint
  in PREMIUM.md. If abuse appears, put the instance behind Cloudflare Access or add
  Turnstile — hooks are documented.
- **Authenticated revoke** — same reason; documented honest caveat in PREMIUM.md.
- **Rejecting expired links at `open()`** — spec says `meta.exp` is advisory,
  client-checked; the UI already flags it. Premium enforces server-side.
