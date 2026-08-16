# 🕯️ Magic Router

**Encrypted links that store themselves.** A Cloudflare Worker with *no database*: the
destination URL (or secret text) is AES-256-GCM encrypted into the link itself, and
unlocked by password, passkey, or keypair — entirely in the browser. The server sees
nothing, stores nothing, and *can* betray nothing.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Edvin-Kjall/Magic-router)
[![Tests](https://github.com/Edvin-Kjall/Magic-router/actions/workflows/test.yml/badge.svg)](https://github.com/Edvin-Kjall/Magic-router/actions/workflows/test.yml)

```
you                      the link                          the server
"https://secret…"  →  s3.<salt>.<iv>.<ciphertext>…  →  serves one static HTML page.
+ password "hunter2"   (#fragment — never sent)          That's the whole product.
```

## Features

- **Zero storage.** No KV, no D1, no Durable Objects in core mode. The entire link —
  salt, IV, ciphertext, unlock wrappers — rides inside the URL fragment, which browsers
  never send to servers.
- **Unlock methods, stackable per link:**
  - 🔑 **Password** — Argon2id memory-hard derivation (64 MiB, 3 passes)
  - 🔓 **Embedded password** — auto-open links (documented as obfuscation: the link *is* the credential)
  - 🪪 **Passkey** — WebAuthn PRF extension (Touch ID / Windows Hello / Android)
  - 🗝️ **Recipient keypair** — hybrid **X25519 + ML-KEM-768** (post-quantum)
- **m-of-n thresholds** — Shamir-secret-shared key; "needs 2 of 3 credentials".
- **Time-locks** — sequential SHA-256 grind before the payload opens (fair-use; see SECURITY).
- **Signed seals** — Ed25519 + ML-DSA-65 hybrid signatures; "Sealed by Alice ✅".
- **Secret text**, not just URLs — tokens, API keys, messages.
- **Destination preview + confirm screen** — anti-phishing by design.
- **Legacy support** — pre-v3 links still open.
- **CLI** (`seal`) for terminals and scripts, plus **bookmarklet, Raycast, iOS Shortcut,
  Slack slash command, Obsidian plugin** — all prefilling wrappers around the same page.
- **Prove-it page** — ask the server to confess exactly what it saw.
- **Optional premium mode** — server stores *ciphertext only* to add burn-after-read,
  expiry enforcement, fetch counters, vanity slugs (see `docs/PREMIUM.md`).

## Quick start

Click the **Deploy to Cloudflare** button above (public repo required — that's why this
one is), or:

```bash
git clone https://github.com/Edvin-Kjall/Magic-router.git
cd Magic-router
npm install
npm run vendor     # build the local browser bundles (hash-wasm, noble PQ, qrcode)
npm test           # 22 tests: crypto, thresholds, CLI, signatures, legacy
npx wrangler deploy
```

Then open your `*.workers.dev` URL. Create a link by typing a destination + password;
open any `/#s3.…` link to unlock it.

## Usage

**Web:** visit the root → seal a link. Share it; recipients open it and unlock.
Everything (Argon2id, AES-GCM, passkeys, ML-KEM, Shamir, time-lock grind) runs in the
browser. The "Prove it" tab shows what the server actually received — nothing but a
page fetch.

**CLI:**

```bash
npx seal create --url https://example.com/private --password "correct horse" --host https://your-host.workers.dev
npx seal create --text "$API_KEY" --embed "pw" --delay 2h --sign alice.json
npx seal create --url https://x --password a --password b --threshold 2 --qr
npx seal open 'https://your-host.workers.dev/#s3.…' --password "correct horse"
npx seal keygen --recipient      # → seal-key.json (hybrid X25519 + ML-KEM-768)
npx seal keygen --identity alice # → seal-identity-alice.json
npx seal info <link>
npx seal passphrase              # 8-word EFF passphrase, ~103 bits
```

CLI links open in the browser and vice versa — one format everywhere.

## How it works

1. **Sealing** (browser): a random 256-bit payload key K encrypts the destination
   (AES-256-GCM). K is then wrapped once per unlock method — e.g. encrypted under a
   key derived from the password (Argon2id), XORed with a passkey PRF output, or
   encapsulated to a hybrid X25519+ML-KEM-768 public key. The whole envelope is
   compressed, base64url-encoded, and appended to the URL as `#s3.…`.
2. **Opening**: the page reads the fragment, asks for the credential(s), unwraps K
   (reconstructing it via Shamir if m-of-n), grinds the time-lock if set, decrypts,
   verifies any signatures, and shows a confirm screen before redirecting.
3. **The server**: serves one static HTML file. It never sees the fragment, the
   password, or the destination. It has nothing to log, leak, or hand over.

Wrong credentials make the GCM tag fail — there is no oracle, and no server to
rate-limit against, so use long passphrases (the 🎲 button generates ~103-bit ones).

## Quantum security

| Component | Status |
|---|---|
| Encryption | AES-256-GCM — NIST post-quantum adequate (Grover: ~2¹²⁸) |
| Keypairs | Hybrid X25519 + ML-KEM-768 — needs classical *and* quantum breaks |
| Signatures | Ed25519 + ML-DSA-65 hybrid |
| Password hashing | Argon2id memory-hardness (raises cost per guess for any attacker) |

Post-quantum parts run on [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum),
vendored locally — no CDN at runtime.

## Repository layout

```
site/worker.js          the worker (stateless by default; premium APIs optional)
site/public/            the single-page app + lib + vendor bundles + EFF wordlist
site/public/lib/        shared crypto core (envelope, shamir, timelock, kd, …)
cli/seal.mjs            the CLI (same lib, Node 20+)
spec/ENVELOPE.md        the link format, formally
docs/PREMIUM.md         the optional stateful tier (ciphertext-only)
docs/INTEGRATIONS.md    bookmarklet / Raycast / iOS / Slack / Obsidian
integrations/           those integrations
tests/                  node:test suites (22 tests)
```

## Honest limits

- Links are **not short** — they carry their own ciphertext (~150–500 chars).
- Stateless links **cannot be revoked or expired** — only passwords can stop being
  shared. Premium mode trades a little state for those features.
- Browsers store full URLs in history and sync them; embedded-password links are
  therefore credentials. Share them accordingly.
- The time-lock is bypassable by editing the page's JS. It's fair-use, not a vault.

See [SECURITY.md](SECURITY.md) for the full threat model.

## License

MIT — [LICENSE](LICENSE)
