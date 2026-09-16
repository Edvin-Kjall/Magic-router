# Premium mode (optional, stateful — ciphertext only)

The core product is stateless and free forever. Premium mode is an *optional* switch
for people who want the things statelessness cannot provide: **burn-after-read,
expiry enforcement, fetch counters, vanity slugs**. It stores only ciphertext
envelopes — still no passwords, no destinations, nothing decryptable server-side.

## What you get

| Feature | Stateless links | Premium links |
|---|---|---|
| Server storage | none | ciphertext envelope + counter |
| Burn after first fetch | — | ✅ |
| Expiry, server-enforced | advisory only | ✅ |
| Fetch counter | — | ✅ |
| Vanity slug (`/s/launch-codes`) | — | ✅ |
| Revoke (`DELETE /api/link/<slug>`) | — | ✅ |
| Password/destination secrecy | ✅ | ✅ (never sent) |

## Enable

```bash
npx wrangler kv namespace create SEAL_KV
```

Paste the printed namespace `id` into `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "SEAL_KV"
id = "your-namespace-id"
```

Set `PREMIUM = "true"` in `[vars]`, then `npx wrangler deploy`.

## API

```
POST   /api/link              { slug?, envelope, exp?, burn? } → { slug, url }
POST   /api/link              { slug?, url, exp?, burn? }       → { slug, url }  (short mode)
GET    /api/link/<slug>       → { envelope, meta } | { redirect, meta } | 410
DELETE /api/link/<slug>       → { revoked }   (unauthenticated — see below)
```

`envelope` links unlock exactly like stateless links. The web app offers a
"Get a short hosted link" button on the result view when the instance reports
premium, and the CLI equivalent is `--store` (with `--slug` / `--burn`).

`url` links are **short mode**: the destination is stored in plaintext behind
an 8-character slug and redirects immediately — the shortest possible link, for
when you don't need encryption. Because an unauthenticated open redirector on
your domain is a phishing amplifier, short mode is **opt-in**: set
`ALLOW_REDIRECTS = "true"` in `[vars]` to enable it. Burn-after-read, expiry
and counters apply to both modes.

### Server-side protections

- API responses carry `Cache-Control: no-store` — a burned/expired link can
  never be resurrected from a cache.
- Envelopes containing an embedded-password tail (`s6.<env>.<password>`) are
  rejected — the server must never hold a plaintext password.
- `exp` must be a parseable date; bodies are capped at 24 KiB, envelopes at
  16 KiB, URLs at 2 048 chars, slugs at 3–64 chars of `a-z0-9_-`.
- Mutating `/api/*` calls from a foreign `Origin` are refused (same-origin only).
- Burning or expiring a link deletes both its `link:` and `meta:` KV keys.

The page at `/s/<slug>` loads the app and fetches the envelope client-side, then
unlocks exactly like a stateless link.

## Honest caveats

- **Burn-after-read deletes the envelope after the first fetch.** A client that
  already decrypted it can of course keep the destination. Burning limits future
  distribution; it cannot claw back knowledge.
- **Revocation is unauthenticated** in this minimal form: anyone who knows the slug
  can `DELETE` it. Slugs are unguessable (8 chars, ~43 bits) but not secret-proof —
  put the instance behind Cloudflare Access or add an API token check if you need it.
- **Creation is unauthenticated too**: anyone can store ciphertext envelopes on
  your instance. There is no per-IP rate limit in this minimal form — if that
  matters, add Turnstile or Cloudflare Access in front of `POST /api/link`.
- **Fetch counters count envelope fetches**, not successful unlocks — the server
  cannot tell the difference (that's the point).
- Premium slugs make the link *shorter* and *revocable*, at the cost of the envelope
  living on a server. Stateless fragment links remain the privacy-maximal default.
