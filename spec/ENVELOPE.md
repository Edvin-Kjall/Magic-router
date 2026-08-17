# Magic Router Envelope — format specification, v3/v4/v5

A sealed link is a URL fragment (or path segment) of the form:

```
s3.<base64url( FLAG || maybe-deflate( JSON ) )>[.<embedded-password>]   ← v3 (verbose, IV-carrying)
s4.<base64url( FLAG || maybe-deflate( JSON ) )>[.<embedded-password>]   ← v4 (compact keys, IV-carrying)
s5.<base64url( FLAG || maybe-deflate( JSON ) )>[.<embedded-password>]   ← v5 (compact keys, IV-less, direct mode)
```

- `FLAG` is one byte: `0x01` = the JSON is deflate-raw compressed, `0x00` = raw UTF-8.
- `base64url` is RFC 4648 §5 (unpadded, `-`/`_`).
- The optional `.`-terminated tail after the envelope is the **embedded password**
  (percent-encoded in the full URL). Its presence selects auto-open mode; the envelope
  contains a matching `embed` wrapper.
- Decoders MUST accept `s3.`, `s4.` and `s5.`. New links SHOULD be encoded as `s5.`.

## v5 changes: IV-less GCM and direct mode

- **No per-ciphertext IVs.** Every key in the protocol is single-use (a fresh
  random payload key, or a key derived from a fresh random salt), so AES-GCM
  uses a fixed all-zero IV. `ct` fields contain only ciphertext||tag. This is
  safe precisely because keys never repeat across links.
- **Direct mode.** When a link has exactly one unlock method (and no threshold
  or time-lock), the payload is encrypted directly under that method's key —
  the wrap layer disappears entirely. Direct wrappers carry no `ct`:

| kind | v5 key | wrapper contents |
|---|---|---|
| password | `P` | `d` (kdf), `s` (salt) |
| embedded | `E` | `d`, `s` |
| passkey | `R` | `q` (credential id), `s` (PRF salt) |
| recipient key | `U` | `x` (eph X25519 pk), `y` (ML-KEM ct) |

Wrapped mode (multiple methods, thresholds, time-locks) keeps the lowercase
keys (`p`/`e`/`r`/`u`) with IV-less `c` fields, exactly as v4 but without IVs.

## v4 compact keys

Same semantics as v3, shorter JSON keys (this cuts ~35-40% of link size):

| v3 | v4 | scope |
|---|---|---|
| `meta` | `m` | envelope |
| `wrap` | `w` | envelope |
| `thr` | `r` | envelope |
| `payload` | `p` | envelope |
| `ct` | `c` | payload + wrappers |
| `host` | `h` | meta |
| `exp` | `e` | meta |
| `note` | `n` | meta |
| `time` | `z` | meta (`s` = salt, `n` = iterations) |
| `sig` | `g` | meta (`a`=alg, `na`=name, `k`=pk, `s`=sig) |
| wrapper `k` | `p`/`e`/`r`/`u` | pass / embed / prf / pub |
| `kd` | `d` | pass/embed — `a` = Argon2id 64MiB/3/1, `f` = Argon2id 8MiB/1/1 (tests), `b` = PBKDF2 (`j` = iterations) |
| `cid` | `q` | prf |
| `x` / `m` | `x` / `y` | pub (eph X25519 pk / ML-KEM ciphertext) |
| share `xi` | `i` | threshold wrappers |

Signature canonicalization is **encoding-independent**: it always uses the v3
expanded field names with fixed key order and a pinned version field of 3, so
the same signed link verifies whether it was stored as s3 or s4.

## v3 envelope JSON:

```jsonc
{
  "v": 3,                    // envelope version
  "t": "url" | "text",       // payload type
  "meta": {                  // all public, shown before unlock
    "host": "example.com",   // optional destination preview — ONLY when the
                             // sealer opts in; off by default so the
                             // destination stays fully encrypted
    "exp": "2026-12-31T00:00:00.000Z",  // advisory expiry (client-checked)
    "note": "…",             // optional public note
    "time": { "salt": "…", "n": 1000000 },  // time-lock: n sequential SHA-256 rounds
    "sig": [                 // signed seals (see Signatures)
      { "alg": "ed25519", "name": "alice", "pk": "…", "sig": "…" },
      { "alg": "mldsa65",  "name": "alice", "pk": "…", "sig": "…" }
    ]
  },
  "wrap": [ … ],             // key wrappers, one per unlock method
  "thr": { "n": 3, "m": 2 }, // optional: m-of-n threshold over wrap[]
  "payload": { "ct": "…" }   // AES-256-GCM: ct = iv(12) || ciphertext||tag
}
```

All byte strings are base64url-encoded.

## Payload

- A random 256-bit payload key `K` encrypts the UTF-8 destination/secret:
  `ct = IV(12 random bytes) || AES-256-GCM(K, IV, plaintext)`.
- With a time-lock, the stored payload key is `K' = H^n(K ‖ salt)` (sequential chain:
  `h0 = SHA-256(K‖salt)`, `hi = SHA-256(h_{i-1}‖salt)`), and the opener must grind the
  same chain before decryption. `n` is chosen from a measured hash rate.

## Key wrappers (`wrap[]`)

Each wrapper decrypts to a 32-byte fragment. Without `thr`, the fragment is `K` and
**any one** wrapper unlocks. With `thr`, each wrapper carries `"xi": 1..n` (its Shamir
share index) and the fragment is one share; any `m` shares reconstruct `K` over
GF(2⁸)/`x⁸+x⁴+x³+x+1` via Lagrange interpolation.

### `pass` — password

```jsonc
{ "k": "pass", "kd": { "algo": "argon2id", "m": 65536, "t": 3, "p": 1 }, "s": "…", "ct": "…" }
```

Key = Argon2id(password, salt=`s`, memory=`m` KiB, iterations=`t`, parallelism=`p`,
32-byte output), used as an AES-256-GCM key. `ct` = IV ‖ AES-GCM(key, fragment).
Legacy `kd.algo` values: `"pbkdf2"` with `{ "i": 210000, "hash": "SHA-256" }`.

### `embed` — embedded password (auto-open)

Identical shape to `pass`; the password is the link tail after the envelope. Same KDF.
Security note: anyone with the link can decrypt — this is obfuscation by design.

### `prf` — passkey (WebAuthn PRF)

```jsonc
{ "k": "prf", "cid": "…", "s": "…", "ct": "…" }
```

- `cid` — the credential id of the passkey created with the PRF extension.
- `s` — 32-byte PRF salt.
- `ct` = `fragment XOR PRF(s)` where PRF is the authenticator's
  `hmac-secret`/PRF output for that credential and salt (32 bytes).

The link never contains the credential's public key, so Shor's algorithm has no
target. Requires `navigator.credentials` with the `prf` extension.

### `pub` — recipient keypair (hybrid, post-quantum)

```jsonc
{ "k": "pub", "alg": "hybrid-x25519-mlkem768", "x": "…", "m": "…", "ct": "…" }
```

- `x` — ephemeral X25519 public key (raw, 32 bytes).
- `m` — ML-KEM-768 ciphertext encapsulating a shared secret to the recipient's
  ML-KEM public key.
- Combined key = `SHA-256("x25519" ‖ X25519(ephPriv, recipientPub) ‖ "mlkem768" ‖
  ML-KEM-decaps(ct, recipientSk))`; `ct` = IV ‖ AES-GCM(combinedKey, fragment).

Recipient key files (`seal-key.json`):

```jsonc
{ "v": 1, "alg": "hybrid-x25519-mlkem768",
  "x25519": { "pub": "…", "priv": "…(pkcs8)" },
  "mlkem":  { "pub": "…", "priv": "…" } }
```

Sealing needs only the public parts; opening needs the private parts.

## Signatures

The signed message is the **canonical serialization** of the envelope with fixed key
order — `{"v","t","meta":{"host","exp","note","time":{"salt","n"}},"wrap","thr","payload"}`
— signatures excluded. Both `ed25519` (WebCrypto) and `mldsa65` (FIPS 204) signatures
may be present for one identity; a hybrid-verifying client should require both.

## Legacy formats (still accepted)

- `v1.<salt>.<iv>.<ct>` — PBKDF2-SHA256, 210 000 iterations, deflate-compressed
  plaintext, AES-256-GCM.
- `v2.<salt>.<iv>.<ct>` — same, Argon2id (64 MiB, 3, 1).

## Conformance notes

- Decoders MUST fail closed on any parse error, unknown version, or GCM tag failure.
- Decoders SHOULD support both compressed and uncompressed envelopes.
- `meta.exp` is advisory and checked client-side; only premium server mode enforces it.
- The embedded-password tail is `decodeURIComponent`-ed before use.
