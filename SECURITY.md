# Security

Magic Router is built so that **the server has nothing to protect** — there is no
database, no stored keys, no logs of link data. This file is the honest list of what
that does and does not buy you.

## Threat model

- **Attacker with full server access (or a subpoena):** learns only that somebody
  fetched a static page. Ciphertext, passwords, and destinations are never transmitted.
- **Attacker who intercepts the link:** holds ciphertext only. Without a credential they
  face AES-256-GCM and the KDFs — see below.
- **Attacker who intercepts the link AND the password (same channel):** wins. Share the
  password on a different channel than the link.
- **Attacker who can see your screen or browser history:** wins. History and cloud sync
  store full URLs including fragments.

## Cryptography

- **Payload:** AES-256-GCM, random 256-bit key, random 96-bit IV, 16-byte tag. Tampering
  or wrong credentials fail closed.
- **Passwords:** Argon2id, 64 MiB, 3 iterations, 1 lane, 16-byte random salt per link.
  Memory-hardness raises the cost per guess for classical and quantum attackers alike.
- **Passkeys:** WebAuthn PRF (`hmac-secret`): the key material is XOR-wrapped with
  `PRF(salt)` from the authenticator. The link never contains the credential's public
  key, so Shor's algorithm has no target. Requires an authenticator with PRF support
  (Chrome 116+, Safari 17.4+, Firefox 128+).
- **Recipient keypairs:** hybrid X25519 + ML-KEM-768. The payload key is wrapped under
  `SHA-256("x25519" ‖ X25519_ss ‖ "mlkem768" ‖ ML-KEM_ss)`; the link embeds an ephemeral
  X25519 public key and an ML-KEM ciphertext. Breaking it requires breaking BOTH the
  classical and the post-quantum primitive.
- **Signatures:** Ed25519 and ML-DSA-65 over a canonical serialization of the envelope
  (fixed field order, signatures excluded). Both must not verify for a forged claim to
  be believed in a hybrid-verifying client.
- **Shamir thresholds:** GF(2⁸) over the AES polynomial, per-byte independent
  polynomials, share index carried in the wrapper. m-of-n reconstruction is
  information-theoretic.
- **Time-locks:** sequential SHA-256 chain (inherently non-parallelizable). **Honest
  caveat:** an opener can patch the page's JavaScript and skip the grind. It is a
  fair-use delay, not tamper resistance.
- **Envelope compression:** deflate-raw with an explicit flag byte; decompression
  failures fall back to raw bytes.

## What the server does and does not see

- Fragment links (`/#s3.…`): the server sees **nothing** — browsers never transmit
  fragments. This is the default.
- Path links (`/_u/s3.…`): the server sees the **ciphertext envelope** (public-safe:
  salt, IVs, ciphertext, no key material). Passwords still never travel.
- Premium mode (`/s/<slug>`): the server stores **ciphertext envelopes** only, plus a
  fetch counter, optional expiry and burn-after-read. It never sees passwords or
  destinations. Burn-after-read deletes the envelope after first fetch — a client that
  already decrypted can still use the destination; this limits future distribution,
  not past possession.

## Known limitations (by design)

- **No revocation** for stateless links. If a link leaks, stop sharing its password.
- **No rate limiting** against brute force — the attacker holds the ciphertext forever.
  Mitigation is the password's entropy: use the built-in 🎲 passphrase generator
  (~103 bits) or a password manager.
- **Weak passwords die quickly.** "hunter2" is dead the moment the link leaks.
- **Embedded-password links are credentials.** Anyone holding the link holds the key.
  They are obfuscation, clearly labeled as such in the UI.
- **No forward secrecy for keypair links** — a future break of both X25519 *and*
  ML-KEM-768 retroactively decrypts. The hybrid design is the hedge.
- **The page is JavaScript.** You must trust the code you loaded — which is why the
  whole product is auditable in a coffee break: one HTML file, one JS app, one small
  worker, no CDN, no remote scripts, and a strict CSP. Pin and audit it.

## Reporting

Open an issue, or contact the maintainer directly. Please do not disclose
vulnerabilities publicly before a fix is published.
