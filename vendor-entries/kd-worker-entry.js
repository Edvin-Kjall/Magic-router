// Argon2id derivation in a dedicated worker: the 64 MiB × 3-pass grind
// never touches the main thread, so the page stays responsive while
// sealing and unlocking. Bundled by scripts/build-vendor.mjs into a
// self-contained classic worker script (no import map needed inside).
import { argon2id } from 'hash-wasm';
import { b64uToBytes } from '../site/public/lib/b64.js';

self.onmessage = async (e) => {
  const { id, password, s, m, t, p } = e.data;
  try {
    const raw = await argon2id({
      password,
      salt: b64uToBytes(s),
      parallelism: p,
      iterations: t,
      memorySize: m, // KiB
      hashLength: 32,
      outputType: 'binary',
    });
    // CryptoKey is structured-cloneable — the main thread gets a ready
    // AES-GCM key, raw bytes never cross the boundary.
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
    self.postMessage({ id, key });
  } catch (err) {
    self.postMessage({ id, error: String(err?.message ?? err) });
  }
};
