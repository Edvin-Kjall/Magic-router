// AES-256-GCM helpers on top of WebCrypto.

import { concatBytes, randomBytes } from './b64.js';

export function importAesKey(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// Returns iv (12 bytes) || ciphertext (plaintext length + 16-byte tag).
export async function aesEncrypt(key, data) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data));
  return concatBytes(iv, ct);
}

// Throws if the GCM tag does not verify (wrong key or tampered data).
export async function aesDecrypt(key, blob) {
  const iv = blob.subarray(0, 12);
  const ct = blob.subarray(12);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
}
