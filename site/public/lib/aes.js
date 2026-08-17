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

// IV-less variant: GCM with a fixed all-zero IV. Safe ONLY because every key
// in this protocol is single-use per link (fresh random payload key, or a
// key derived from a fresh random salt) — the IV never repeats under one key.
// Saves 12 bytes per encryption (16 base64 chars each).
const ZERO_IV = new Uint8Array(12);

export async function aesEncryptNoIv(key, data) {
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ZERO_IV }, key, data));
}

export async function aesDecryptNoIv(key, ct) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ZERO_IV }, key, ct));
}
