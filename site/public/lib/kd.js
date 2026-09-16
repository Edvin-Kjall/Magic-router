// Key derivation. Argon2id is the default (memory-hard, the strongest
// practical defense against password guessing — classical or quantum);
// PBKDF2-SHA256 is kept for legacy v1 links and constrained environments.
//
// hash-wasm is imported as a bare specifier: the site maps it to a local
// vendored bundle via <script type="importmap">, Node resolves it from
// node_modules. Same source, both runtimes.
//
// In browsers, Argon2id runs in a dedicated worker (/vendor/kd-worker.js)
// so the ~64 MiB grind never freezes the UI. Node, the CLI and flat static
// builds have no worker — they use the inline path below.

import { argon2id } from 'hash-wasm';
import { b64uToBytes, toBytes } from './b64.js';

export const ARGON2ID = Object.freeze({ algo: 'argon2id', m: 65536, t: 3, p: 1 });
export const ARGON2ID_FAST = Object.freeze({ algo: 'argon2id', m: 8192, t: 1, p: 1 }); // tests / CI only
export const PBKDF2_V1 = Object.freeze({ algo: 'pbkdf2', i: 210000, hash: 'SHA-256' });

let worker = null;
let workerBroken = false;
let seq = 0;
const pending = new Map();

function argon2Worker() {
  if (worker || workerBroken) return worker;
  if (typeof Worker === 'undefined' || typeof location === 'undefined') {
    workerBroken = true;
    return null;
  }
  try {
    worker = new Worker('/vendor/kd-worker.js');
    worker.onmessage = (e) => {
      const { id, key, error } = e.data;
      const p = pending.get(id);
      if (!p) return;
      pending.delete(id);
      if (error) p.reject(new Error(error));
      else p.resolve(key);
    };
    worker.onerror = () => {
      // Missing worker script (flat drop builds) or worker crash: reject
      // in-flight jobs and settle back to inline derivation permanently.
      workerBroken = true;
      for (const p of pending.values()) p.reject(new Error('argon2 worker failed'));
      pending.clear();
      worker.terminate();
      worker = null;
    };
  } catch {
    workerBroken = true;
    worker = null;
  }
  return worker;
}

function deriveArgon2InWorker(w, params, password) {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    w.postMessage({
      id,
      password: String(password),
      s: params.s,
      m: params.m ?? 65536,
      t: params.t ?? 3,
      p: params.p ?? 1,
    });
  });
}

// params: { algo: 'argon2id', m: memoryKiB, t: iterations, p: parallelism, s: saltB64u }
//       | { algo: 'pbkdf2', i: iterations, hash: 'SHA-256', s: saltB64u }
// Returns an AES-GCM CryptoKey (never exportable).
export async function deriveKey(params, password) {
  if (params.algo === 'argon2id') {
    const w = argon2Worker();
    if (w) {
      try {
        return await deriveArgon2InWorker(w, params, password);
      } catch {
        /* fall back to inline derivation */
      }
    }
    const raw = await argon2id({
      password: String(password),
      salt: b64uToBytes(params.s),
      parallelism: params.p ?? 1,
      iterations: params.t ?? 3,
      memorySize: params.m ?? 65536, // KiB
      hashLength: 32,
      outputType: 'binary',
    });
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }
  if (params.algo === 'pbkdf2') {
    const km = await crypto.subtle.importKey('raw', toBytes(String(password)), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: b64uToBytes(params.s), iterations: params.i ?? 210000, hash: params.hash ?? 'SHA-256' },
      km,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }
  throw new Error(`unknown KDF: ${params.algo}`);
}

// One-off: derive raw 32 bytes (used by the CLI for self-test round trips).
export async function deriveRaw(params, password) {
  if (params.algo === 'argon2id') {
    return await argon2id({
      password: String(password),
      salt: b64uToBytes(params.s),
      parallelism: params.p ?? 1,
      iterations: params.t ?? 3,
      memorySize: params.m ?? 65536,
      hashLength: 32,
      outputType: 'binary',
    });
  }
  const km = await crypto.subtle.importKey('raw', toBytes(String(password)), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: b64uToBytes(params.s), iterations: params.i ?? 210000, hash: params.hash ?? 'SHA-256' },
      km,
      256
    )
  );
}
