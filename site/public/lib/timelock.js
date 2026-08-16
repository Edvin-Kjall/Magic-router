// Time-locked links: after unlocking, the opener must grind a sequential
// SHA-256 chain before the real payload key appears. No server, no clock
// trust — just honest computational delay. Sequential hashing cannot be
// parallelized (one output feeds the next input).
//
// Honest caveat (documented in SECURITY.md): a determined opener can patch
// the page's JavaScript to skip the wait. This is a fair-use time lock,
// not a tamper-proof one.

import { concatBytes } from './b64.js';

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

let nodeCrypto = null;
const IS_NODE = typeof process !== 'undefined' && !!process.versions?.node;
async function nodeSha() {
  if (nodeCrypto === null) {
    if (!IS_NODE) {
      nodeCrypto = false;
      return nodeCrypto;
    }
    try {
      nodeCrypto = (await import('node:crypto')).default ?? (await import('node:crypto'));
    } catch {
      nodeCrypto = false;
    }
  }
  return nodeCrypto;
}

// iterations sequential SHA-256 rounds: h0 = H(seed||salt), hi = H(h{i-1}||salt)
export async function hashChain(seed, salt, iterations) {
  const node = await nodeSha();
  if (node) {
    let h = node.createHash('sha256').update(seed).update(salt).digest();
    for (let i = 1; i < iterations; i++) h = node.createHash('sha256').update(h).update(salt).digest();
    return new Uint8Array(h);
  }
  let h = await sha256(concatBytes(seed, salt));
  for (let i = 1; i < iterations; i++) h = await sha256(concatBytes(h, salt));
  return h;
}

// Hashes per second on this device (used to pick `iterations` at seal time).
export async function estimateHashRate(samples = 4000) {
  const t0 = performance.now();
  await hashChain(new Uint8Array(32), new Uint8Array(16), samples);
  const dt = Math.max(performance.now() - t0, 1);
  return (samples * 1000) / dt;
}

export function iterationsFor(targetMillis, rate) {
  return Math.max(1, Math.round((targetMillis * rate) / 1000));
}

export function formatDuration(ms) {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h`;
  return `${Math.round(h / 24)}d`;
}
