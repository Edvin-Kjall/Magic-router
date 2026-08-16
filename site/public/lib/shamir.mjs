// Shamir secret sharing over GF(2^8) (AES polynomial 0x11b).
// Used for n-of-m links: the payload key is split into n shares,
// each share wrapped by a different unlock method; any m shares
// reconstruct the key. Fully client-side, no storage.

import { randomBytes } from './b64.mjs';

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  // Build the field with primitive generator 3 (0x02 has order 51 in
  // GF(2^8)/0x11b, so powers of 2 cover only a subgroup). Multiply by
  // 3 = x ^ xtime(x); JS-safe xtime (C's 8-bit overflow doesn't exist here).
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    const xt = ((x << 1) & 0xff) ^ (x & 0x80 ? 0x1b : 0);
    x ^= xt;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
}

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}
function gfPow(a, e) {
  if (a === 0) return e === 0 ? 1 : 0;
  return EXP[(LOG[a] * e) % 255];
}
function gfDiv(a, b) {
  if (b === 0) throw new Error('division by zero');
  if (a === 0) return 0;
  return EXP[(LOG[a] - LOG[b] + 255) % 255];
}

// Split secret bytes into n shares; any m of them reconstruct.
// Shares are { x: 1..n, bytes: Uint8Array } — x is public metadata.
export function splitSecret(secret, n, m) {
  if (!(Number.isInteger(n) && Number.isInteger(m))) throw new Error('n, m must be integers');
  if (m < 2 || m > n || n > 255) throw new Error('require 2 <= m <= n <= 255');
  const shares = [];
  for (let x = 1; x <= n; x++) shares.push({ x, bytes: new Uint8Array(secret.length) });
  for (let b = 0; b < secret.length; b++) {
    // ONE polynomial per byte — the same coefficients for every share x.
    const coefs = [];
    for (let k = 1; k < m; k++) coefs.push(randomBytes(1)[0]);
    for (let x = 1; x <= n; x++) {
      let acc = secret[b];
      for (let k = 1; k < m; k++) acc ^= gfMul(coefs[k - 1], gfPow(x, k));
      shares[x - 1].bytes[b] = acc;
    }
  }
  return shares;
}

// Lagrange interpolation over GF(2^8). Need >= m shares; extra shares
// beyond m are fine (they only improve the interpolation).
export function combineShares(shares, length) {
  if (shares.length < 2) throw new Error('need at least 2 shares');
  const secret = new Uint8Array(length);
  for (let b = 0; b < length; b++) {
    let acc = 0;
    for (const s of shares) {
      let term = s.bytes[b];
      for (const o of shares) {
        if (o.x !== s.x) term = gfMul(term, gfDiv(o.x, o.x ^ s.x));
      }
      acc ^= term;
    }
    secret[b] = acc;
  }
  return secret;
}
