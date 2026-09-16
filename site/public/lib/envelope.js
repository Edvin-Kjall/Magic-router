// Magic Router envelope — the whole format, in one file.
//
// A sealed link is:  s3.<base64url( flag || maybe-deflated( JSON envelope ) )>
// The envelope is public-safe (salt, IVs and ciphertext only); the payload
// key is wrapped once per unlock method, so a link can carry ANY or ALL of:
//   - password (Argon2id)
//   - embedded password (auto-open mode — obfuscation, documented as such)
//   - passkey (WebAuthn PRF extension)
//   - recipient keypair (hybrid X25519 + ML-KEM-768)
// wrapped as full keys (any one unlocks) or as Shamir shares (m-of-n).
// Optional: time-lock (sequential SHA-256 chain), signed seals
// (Ed25519 + ML-DSA-65), advisory expiry, destination preview.
//
// Isomorphic: browsers (WebCrypto + vendored noble) and Node 20+ (same).

import {
  bytesToB64u,
  b64uToBytes,
  toBytes,
  toStr,
  randomBytes,
  concatBytes,
  xorBytes,
} from './b64.js';
import { deriveKey, ARGON2ID } from './kd.js';
import { aesEncrypt, aesDecrypt, aesEncryptNoIv, aesDecryptNoIv, importAesKey } from './aes.js';
import { splitSecret, combineShares } from './shamir.js';
import { hashChain } from './timelock.js';
import { dictCompressEx, dictDecompress, dictDecompressLegacy, dictDecompressV3, dictCompressDeep, dictDecompressDeep, dictDecompressDeepV1, ensureDeepDict, ensureDeepDictV1, hasDeep } from './dict.js';

export const PREFIX = 's3.';
export const COMPACT_PREFIX = 's5.';
export const LEGACY_COMPACT_PREFIX = 's4.';
export const BINARY_PREFIX = 's6.';
export const VERSION = 3;
export const COMPACT_VERSION = 5;
export const LEGACY_COMPACT_VERSION = 4;
export const BINARY_VERSION = 6;
export const KDF_DEFAULT = ARGON2ID;

export class SealError extends Error {}

// Decoder limits — bound the damage a hostile/corrupt link can do.
// 64 wrappers is far beyond any legit link (the UI tops out around 5), but
// caps the password-candidates × wrappers Argon2id blowup on crafted links.
export const MAX_WRAPPERS = 64;
// Deflate bombs: a tiny crafted link must never expand to gigabytes.
export const MAX_INFLATE = 4 * 1024 * 1024;
// u48 allows ~9 000 years of grinding — refuse absurd time-locks
// (the UI offers at most 1 day; this leaves ~50 days of headroom at 1M h/s).
export const MAX_TIMELOCK_N = 2 ** 42;

// A WebAuthn prompt the user dismissed (or that timed out) is not a wrong
// credential — callers use this to keep the UI quiet instead of claiming
// "None of the provided credentials unlocked this link".
export function isCancelError(e) {
  return e?.name === 'NotAllowedError' || e?.name === 'AbortError';
}

// ---------------------------------------------------------------- basics

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

// Payload pre-compression for URL payloads: shared dictionary + deflate
// BEFORE encryption. Flag byte: 0 raw · 1 legacy-dict+deflate · 2 legacy-dict
// · 3 ext-dict+deflate · 4 ext-dict · 5 run-dict+deflate · 6 run-dict
// · 7 deep-dict+deflate · 8 deep-dict. URLs always start with 'h', so
// legacy flag-less payloads are unambiguous. An older page misdecoding a
// newer flag produces an invalid URL (control byte) and fails loudly
// instead of silently showing the wrong destination.
// (Safe against CRIME-style attacks: links are created once by their owner,
// with no attacker-influenced plaintext oracle.)
async function preparePayload(type, data) {
  const raw = toBytes(String(data));
  if (type !== 'url') return raw;
  let best = raw;
  let bestTier = 'raw';
  if (hasDeep()) {
    const d = dictCompressDeep(raw).bytes;
    if (d.length < best.length) { best = d; bestTier = 'deep'; }
  }
  const { bytes: d, tier } = dictCompressEx(raw);
  if (d.length < best.length) { best = d; bestTier = tier; }
  if (bestTier === 'raw') return concatBytes(new Uint8Array([0]), raw);
  const { flag, bytes } = await deflateMaybe(best);
  const f = bestTier === 'deep' ? (flag ? 9 : 10)
    : bestTier === 'v3' ? (flag ? 5 : 6)
    : bestTier === 'v2' ? (flag ? 3 : 4)
    : (flag ? 1 : 2);
  return concatBytes(new Uint8Array([f]), bytes);
}

async function restorePayload(type, bytes) {
  if (type !== 'url' || bytes.length === 0) return bytes;
  const f = bytes[0];
  if (f === 0) return bytes.subarray(1);
  if (f === 1) return dictDecompressLegacy(await inflateMaybe(1, bytes.subarray(1)));
  if (f === 2) return dictDecompressLegacy(bytes.subarray(1));
  if (f === 3) return dictDecompress(await inflateMaybe(1, bytes.subarray(1)));
  if (f === 4) return dictDecompress(bytes.subarray(1));
  if (f === 5) return dictDecompressV3(await inflateMaybe(1, bytes.subarray(1)));
  if (f === 6) return dictDecompressV3(bytes.subarray(1));
  if (f === 7) {
    await ensureDeepDictV1();
    return dictDecompressDeepV1(await inflateMaybe(1, bytes.subarray(1)));
  }
  if (f === 8) {
    await ensureDeepDictV1();
    return dictDecompressDeepV1(bytes.subarray(1));
  }
  if (f === 9) {
    await ensureDeepDict();
    return dictDecompressDeep(await inflateMaybe(1, bytes.subarray(1)));
  }
  if (f === 10) {
    await ensureDeepDict();
    return dictDecompressDeep(bytes.subarray(1));
  }
  return bytes; // legacy flag-less payload
}

export function isSealedLink(s) {
  return typeof s === 'string' && /^(s3\.|s4\.|s5\.|s6\.|v1\.|v2\.)/.test(s);
}

// s3.<env>.<embedded-password> → { env, tail }. The envelope itself is
// base64url, so the first '.' after the prefix delimits it.
export function splitEmbedded(str) {
  if (!str.startsWith(PREFIX) && !str.startsWith(COMPACT_PREFIX) && !str.startsWith(LEGACY_COMPACT_PREFIX) && !str.startsWith(BINARY_PREFIX)) {
    return { env: str, tail: null };
  }
  const i = str.indexOf('.', 3);
  if (i === -1) return { env: str, tail: null };
  return { env: str.slice(0, i), tail: str.slice(i + 1) };
}

export function parseDuration(s) {
  const m = /^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)$/i.exec(String(s).trim());
  if (!m) throw new SealError('duration must look like 200ms, 90s, 5m, 3h or 2d');
  const mul = { ms: 1, s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2].toLowerCase()];
  return Math.round(parseFloat(m[1]) * mul);
}

export function expiryStatus(meta) {
  if (!meta?.exp) return null;
  const t = Date.parse(meta.exp);
  if (Number.isNaN(t)) return null;
  const left = t - Date.now();
  return { at: meta.exp, expired: left <= 0, leftMs: left };
}

// ------------------------------------------------------- (de)compression

async function deflateMaybe(bytes) {
  if (typeof CompressionStream !== 'undefined') {
    try {
      const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream('deflate-raw'));
      const out = new Uint8Array(await new Response(stream).arrayBuffer());
      if (out.length < bytes.length) return { flag: 1, bytes: out };
    } catch {
      /* fall through to raw */
    }
  }
  return { flag: 0, bytes };
}

// Inflate with a hard output cap — a crafted link must not become a
// decompression bomb. Reads the stream chunk-wise so the cap is enforced
// before the full output is allocated.
async function inflateCapped(bytes) {
  if (typeof DecompressionStream !== 'undefined') {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    const reader = stream.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_INFLATE) {
        reader.cancel().catch(() => {});
        throw new SealError(`link expands beyond the ${MAX_INFLATE / 1024 / 1024} MiB safety limit`);
      }
      chunks.push(value);
    }
    return concatBytes(...chunks);
  }
  const zlib = await import('node:zlib');
  const out = new Uint8Array(zlib.inflateRawSync(bytes, { maxOutputLength: MAX_INFLATE }));
  if (out.length > MAX_INFLATE) {
    throw new SealError(`link expands beyond the ${MAX_INFLATE / 1024 / 1024} MiB safety limit`);
  }
  return out;
}

async function inflateMaybe(flag, bytes) {
  if (flag === 1) {
    if (typeof DecompressionStream !== 'undefined') return inflateCapped(bytes);
    try {
      return await inflateCapped(bytes);
    } catch (e) {
      if (e instanceof SealError) throw e; // bomb cap is not "not compressed"
      /* fall through */
    }
  }
  return bytes;
}

async function inflateIfPossible(bytes) {
  try {
    return await inflateCapped(bytes);
  } catch (e) {
    if (e instanceof SealError) throw e; // a real inflate that overflows is a bomb, not "not compressed"
    return bytes;
  }
}

// ------------------------------------------------------- plain (short) mode

// Unencrypted short links: u1.<base64url( FLAG || maybe-deflate( URL ) )>.
// No crypto, no storage — just compression. Anyone holding the link can
// decode the destination, which is exactly what "no encryption" means.
// u2. is the same format with the downloadable deep dictionary v1 (bit7);
// u3. with deep dictionary v2 (the current table). u0. is the raw mode:
// no compression, no base64 — the URL itself with https:// and www.
// stripped, so even URLs the dictionary barely helps still come out
// shorter than the original.
export const PLAIN_PREFIX = 'u1.';
export const PLAIN_PREFIX_DEEP = 'u2.';
export const PLAIN_PREFIX_DEEP2 = 'u3.';
export const PLAIN_PREFIX_RAW = 'u0.';

export function isPlainLink(s) {
  return typeof s === 'string' && (
    s.startsWith(PLAIN_PREFIX) || s.startsWith(PLAIN_PREFIX_DEEP) ||
    s.startsWith(PLAIN_PREFIX_DEEP2) || s.startsWith(PLAIN_PREFIX_RAW)
  );
}

// Pull the link string out of whatever the user pasted or the browser
// served: 's6.…', '#s6.…', '/_u/s6.…', 'https://host/#s6.…' or
// 'https://host/_u/s6.…'. Percent-decoding happens AT MOST ONCE, and
// never for plain (u0.–u3.) links — raw-mode bodies carry their own
// %23/%25 escapes that decodePlainUrl() owns, so pre-decoding them would
// corrupt the destination. Sealed envelopes get decoded once because
// their embedded-password tail may be percent-encoded.
export function extractLinkFragment(input) {
  let s = String(input ?? '');
  const hash = s.indexOf('#');
  if (hash !== -1) s = s.slice(hash + 1);
  else {
    const u = s.indexOf('/_u/');
    if (u !== -1) s = s.slice(u + 4);
  }
  if (isPlainLink(s)) return s;
  try {
    return decodeURIComponent(s);
  } catch {
    return s; // malformed escapes: hand the raw string to the decoders
  }
}

export async function encodePlainUrl(url) {
  const original = String(url);
  let s = original;
  let flags = 0; // bit0 deflated · bits1-2 scheme (0 none, 1 http, 2 https) · bit3 www. stripped · bit4 dictionary-tokenized · bit5 v2 (extended) · bit6 v3 (runs) · bit7 deep
  if (/^https:\/\//i.test(s)) {
    flags |= 2 << 1;
    s = s.slice(8);
  } else if (/^http:\/\//i.test(s)) {
    flags |= 1 << 1;
    s = s.slice(7);
  }
  if (/^www\./i.test(s)) {
    flags |= 1 << 3;
    s = s.slice(4);
  }
  let body = toBytes(s);
  let tier = null;
  const { bytes: d, tier: t } = dictCompressEx(body);
  if (d.length < body.length) {
    flags |= 1 << 4;
    if (t !== 'legacy') flags |= 1 << 5;
    if (t === 'v3') flags |= 1 << 6;
    tier = t;
    body = d;
  }
  if (hasDeep()) {
    const dd = dictCompressDeep(toBytes(s)).bytes;
    if (dd.length < body.length) {
      flags |= (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7);
      tier = 'deep';
      body = dd;
    }
  }
  const { flag, bytes } = await deflateMaybe(body);
  const outFlags = flags | flag;
  const prefix = tier === 'deep' ? PLAIN_PREFIX_DEEP2 : PLAIN_PREFIX;
  const link = prefix + bytesToB64u(concatBytes(new Uint8Array([outFlags]), bytes));
  // Hard invariant: a "short" link is never longer than the URL it points
  // to. When the compressed forms can't win, fall back to the raw mode —
  // the URL itself with scheme/www stripped (no base64 expansion at all) —
  // and only if even that loses, hand back the URL unchanged.
  if (link.length < original.length) return link;
  let rawBody = original;
  let v = 0; // bits: 1-2 scheme (1 http, 2 https) · bit3 www
  if (/^https:\/\//i.test(rawBody)) {
    v |= 2;
    rawBody = rawBody.slice(8);
  } else if (/^http:\/\//i.test(rawBody)) {
    v |= 1;
    rawBody = rawBody.slice(7);
  }
  if (/^www\./i.test(rawBody)) {
    v |= 4;
    rawBody = rawBody.slice(4);
  }
  const escaped = rawBody.replace(/%/g, '%25').replace(/#/g, '%23');
  // single-char flags: first base64url char of byte (v << 2) holds v
  const raw = PLAIN_PREFIX_RAW + bytesToB64u(new Uint8Array([v << 2]))[0] + escaped;
  return raw.length < original.length ? raw : original;
}

export async function decodePlainUrl(str) {
  if (str.startsWith(PLAIN_PREFIX_RAW)) {
    const body = str.slice(PLAIN_PREFIX_RAW.length);
    if (!body) throw new SealError('malformed short link');
    const v = b64uToBytes(body[0] + 'A')[0] >> 2;
    let s = body.slice(1).replace(/%23/g, '#').replace(/%25/g, '%');
    if (v & 4) s = 'www.' + s;
    if ((v & 3) === 2) s = 'https://' + s;
    else if ((v & 3) === 1) s = 'http://' + s;
    return s;
  }
  let deep = 0;
  if (str.startsWith(PLAIN_PREFIX_DEEP2)) {
    str = str.slice(PLAIN_PREFIX_DEEP2.length);
    deep = 2;
  } else if (str.startsWith(PLAIN_PREFIX_DEEP)) {
    str = str.slice(PLAIN_PREFIX_DEEP.length);
    deep = 1;
  } else if (str.startsWith(PLAIN_PREFIX)) {
    str = str.slice(PLAIN_PREFIX.length);
  }
  let raw;
  try {
    raw = b64uToBytes(str);
  } catch {
    throw new SealError('malformed short link');
  }
  if (!raw.length) throw new SealError('malformed short link');
  const flags = raw[0];
  const scheme = (flags >> 1) & 3;
  let bytes = await inflateMaybe(flags & 1, raw.subarray(1));
  if (flags & 16) {
    if (deep === 1 || (deep === 0 && flags & 128)) {
      await ensureDeepDictV1();
      bytes = dictDecompressDeepV1(bytes);
    } else if (deep === 2) {
      await ensureDeepDict();
      bytes = dictDecompressDeep(bytes);
    } else if (flags & 64) {
      bytes = dictDecompressV3(bytes);
    } else if (flags & 32) {
      bytes = dictDecompress(bytes);
    } else {
      bytes = dictDecompressLegacy(bytes);
    }
  }
  let s = toStr(bytes);
  if (flags & 8) s = 'www.' + s;
  if (scheme === 2) s = 'https://' + s;
  else if (scheme === 1) s = 'http://' + s;
  return s;
}

// ------------------------------------------------------------ (en)coding

// Compact v5 encoding: same data, short JSON keys, no per-ciphertext IVs
// (every key in the protocol is single-use, so GCM's IV is a fixed constant)
// and "direct" wrappers for single-method links (the payload is encrypted
// directly under the method's key — no wrap layer). Decoders also accept
// s3. (verbose v3) and s4. (compact v4, IV-carrying).
const WK = { pass: 'p', embed: 'e', prf: 'r', pub: 'u' };
const WK_BACK = { p: 'pass', e: 'embed', r: 'prf', u: 'pub' };
const WK_DIRECT = { pass: 'P', embed: 'E', prf: 'R', pub: 'U' };
const WK_DIRECT_BACK = { P: 'pass', E: 'embed', R: 'prf', U: 'pub' };

function compactEnvelope(env) {
  const out = { v: COMPACT_VERSION, t: env.t };
  const m = {};
  if (env.meta?.host != null) m.h = env.meta.host;
  if (env.meta?.exp != null) m.e = env.meta.exp;
  if (env.meta?.note != null) m.n = env.meta.note;
  if (env.meta?.time != null) m.z = { s: env.meta.time.salt, n: env.meta.time.n };
  if (env.meta?.sig?.length) {
    m.g = env.meta.sig.map((s) => ({ a: s.alg, na: s.name, k: s.pk, s: s.sig }));
  }
  out.m = m;
  out.w = (env.wrap || []).map((w) => {
    const c = { k: w.direct ? WK_DIRECT[w.k] : WK[w.k] };
    if (!w.direct) c.c = w.ct;
    if (w.s != null) c.s = w.s;
    if (w.k === 'pass' || w.k === 'embed') {
      const kd = w.kd;
      if (kd.algo === 'argon2id') {
        c.d = kd.m === 8192 && kd.t === 1 ? 'f' : 'a';
      } else {
        c.d = 'b';
        c.j = kd.i ?? 210000;
      }
    }
    if (w.k === 'prf') c.q = w.cid;
    if (w.k === 'pub') {
      c.x = w.x;
      c.y = w.m;
    }
    if (w.xi != null) c.i = w.xi;
    return c;
  });
  if (env.thr) out.r = { n: env.thr.n, m: env.thr.m };
  out.p = { c: env.payload.ct };
  return out;
}

function expandCompact(c, version) {
  const env = { v: version, t: c.t, meta: {}, wrap: [], payload: { ct: c.p.c } };
  if (c.m) {
    if (c.m.h != null) env.meta.host = c.m.h;
    if (c.m.e != null) env.meta.exp = c.m.e;
    if (c.m.n != null) env.meta.note = c.m.n;
    if (c.m.z != null) env.meta.time = { salt: c.m.z.s, n: c.m.z.n };
    if (c.m.g != null) env.meta.sig = c.m.g.map((s) => ({ alg: s.a, name: s.na, pk: s.k, sig: s.s }));
  }
  for (const w of c.w || []) {
    const direct = w.k in WK_DIRECT_BACK;
    const e = { k: direct ? WK_DIRECT_BACK[w.k] : WK_BACK[w.k], ct: w.c };
    if (direct) e.direct = true;
    if (w.s != null) e.s = w.s;
    if (w.d != null) {
      if (w.d === 'a') e.kd = { algo: 'argon2id', m: 65536, t: 3, p: 1 };
      else if (w.d === 'f') e.kd = { algo: 'argon2id', m: 8192, t: 1, p: 1 };
      else if (w.d === 'b') e.kd = { algo: 'pbkdf2', i: w.j ?? 210000, hash: 'SHA-256' };
    }
    if (w.q != null) e.cid = w.q;
    if (w.x != null) e.x = w.x;
    if (w.y != null) e.m = w.y;
    if (w.i != null) e.xi = w.i;
    env.wrap.push(e);
  }
  if (c.r) env.thr = { n: c.r.n, m: c.r.m };
  return env;
}

// --------------------------------------------------- binary v6 encoding

// Pure binary envelope — no JSON, no key names, no compression (ciphertext
// is random and incompressible anyway). ~45% shorter than the v5 JSON form.
// Byte layout (big-endian numbers):
//   u8 version (6)
//   u8 flags: bit0 type (0=url 1=text), bit1 hasMeta, bit2 hasThr
//   [meta: u8 flags — bit0 host, bit1 exp, bit2 note, bit3 time, bit4 sig
//     host:  u8 len + utf8
//     exp:   u48 unix ms
//     note:  u16 len + utf8
//     time:  u48 n + 16-byte salt
//     sig:   u8 count, then per sig: u8 alg (1=ed25519 2=mldsa65),
//            u8 nameLen + utf8, u16 pkLen + pk, u16 sigLen + sig]
//   [thr: u8 n, u8 m]
//   u8 wrapCount, then per wrapper:
//     u8 kind: bits0-1 kind (0 pass,1 embed,2 prf,3 pub), bit7 direct
//     pass/embed: u8 kdf (0 argon2id 64/3/1, 1 fast, 2 pbkdf2+u32 i) + 16 salt
//                 + [48 ct unless direct]
//     prf: 32 salt + u8 cidLen + cid + [32 ct unless direct]
//     pub: 32 x + 1088 mlkem + [48 ct unless direct]
//     + [u8 xi if thr]
//   u16 payloadLen + payload ciphertext
const KIND_NUM = { pass: 0, embed: 1, prf: 2, pub: 3 };
const KIND_BACK = ['pass', 'embed', 'prf', 'pub'];
const MLKEM_CT_LEN = 1088;

function numBytes(n, len) {
  const out = new Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = n & 255;
    n = Math.floor(n / 256);
  }
  return out;
}

// out.push(...bytes) with a chunk size that stays far below the engine's
// argument-count limit — large text secrets would otherwise blow the stack.
function pushBytes(out, bytes) {
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out.push(...bytes.subarray(i, i + 0x8000));
  }
}

// Decode a base64url field and enforce its exact byte length — a malformed
// envelope object must fail loudly here instead of producing a corrupt link.
function fieldBytes(b64, len, what) {
  let b;
  try {
    b = b64uToBytes(String(b64 ?? ''));
  } catch {
    throw new SealError(`malformed envelope: bad ${what}`);
  }
  if (len != null && b.length !== len) {
    throw new SealError(`malformed envelope: ${what} must be ${len} bytes, got ${b.length}`);
  }
  return b;
}

function binaryEncode(env) {
  const out = [];
  const m = env.meta || {};

  // Length fields are u8/u16 — refuse values that would silently wrap and
  // produce a corrupt envelope instead of a friendly error.
  const hostBytes = m.host != null ? toBytes(m.host) : null;
  const noteBytes = m.note != null ? toBytes(m.note) : null;
  const payloadBytes = fieldBytes(env.payload?.ct, null, 'payload ciphertext');
  if (hostBytes?.length > 255) throw new SealError(`host too long for the link format (max 255 bytes, got ${hostBytes.length})`);
  if (noteBytes?.length > 65535) throw new SealError(`note too long for the link format (max 65535 bytes, got ${noteBytes.length})`);
  if (payloadBytes.length > 65535) {
    throw new SealError(`payload too large for the link format (max 64 KiB encrypted, got ${payloadBytes.length} bytes)`);
  }
  if (!Array.isArray(env.wrap) || env.wrap.length > 255) {
    throw new SealError('too many unlock methods for the link format (max 255)');
  }
  if (env.thr && (env.thr.n > 255 || env.thr.m > 255)) {
    throw new SealError('threshold too large for the link format (max 255)');
  }
  let expMs = null;
  if (m.exp != null) {
    expMs = Date.parse(m.exp);
    if (!Number.isFinite(expMs) || expMs < 0 || expMs >= 2 ** 48) {
      throw new SealError('invalid expiry — must be a parseable date within the u48 range');
    }
  }
  if (m.time != null && (!Number.isFinite(m.time.n) || m.time.n < 1 || m.time.n >= 2 ** 48)) {
    throw new SealError('invalid time-lock round count');
  }
  const timeSalt = m.time != null ? fieldBytes(m.time.salt, 16, 'time-lock salt') : null;
  const sigs = m.sig ?? [];
  if (sigs.length > 255) throw new SealError('too many signatures for the link format');
  for (const s of sigs) {
    if (toBytes(s.name).length > 255) throw new SealError(`signer name too long for the link format (max 255 bytes)`);
    if (s.alg !== 'ed25519' && s.alg !== 'mldsa65') throw new SealError(`unknown signature algorithm: ${s.alg}`);
  }

  const hasMeta = m.host != null || m.exp != null || m.note != null || m.time != null || (m.sig?.length > 0);
  const flags = (env.t === 'text' ? 1 : 0) | (hasMeta ? 2 : 0) | (env.thr ? 4 : 0);
  out.push(BINARY_VERSION, flags);

  if (hasMeta) {
    let mf = 0;
    if (m.host != null) mf |= 1;
    if (m.exp != null) mf |= 2;
    if (m.note != null) mf |= 4;
    if (m.time != null) mf |= 8;
    if (m.sig?.length) mf |= 16;
    out.push(mf);
    if (hostBytes != null) {
      out.push(hostBytes.length);
      pushBytes(out, hostBytes);
    }
    if (expMs != null) out.push(...numBytes(expMs, 6));
    if (noteBytes != null) {
      out.push(...numBytes(noteBytes.length, 2));
      pushBytes(out, noteBytes);
    }
    if (m.time != null) {
      out.push(...numBytes(m.time.n, 6));
      pushBytes(out, timeSalt);
    }
    if (sigs.length) {
      out.push(sigs.length);
      for (const s of sigs) {
        out.push(s.alg === 'ed25519' ? 1 : 2);
        const nb = toBytes(s.name);
        out.push(nb.length);
        pushBytes(out, nb);
        const pk = fieldBytes(s.pk, null, 'signer public key');
        if (pk.length > 65535) throw new SealError('signer public key too long for the link format');
        out.push(...numBytes(pk.length, 2));
        pushBytes(out, pk);
        const sg = fieldBytes(s.sig, null, 'signature');
        if (sg.length > 65535) throw new SealError('signature too long for the link format');
        out.push(...numBytes(sg.length, 2));
        pushBytes(out, sg);
      }
    }
  }

  if (env.thr) out.push(env.thr.n, env.thr.m);
  out.push(env.wrap.length);
  for (const w of env.wrap) {
    if (KIND_NUM[w.k] === undefined) throw new SealError(`malformed envelope: unknown wrapper kind ${w.k}`);
    out.push(KIND_NUM[w.k] | (w.direct ? 128 : 0));
    if (w.k === 'pass' || w.k === 'embed') {
      const kd = w.kd ?? {};
      out.push(kd.algo === 'argon2id' ? (kd.m === 8192 && kd.t === 1 ? 1 : 0) : 2);
      if (kd.algo !== 'argon2id') out.push(...numBytes(kd.i ?? 210000, 4));
      pushBytes(out, fieldBytes(w.s, 16, 'password salt'));
      if (!w.direct) pushBytes(out, fieldBytes(w.ct, 48, 'wrapped key'));
    } else if (w.k === 'prf') {
      pushBytes(out, fieldBytes(w.s, 32, 'passkey salt'));
      const cid = fieldBytes(w.cid, null, 'credential id');
      if (cid.length > 255) throw new SealError('credential id too long for the link format');
      out.push(cid.length);
      pushBytes(out, cid);
      if (!w.direct) pushBytes(out, fieldBytes(w.ct, 32, 'wrapped key'));
    } else if (w.k === 'pub') {
      pushBytes(out, fieldBytes(w.x, 32, 'ephemeral public key'));
      pushBytes(out, fieldBytes(w.m, MLKEM_CT_LEN, 'ML-KEM ciphertext'));
      if (!w.direct) pushBytes(out, fieldBytes(w.ct, 48, 'wrapped key'));
    }
    if (env.thr) {
      if (!Number.isInteger(w.xi) || w.xi < 1 || w.xi > 255) {
        throw new SealError('malformed envelope: bad share index');
      }
      out.push(w.xi);
    }
  }

  out.push(...numBytes(payloadBytes.length, 2));
  pushBytes(out, payloadBytes);
  return new Uint8Array(out);
}

function binaryReader(bytes) {
  let off = 0;
  const need = (n) => {
    if (off + n > bytes.length) throw new SealError('malformed link: truncated envelope');
  };
  return {
    u8: () => {
      need(1);
      return bytes[off++];
    },
    bytes: (n) => {
      need(n);
      const s = bytes.subarray(off, off + n);
      off += n;
      return s;
    },
    num: (n) => {
      need(n);
      let v = 0;
      for (let i = 0; i < n; i++) v = v * 256 + bytes[off++];
      return v;
    },
    done: () => off === bytes.length,
  };
}

function binaryDecode(bytes) {
  const r = binaryReader(bytes);
  if (r.u8() !== BINARY_VERSION) throw new SealError('unsupported binary envelope version');
  const flags = r.u8();
  const env = { v: BINARY_VERSION, t: flags & 1 ? 'text' : 'url', meta: {}, wrap: [], payload: {} };
  if (flags & 2) {
    const mf = r.u8();
    if (mf & 1) env.meta.host = toStr(r.bytes(r.u8()));
    if (mf & 2) env.meta.exp = new Date(r.num(6)).toISOString();
    if (mf & 4) env.meta.note = toStr(r.bytes(r.num(2)));
    if (mf & 8) env.meta.time = { n: r.num(6), salt: bytesToB64u(r.bytes(16)) };
    if (mf & 16) {
      const count = r.u8();
      env.meta.sig = [];
      for (let i = 0; i < count; i++) {
        const alg = r.u8();
        env.meta.sig.push({
          alg: alg === 1 ? 'ed25519' : alg === 2 ? 'mldsa65' : 'unknown',
          name: toStr(r.bytes(r.u8())),
          pk: bytesToB64u(r.bytes(r.num(2))),
          sig: bytesToB64u(r.bytes(r.num(2))),
        });
      }
    }
  }
  if (flags & 4) env.thr = { n: r.u8(), m: r.u8() };
  const wc = r.u8();
  if (env.thr && wc !== env.thr.n) {
    throw new SealError('malformed link: threshold count does not match wrapper count');
  }
  for (let i = 0; i < wc; i++) {
    const b = r.u8();
    const direct = !!(b & 128);
    const kind = KIND_BACK[b & 3];
    const w = { k: kind };
    if (direct) w.direct = true;
    if (kind === 'pass' || kind === 'embed') {
      const kdFlag = r.u8();
      if (kdFlag === 0) w.kd = { algo: 'argon2id', m: 65536, t: 3, p: 1 };
      else if (kdFlag === 1) w.kd = { algo: 'argon2id', m: 8192, t: 1, p: 1 };
      else if (kdFlag === 2) w.kd = { algo: 'pbkdf2', i: r.num(4), hash: 'SHA-256' };
      else throw new SealError('malformed link: unknown KDF id');
      w.s = bytesToB64u(r.bytes(16));
      if (!direct) w.ct = bytesToB64u(r.bytes(48));
    } else if (kind === 'prf') {
      w.s = bytesToB64u(r.bytes(32));
      w.cid = bytesToB64u(r.bytes(r.u8()));
      if (!direct) w.ct = bytesToB64u(r.bytes(32));
    } else {
      w.x = bytesToB64u(r.bytes(32));
      w.m = bytesToB64u(r.bytes(MLKEM_CT_LEN));
      if (!direct) w.ct = bytesToB64u(r.bytes(48));
    }
    if (env.thr) w.xi = r.u8();
    env.wrap.push(w);
  }
  env.payload.ct = bytesToB64u(r.bytes(r.num(2)));
  if (!r.done()) throw new SealError('malformed link: trailing bytes after payload');
  return env;
}

export async function encodeEnvelope(env, opts = {}) {
  if (opts.legacy) {
    const json = toBytes(JSON.stringify(env));
    const { flag, bytes } = await deflateMaybe(json);
    return PREFIX + bytesToB64u(concatBytes(new Uint8Array([flag]), bytes));
  }
  return BINARY_PREFIX + bytesToB64u(binaryEncode(env));
}

// Post-decode sanity: every decoding path (JSON v3, compact v4/v5, binary v6)
// funnels through here so a malformed envelope fails closed with a friendly
// SealError instead of a stray TypeError three functions later.
const KNOWN_KINDS = new Set(['pass', 'embed', 'prf', 'pub']);
function validateEnvelope(env) {
  if (!env || typeof env !== 'object') throw new SealError('malformed link');
  if (env.t !== 'url' && env.t !== 'text') throw new SealError('malformed link: bad payload type');
  if (!Array.isArray(env.wrap) || env.wrap.length === 0) {
    throw new SealError('malformed link: no unlock methods');
  }
  if (env.wrap.length > MAX_WRAPPERS) {
    throw new SealError(`malformed link: too many unlock methods (max ${MAX_WRAPPERS})`);
  }
  for (const w of env.wrap) {
    if (!w || typeof w !== 'object' || !KNOWN_KINDS.has(w.k)) {
      throw new SealError('malformed link: unknown unlock method');
    }
  }
  if (env.payload == null || typeof env.payload.ct !== 'string' || !env.payload.ct) {
    throw new SealError('malformed link: missing payload');
  }
  if (env.meta != null && typeof env.meta !== 'object') {
    throw new SealError('malformed link: bad metadata');
  }
  if (env.meta?.sig != null && !Array.isArray(env.meta.sig)) {
    throw new SealError('malformed link: bad signatures');
  }
  if (env.meta?.time != null) {
    const t = env.meta.time;
    if (typeof t.salt !== 'string' || !Number.isFinite(t.n) || t.n < 1) {
      throw new SealError('malformed link: bad time-lock');
    }
    if (t.n > MAX_TIMELOCK_N) {
      throw new SealError('this link claims an unreasonable time-lock — refusing to grind');
    }
  }
  if (env.thr) {
    const { n, m } = env.thr;
    if (!Number.isInteger(n) || !Number.isInteger(m) || m < 1 || m > n || n !== env.wrap.length) {
      throw new SealError('malformed link: bad threshold');
    }
    const seen = new Set();
    for (const w of env.wrap) {
      if (!Number.isInteger(w.xi) || w.xi < 1 || w.xi > n || seen.has(w.xi)) {
        throw new SealError('malformed link: bad share index');
      }
      seen.add(w.xi);
    }
  }
  return env;
}

export async function decodeEnvelope(str) {
  try {
    let env;
    if (str.startsWith(BINARY_PREFIX)) {
      env = binaryDecode(b64uToBytes(str.slice(BINARY_PREFIX.length)));
    } else if (str.startsWith(COMPACT_PREFIX)) {
      const raw = b64uToBytes(str.slice(COMPACT_PREFIX.length));
      const bytes = await inflateMaybe(raw[0], raw.subarray(1));
      env = expandCompact(JSON.parse(toStr(bytes)), COMPACT_VERSION);
    } else if (str.startsWith(LEGACY_COMPACT_PREFIX)) {
      const raw = b64uToBytes(str.slice(LEGACY_COMPACT_PREFIX.length));
      const bytes = await inflateMaybe(raw[0], raw.subarray(1));
      env = expandCompact(JSON.parse(toStr(bytes)), LEGACY_COMPACT_VERSION);
    } else {
      const body = str.startsWith(PREFIX) ? str.slice(PREFIX.length) : str;
      const raw = b64uToBytes(body);
      const bytes = await inflateMaybe(raw[0], raw.subarray(1));
      env = JSON.parse(toStr(bytes));
      if (env.v !== VERSION) throw new SealError(`unsupported envelope version: ${env.v}`);
    }
    return validateEnvelope(env);
  } catch (e) {
    if (e instanceof SealError) throw e;
    throw new SealError(`malformed link: ${e?.message ?? 'could not decode'}`);
  }
}

// Deterministic serialization for signatures: fixed key order, no sigs.
// The version field is pinned to 3 — it is a domain separator, not the
// wire-format version, so v3 and v4 encodings sign identically. Wrappers
// are rebuilt in their creation order (which is also the order the old
// v3 encoder emitted), so previously signed v3 links keep verifying.
function canonicalWrap(w) {
  const out = { k: w.k };
  if (w.k === 'pass' || w.k === 'embed') {
    out.kd = { algo: w.kd.algo, m: w.kd.m, t: w.kd.t, p: w.kd.p, i: w.kd.i, hash: w.kd.hash };
    out.s = w.s;
    if (!w.direct) out.ct = w.ct;
  } else if (w.k === 'prf') {
    out.cid = w.cid;
    out.s = w.s;
    if (!w.direct) out.ct = w.ct;
  } else if (w.k === 'pub') {
    out.alg = w.alg ?? 'hybrid-x25519-mlkem768';
    out.x = w.x;
    out.m = w.m;
    if (!w.direct) out.ct = w.ct;
  }
  if (w.xi != null) out.xi = w.xi;
  return out;
}

export function canonicalize(env) {
  const meta = {};
  if (env.meta?.host != null) meta.host = env.meta.host;
  if (env.meta?.exp != null) meta.exp = env.meta.exp;
  if (env.meta?.note != null) meta.note = env.meta.note;
  if (env.meta?.time != null) meta.time = { salt: env.meta.time.salt, n: env.meta.time.n };
  const out = { v: 3, t: env.t, meta };
  if (env.wrap) out.wrap = env.wrap.map(canonicalWrap);
  if (env.thr) out.thr = { n: env.thr.n, m: env.thr.m };
  out.payload = { ct: env.payload.ct };
  return JSON.stringify(out);
}

// -------------------------------------------------------------- wrapping

async function wrapCredential(c, keyBytes, kdf) {
  if (c.k === 'pass' || c.k === 'embed') {
    const s = randomBytes(16);
    const key = await deriveKey({ ...kdf, s: bytesToB64u(s) }, c.password);
    return { k: c.k, kd: { algo: kdf.algo, m: kdf.m, t: kdf.t, p: kdf.p, i: kdf.i, hash: kdf.hash }, s: bytesToB64u(s), ct: bytesToB64u(await aesEncryptNoIv(key, keyBytes)) };
  }
  if (c.k === 'prf') {
    const s = randomBytes(32);
    const { first, credentialId } = await enrollPasskey(s);
    return { k: 'prf', cid: bytesToB64u(credentialId), s: bytesToB64u(s), ct: bytesToB64u(xorBytes(first, keyBytes)) };
  }
  if (c.k === 'pub') {
    const { x25519Pub, mlkemPub } = normalizeRecipient(c.recipient);
    const eph = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const ephPub = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
    const ssX = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'X25519', public: await importX25519Public(b64uToBytes(x25519Pub)) },
        eph.privateKey,
        256
      )
    );
    const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js');
    const enc = await ml_kem768.encapsulate(b64uToBytes(mlkemPub));
    const ssM = new Uint8Array(enc.sharedSecret);
    const ctKem = new Uint8Array(enc.cipherText);
    const combined = await sha256(concatBytes(toBytes('x25519'), ssX, toBytes('mlkem768'), ssM));
    const key = await importAesKey(combined);
    return {
      k: 'pub',
      alg: 'hybrid-x25519-mlkem768',
      x: bytesToB64u(ephPub),
      m: bytesToB64u(ctKem),
      ct: bytesToB64u(await aesEncryptNoIv(key, keyBytes)),
    };
  }
  throw new SealError(`unknown credential kind: ${c.k}`);
}

async function tryUnwrap(w, creds, noIv) {
  const decrypt = noIv ? aesDecryptNoIv : aesDecrypt;
  try {
    let bytes = null;
    if (w.k === 'pass' || w.k === 'embed') {
      // One wrapper may be tried against several candidate passwords
      // (CLI multi-password links, m-of-n links). First match wins.
      const candidates = w.k === 'embed'
        ? [creds.embeddedPassword, ...(creds.embeddedPasswords ?? [])]
        : [creds.password, ...(creds.passwords ?? [])];
      for (const pw of candidates) {
        if (pw == null) continue;
        try {
          const key = await deriveKey({ ...w.kd, s: w.s }, pw);
          bytes = await decrypt(key, b64uToBytes(w.ct));
          break;
        } catch {
          /* wrong candidate, try the next */
        }
      }
      if (bytes == null) return null;
    } else if (w.k === 'prf') {
      const first = await (creds.prfAssertion ? creds.prfAssertion(w) : assertPasskey(w));
      if (!first) return null;
      bytes = xorBytes(first, b64uToBytes(w.ct));
    } else if (w.k === 'pub') {
      if (!creds.privateKeys) return null;
      const { x25519Key, mlkemPriv } = await normalizePrivate(creds.privateKeys);
      const ssX = new Uint8Array(
        await crypto.subtle.deriveBits({ name: 'X25519', public: await importX25519Public(b64uToBytes(w.x)) }, x25519Key, 256)
      );
      const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js');
      const ssM = new Uint8Array(await ml_kem768.decapsulate(b64uToBytes(w.m), mlkemPriv));
      const combined = await sha256(concatBytes(toBytes('x25519'), ssX, toBytes('mlkem768'), ssM));
      const key = await importAesKey(combined);
      bytes = await decrypt(key, b64uToBytes(w.ct));
    }
    return bytes ? { x: w.xi ?? 0, bytes } : null;
  } catch (e) {
    if (isCancelError(e)) throw e; // cancelled passkey prompt ≠ wrong credential
    return null;
  }
}

// Direct mode: derive payload-key candidates straight from the single
// credential. A password/embed wrapper may face several candidates (CLI
// multi-password links); each gets its chance against the GCM tag in
// open(). There is no wrap layer to verify against, so candidates cannot
// be filtered here — only the payload decryption can tell them apart.
async function deriveDirectKeys(w, creds) {
  if (w.k === 'pass' || w.k === 'embed') {
    const candidates = w.k === 'embed'
      ? [creds.embeddedPassword, ...(creds.embeddedPasswords ?? [])]
      : [creds.password, ...(creds.passwords ?? [])];
    const keys = [];
    for (const pw of candidates) {
      if (pw == null) continue;
      keys.push(await deriveKey({ ...w.kd, s: w.s }, pw));
    }
    return keys;
  }
  try {
    if (w.k === 'prf') {
      const first = await (creds.prfAssertion ? creds.prfAssertion(w) : assertPasskey(w));
      return first ? [await importAesKey(first)] : [];
    }
    if (w.k === 'pub') {
      if (!creds.privateKeys) return [];
      const { x25519Key, mlkemPriv } = await normalizePrivate(creds.privateKeys);
      const ssX = new Uint8Array(
        await crypto.subtle.deriveBits({ name: 'X25519', public: await importX25519Public(b64uToBytes(w.x)) }, x25519Key, 256)
      );
      const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js');
      const ssM = new Uint8Array(await ml_kem768.decapsulate(b64uToBytes(w.m), mlkemPriv));
      const combined = await sha256(concatBytes(toBytes('x25519'), ssX, toBytes('mlkem768'), ssM));
      return [await importAesKey(combined)];
    }
  } catch (e) {
    if (isCancelError(e)) throw e; // "user cancelled" is not "wrong credential"
    return [];
  }
  return [];
}

// ------------------------------------------------------------- passkeys

function webauthnOk() {
  return (
    typeof navigator !== 'undefined' &&
    navigator.credentials &&
    typeof globalThis.PublicKeyCredential !== 'undefined'
  );
}

// Ask an existing credential to evaluate the PRF extension. Throws the
// raw WebAuthn error on cancellation (isCancelError); a missing PRF result
// becomes a friendly SealError.
async function evalPrf(credentialId, salt) {
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32).buffer,
      allowCredentials: [{ id: credentialId.buffer, type: 'public-key' }],
    },
    extensions: { prf: { eval: { first: salt.buffer } } },
  });
  const ext = cred.getClientExtensionResults();
  const first = ext?.prf?.results?.first;
  if (!first) throw new SealError('this authenticator does not support the PRF extension');
  return new Uint8Array(first);
}

async function enrollPasskey(salt) {
  if (!webauthnOk()) throw new SealError('passkeys need a modern browser');
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32).buffer,
      rp: { name: 'Magic Router' },
      user: { id: randomBytes(16).buffer, name: 'sealed-link', displayName: 'Sealed link' },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    },
    extensions: { prf: { eval: { first: salt.buffer } } },
  });
  const credentialId = new Uint8Array(cred.rawId);
  const ext = cred.getClientExtensionResults();
  const first = ext?.prf?.results?.first;
  if (first) return { first: new Uint8Array(first), credentialId };
  // Two-step fallback: many authenticators only evaluate PRF on get(),
  // not during creation. Verify the new credential can actually produce
  // a PRF output before promising it will unlock anything.
  return { first: await evalPrf(credentialId, salt), credentialId };
}

async function assertPasskey(w) {
  if (!webauthnOk()) throw new SealError('passkeys need a modern browser');
  return evalPrf(b64uToBytes(w.cid), b64uToBytes(w.s));
}

// ------------------------------------------------------------ keypairs

export async function generateRecipientKeypair() {
  const x25519 = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js');
  const kem = await ml_kem768.keygen();
  return {
    v: 1,
    alg: 'hybrid-x25519-mlkem768',
    x25519: {
      pub: bytesToB64u(new Uint8Array(await crypto.subtle.exportKey('raw', x25519.publicKey))),
      priv: bytesToB64u(new Uint8Array(await crypto.subtle.exportKey('pkcs8', x25519.privateKey))),
    },
    mlkem: {
      pub: bytesToB64u(new Uint8Array(kem.publicKey)),
      priv: bytesToB64u(new Uint8Array(kem.secretKey)),
    },
  };
}

export function normalizeRecipient(recipient) {
  const r = typeof recipient === 'string' ? JSON.parse(recipient) : recipient;
  const x25519Pub = r.x25519?.pub ?? r.x25519Pub;
  const mlkemPub = r.mlkem?.pub ?? r.mlkemPub;
  if (!x25519Pub || !mlkemPub) throw new SealError('recipient needs x25519.pub and mlkem.pub');
  return { x25519Pub, mlkemPub };
}

async function importX25519Public(bytes) {
  return crypto.subtle.importKey('raw', bytes, { name: 'X25519' }, false, []);
}

async function normalizePrivate(priv) {
  if (priv.x25519Key && priv.mlkemPriv) return priv;
  const r = typeof priv === 'string' ? JSON.parse(priv) : priv;
  const x25519Key = await crypto.subtle.importKey(
    'pkcs8',
    b64uToBytes(r.x25519?.priv ?? r.x25519Priv),
    { name: 'X25519' },
    false,
    ['deriveBits']
  );
  const mlkemPriv = b64uToBytes(r.mlkem?.priv ?? r.mlkemPriv);
  return { x25519Key, mlkemPriv };
}

// ------------------------------------------------------------ identities

export async function generateSignerIdentity(name) {
  let ed = null;
  try {
    ed = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  } catch {
    ed = null;
  }
  let mldsa = null;
  try {
    const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
    const kp = await ml_dsa65.keygen();
    mldsa = {
      pub: bytesToB64u(new Uint8Array(kp.publicKey)),
      priv: bytesToB64u(new Uint8Array(kp.secretKey)),
    };
  } catch {
    mldsa = null;
  }
  if (!ed && !mldsa) throw new SealError('no signature algorithm available in this browser');
  return {
    v: 1,
    name: String(name),
    ed25519: ed
      ? {
          pub: bytesToB64u(new Uint8Array(await crypto.subtle.exportKey('raw', ed.publicKey))),
          priv: bytesToB64u(new Uint8Array(await crypto.subtle.exportKey('pkcs8', ed.privateKey))),
        }
      : null,
    mldsa65: mldsa,
  };
}

// opts.pq: also add the ML-DSA-65 signature. Post-quantum, but the extra
// signature + public key add ~7 KB to the link, so it is opt-in — Ed25519
// alone keeps signed links short.
export async function signEnvelope(env, identity, opts = {}) {
  const msg = toBytes(canonicalize(env));
  const sigs = [];
  if (identity.ed25519?.priv) {
    try {
      const priv = await crypto.subtle.importKey('pkcs8', b64uToBytes(identity.ed25519.priv), { name: 'Ed25519' }, false, ['sign']);
      const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, priv, msg));
      sigs.push({ alg: 'ed25519', name: identity.name, pk: identity.ed25519.pub, sig: bytesToB64u(sig) });
    } catch {
      /* skip ed25519 if unavailable */
    }
  }
  if (opts.pq && identity.mldsa65?.priv) {
    try {
      const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
      const sig = await ml_dsa65.sign(msg, b64uToBytes(identity.mldsa65.priv));
      sigs.push({ alg: 'mldsa65', name: identity.name, pk: identity.mldsa65.pub, sig: bytesToB64u(new Uint8Array(sig)) });
    } catch {
      /* skip mldsa if unavailable */
    }
  }
  if (!sigs.length) throw new SealError('no signature algorithm available in this environment');
  if (!env.meta.sig) env.meta.sig = [];
  env.meta.sig = env.meta.sig.filter((s) => s.name !== identity.name);
  env.meta.sig.push(...sigs);
  return env;
}

export async function verifySignatures(env) {
  const sigs = env.meta?.sig || [];
  const msg = toBytes(canonicalize(env));
  const results = [];
  for (const s of sigs) {
    try {
      if (s.alg === 'ed25519') {
        const pub = await crypto.subtle.importKey('raw', b64uToBytes(s.pk), { name: 'Ed25519' }, false, ['verify']);
        results.push({ name: s.name, alg: 'ed25519', ok: await crypto.subtle.verify({ name: 'Ed25519' }, pub, b64uToBytes(s.sig), msg) });
      } else if (s.alg === 'mldsa65') {
        const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
        results.push({ name: s.name, alg: 'mldsa65', ok: await ml_dsa65.verify(b64uToBytes(s.sig), msg, b64uToBytes(s.pk)) });
      } else {
        results.push({ name: s.name, alg: s.alg, ok: false });
      }
    } catch {
      results.push({ name: s.name, alg: s.alg, ok: false });
    }
  }
  return results;
}

// ---------------------------------------------------------------- seal

// All unlock methods in one call. passwords: string[], embedded: string|null,
// recipient: keypair JSON (public part used), prf: bool (browser enrollment),
// threshold: m for m-of-n over the methods, timeLock: {saltB64, n},
// expiry: Date|ISO string (advisory), note: public note, signer: identity,
// pq: add ML-DSA-65 signature, preview: store the destination domain in
// public metadata (anti-phishing preview — off by default: the destination
// stays fully encrypted).
export async function seal(opts = {}) {
  const {
    type = 'url',
    data,
    passwords = [],
    embedded = null,
    recipient = null,
    prf = false,
    threshold = null,
    timeLock = null,
    expiry = null,
    note = null,
    kdf = KDF_DEFAULT,
    signer = null,
    pq = false,
    preview = false,
  } = opts;

  if (!data) throw new SealError('seal: data is required');
  if (type === 'url' && !/^https?:\/\//i.test(String(data))) {
    throw new SealError('URL must start with http:// or https://');
  }
  const embeddedPw = embedded == null ? null : String(embedded);

  const creds = [];
  if (embeddedPw != null) creds.push({ k: 'embed', password: embeddedPw });
  for (const p of passwords) creds.push({ k: 'pass', password: String(p) });
  if (prf) creds.push({ k: 'prf' });
  if (recipient) creds.push({ k: 'pub', recipient });
  if (!creds.length) throw new SealError('seal: at least one unlock method required');

  const K = randomBytes(32);
  const meta = {};
  if (preview && type === 'url') {
    try {
      meta.host = new URL(String(data)).hostname;
    } catch {
      /* keep going; open() will still show the confirm screen */
    }
  }
  if (expiry) {
    const t = new Date(expiry);
    if (Number.isNaN(t.getTime())) throw new SealError('seal: expiry must be a valid date');
    meta.exp = t.toISOString();
  }
  if (note) meta.note = String(note);
  if (timeLock) meta.time = { salt: timeLock.saltB64 ?? bytesToB64u(timeLock.salt), n: timeLock.n };

  const env = { v: VERSION, t: type, meta, wrap: [], payload: {} };

  // Direct mode: exactly one unlock method and no threshold/time-lock — the
  // payload is encrypted directly under that method's key. No wrap layer,
  // no random payload key: the smallest possible encrypted link.
  const direct = creds.length === 1 && threshold == null && timeLock == null;
  if (direct) {
    const c = creds[0];
    let key;
    if (c.k === 'pass' || c.k === 'embed') {
      const s = randomBytes(16);
      key = await deriveKey({ ...kdf, s: bytesToB64u(s) }, c.password);
      env.wrap.push({
        k: c.k,
        direct: true,
        kd: { algo: kdf.algo, m: kdf.m, t: kdf.t, p: kdf.p, i: kdf.i, hash: kdf.hash },
        s: bytesToB64u(s),
      });
    } else if (c.k === 'prf') {
      const s = randomBytes(32);
      const { first, credentialId } = await enrollPasskey(s);
      key = await importAesKey(first);
      env.wrap.push({ k: 'prf', direct: true, cid: bytesToB64u(credentialId), s: bytesToB64u(s) });
    } else if (c.k === 'pub') {
      const { x25519Pub, mlkemPub } = normalizeRecipient(c.recipient);
      const eph = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
      const ephPub = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
      const ssX = new Uint8Array(
        await crypto.subtle.deriveBits(
          { name: 'X25519', public: await importX25519Public(b64uToBytes(x25519Pub)) },
          eph.privateKey,
          256
        )
      );
      const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js');
      const enc = await ml_kem768.encapsulate(b64uToBytes(mlkemPub));
      const combined = await sha256(concatBytes(toBytes('x25519'), ssX, toBytes('mlkem768'), new Uint8Array(enc.sharedSecret)));
      key = await importAesKey(combined);
      env.wrap.push({
        k: 'pub',
        direct: true,
        alg: 'hybrid-x25519-mlkem768',
        x: bytesToB64u(ephPub),
        m: bytesToB64u(new Uint8Array(enc.cipherText)),
      });
    }
    env.payload = { ct: bytesToB64u(await aesEncryptNoIv(key, await preparePayload(type, data))) };
    if (signer) await signEnvelope(env, signer, { pq });
    return env;
  }

  if (threshold != null) {
    const m = Number(threshold);
    if (!Number.isInteger(m) || m < 1 || m > creds.length) {
      throw new SealError(`threshold must be between 1 and ${creds.length}`);
    }
    if (m === 1) {
      // m-of-n with m=1 is just "any one unlocks": wrap the full key in each.
      for (const c of creds) env.wrap.push(await wrapCredential(c, K, kdf));
    } else {
      env.thr = { n: creds.length, m };
      const shares = splitSecret(K, creds.length, m);
      for (let i = 0; i < creds.length; i++) {
        const w = await wrapCredential(creds[i], shares[i].bytes, kdf);
        w.xi = shares[i].x; // share index — note: 'x' is taken (X25519 eph pubkey)
        env.wrap.push(w);
      }
    }
  } else {
    for (const c of creds) env.wrap.push(await wrapCredential(c, K, kdf));
  }

  // Time-lock: the payload key is the wrapped key pushed through a
  // sequential hash chain. Seal applies it once so the opener's chain
  // lands on the same value; open() re-applies it (that's the grind).
  let payloadKey = K;
  if (meta.time) payloadKey = await hashChain(K, b64uToBytes(meta.time.salt), meta.time.n);

  const key = await importAesKey(payloadKey);
  env.payload = { ct: bytesToB64u(await aesEncryptNoIv(key, await preparePayload(type, data))) };
  if (signer) await signEnvelope(env, signer, { pq });
  return env;
}

// ---------------------------------------------------------------- open

// creds: { password?, passwords?, embeddedPassword?, embeddedPasswords?,
//          privateKeys? (keypair JSON), prfAssertion?: fn(w)=>bytes }
// opts:  { onProgress?: fn(done, total) — called while grinding a time-lock }
// Returns { type, data, meta, env }. Throws SealError with a friendly message.
export async function open(str, creds = {}, opts = {}) {
  const env = await decodeEnvelope(str);
  const noIv = env.v >= COMPACT_VERSION;

  // Direct mode fast path: single method, payload encrypted under its key.
  if (!env.thr && env.wrap?.length === 1 && env.wrap[0].direct) {
    const keys = await deriveDirectKeys(env.wrap[0], creds);
    const ct = b64uToBytes(env.payload.ct);
    for (const key of keys) {
      try {
        const pt = await restorePayload(env.t, await aesDecryptNoIv(key, ct));
        return { type: env.t, data: toStr(pt), meta: env.meta, env };
      } catch {
        /* wrong candidate — GCM tag failed, try the next */
      }
    }
    throw new SealError('None of the provided credentials unlocked this link');
  }

  const fragments = [];
  if (env.thr) {
    // One credential may satisfy several wrappers that share it; each share
    // (xi) may only count once toward the threshold.
    const seen = new Set();
    for (const w of env.wrap) {
      const f = await tryUnwrap(w, creds, noIv);
      if (f && !seen.has(f.x)) {
        seen.add(f.x);
        fragments.push(f);
      }
    }
  } else {
    for (const w of env.wrap) {
      const f = await tryUnwrap(w, creds, noIv);
      if (f) {
        fragments.push(f);
        break; // any single wrapper yields the full key
      }
    }
  }

  let K;
  if (env.thr) {
    if (fragments.length < env.thr.m) {
      throw new SealError(`Need ${env.thr.m} credentials of ${env.thr.n}; you provided ${fragments.length}`);
    }
    K = combineShares(
      fragments.map((f) => ({ x: f.x, bytes: f.bytes })),
      32
    );
  } else if (fragments.length) {
    K = fragments[0].bytes;
  } else {
    throw new SealError('None of the provided credentials unlocked this link');
  }

  if (env.meta?.time) {
    K = await hashChain(K, b64uToBytes(env.meta.time.salt), env.meta.time.n, opts.onProgress);
  }

  const key = await importAesKey(K);
  const pt = await restorePayload(
    env.t,
    await (noIv ? aesDecryptNoIv(key, b64uToBytes(env.payload.ct)) : aesDecrypt(key, b64uToBytes(env.payload.ct)))
  );
  const data = toStr(pt);
  return { type: env.t, data, meta: env.meta, env };
}

// ---------------------------------------------------------------- legacy

// v1.<salt>.<iv>.<ct>  (PBKDF2-SHA256, 210k) and v2.<salt>.<iv>.<ct> (Argon2id).
// Both encrypt deflate-compressed UTF-8; kept so pre-v3 links keep working.
export async function openLegacy(blob, password) {
  const parts = String(blob).split('.');
  if (parts.length !== 4) throw new SealError('malformed legacy link');
  const [ver, saltS, ivS, ctS] = parts;
  const kd =
    ver === 'v2'
      ? { algo: 'argon2id', m: 65536, t: 3, p: 1, s: saltS }
      : { algo: 'pbkdf2', i: 210000, hash: 'SHA-256', s: saltS };
  const key = await deriveKey(kd, password);
  const raw = await aesDecrypt(key, concatBytes(b64uToBytes(ivS), b64uToBytes(ctS)));
  const data = toStr(await inflateIfPossible(raw));
  return { type: /^https?:\/\//i.test(data) ? 'url' : 'text', data, meta: { legacy: ver } };
}

// -------------------------------------------------------------- helpers

export async function makeTimeLock(targetMs, rate) {
  return {
    saltB64: bytesToB64u(randomBytes(16)),
    n: Math.max(1, Math.round((targetMs * rate) / 1000)),
    targetMs,
  };
}

export function describeEnvelope(env) {
  const methods = (env.wrap || []).map((w) => w.k);
  return {
    type: env.t,
    host: env.meta?.host ?? null,
    note: env.meta?.note ?? null,
    exp: env.meta?.exp ?? null,
    time: env.meta?.time ?? null,
    threshold: env.thr ?? null,
    methods,
    signed: (env.meta?.sig || []).map((s) => s.name),
  };
}
