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
import { aesEncrypt, aesDecrypt, importAesKey } from './aes.js';
import { splitSecret, combineShares } from './shamir.js';
import { hashChain } from './timelock.js';

export const PREFIX = 's3.';
export const COMPACT_PREFIX = 's4.';
export const VERSION = 3;
export const COMPACT_VERSION = 4;
export const KDF_DEFAULT = ARGON2ID;

export class SealError extends Error {}

// ---------------------------------------------------------------- basics

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export function isSealedLink(s) {
  return typeof s === 'string' && /^(s3\.|s4\.|v1\.|v2\.)/.test(s);
}

// s3.<env>.<embedded-password> → { env, tail }. The envelope itself is
// base64url, so the first '.' after the prefix delimits it.
export function splitEmbedded(str) {
  if (!str.startsWith(PREFIX) && !str.startsWith(COMPACT_PREFIX)) return { env: str, tail: null };
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

async function inflateMaybe(flag, bytes) {
  if (flag === 1) {
    if (typeof DecompressionStream !== 'undefined') {
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
      return new Uint8Array(await new Response(stream).arrayBuffer());
    }
    try {
      const zlib = await import('node:zlib');
      return new Uint8Array(zlib.inflateRawSync(bytes));
    } catch {
      /* fall through */
    }
  }
  return bytes;
}

async function inflateIfPossible(bytes) {
  if (typeof DecompressionStream !== 'undefined') {
    try {
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
      return new Uint8Array(await new Response(stream).arrayBuffer());
    } catch {
      return bytes;
    }
  }
  try {
    const zlib = await import('node:zlib');
    return new Uint8Array(zlib.inflateRawSync(bytes));
  } catch {
    return bytes;
  }
}

// ------------------------------------------------------- plain (short) mode

// Unencrypted short links: u1.<base64url( FLAG || maybe-deflate( URL ) )>.
// No crypto, no storage — just compression. Anyone holding the link can
// decode the destination, which is exactly what "no encryption" means.
export const PLAIN_PREFIX = 'u1.';

export function isPlainLink(s) {
  return typeof s === 'string' && s.startsWith(PLAIN_PREFIX);
}

export async function encodePlainUrl(url) {
  const { flag, bytes } = await deflateMaybe(toBytes(String(url)));
  return PLAIN_PREFIX + bytesToB64u(concatBytes(new Uint8Array([flag]), bytes));
}

export async function decodePlainUrl(str) {
  if (str.startsWith(PLAIN_PREFIX)) str = str.slice(PLAIN_PREFIX.length);
  const raw = b64uToBytes(str);
  const flag = raw[0];
  const bytes = await inflateMaybe(flag, raw.subarray(1));
  return toStr(bytes);
}

// ------------------------------------------------------------ (en)coding

// Compact v4 encoding: same data, short JSON keys. Shrinks links ~35-40%
// (verbose key names + KDF parameters were the biggest fixed cost).
// Decoders accept both s3. (verbose v3) and s4. (compact v4).
const WK = { pass: 'p', embed: 'e', prf: 'r', pub: 'u' };
const WK_BACK = { p: 'pass', e: 'embed', r: 'prf', u: 'pub' };

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
    const c = { k: WK[w.k], c: w.ct };
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

function expandCompact(c) {
  const env = { v: COMPACT_VERSION, t: c.t, meta: {}, wrap: [], payload: { ct: c.p.c } };
  if (c.m) {
    if (c.m.h != null) env.meta.host = c.m.h;
    if (c.m.e != null) env.meta.exp = c.m.e;
    if (c.m.n != null) env.meta.note = c.m.n;
    if (c.m.z != null) env.meta.time = { salt: c.m.z.s, n: c.m.z.n };
    if (c.m.g != null) env.meta.sig = c.m.g.map((s) => ({ alg: s.a, name: s.na, pk: s.k, sig: s.s }));
  }
  for (const w of c.w || []) {
    const e = { k: WK_BACK[w.k], ct: w.c };
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

export async function encodeEnvelope(env, opts = {}) {
  const json = toBytes(JSON.stringify(opts.legacy ? env : compactEnvelope(env)));
  const { flag, bytes } = await deflateMaybe(json);
  const prefix = opts.legacy ? PREFIX : COMPACT_PREFIX;
  return prefix + bytesToB64u(concatBytes(new Uint8Array([flag]), bytes));
}

export async function decodeEnvelope(str) {
  if (str.startsWith(COMPACT_PREFIX)) {
    str = str.slice(COMPACT_PREFIX.length);
    const raw = b64uToBytes(str);
    const flag = raw[0];
    const bytes = await inflateMaybe(flag, raw.subarray(1));
    const env = expandCompact(JSON.parse(toStr(bytes)));
    if (env.v !== COMPACT_VERSION) throw new SealError(`unsupported envelope version: ${env.v}`);
    return env;
  }
  if (str.startsWith(PREFIX)) str = str.slice(PREFIX.length);
  const raw = b64uToBytes(str);
  const flag = raw[0];
  const bytes = await inflateMaybe(flag, raw.subarray(1));
  const env = JSON.parse(toStr(bytes));
  if (env.v !== VERSION) throw new SealError(`unsupported envelope version: ${env.v}`);
  return env;
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
    out.ct = w.ct;
  } else if (w.k === 'prf') {
    out.cid = w.cid;
    out.s = w.s;
    out.ct = w.ct;
  } else if (w.k === 'pub') {
    out.alg = w.alg ?? 'hybrid-x25519-mlkem768';
    out.x = w.x;
    out.m = w.m;
    out.ct = w.ct;
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
    return { k: c.k, kd: { algo: kdf.algo, m: kdf.m, t: kdf.t, p: kdf.p, i: kdf.i, hash: kdf.hash }, s: bytesToB64u(s), ct: bytesToB64u(await aesEncrypt(key, keyBytes)) };
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
      ct: bytesToB64u(await aesEncrypt(key, keyBytes)),
    };
  }
  throw new SealError(`unknown credential kind: ${c.k}`);
}

async function tryUnwrap(w, creds) {
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
          bytes = await aesDecrypt(key, b64uToBytes(w.ct));
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
      bytes = await aesDecrypt(key, b64uToBytes(w.ct));
    }
    return bytes ? { x: w.xi ?? 0, bytes } : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------- passkeys

function webauthnOk() {
  return (
    typeof navigator !== 'undefined' &&
    navigator.credentials &&
    typeof globalThis.PublicKeyCredential !== 'undefined'
  );
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
  const ext = cred.getClientExtensionResults();
  const first = ext?.prf?.results?.first;
  if (!first) throw new SealError('this authenticator does not support the PRF extension');
  return { first: new Uint8Array(first), credentialId: new Uint8Array(cred.rawId) };
}

async function assertPasskey(w) {
  if (!webauthnOk()) throw new SealError('passkeys need a modern browser');
  const salt = b64uToBytes(w.s);
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32).buffer,
      allowCredentials: [{ id: b64uToBytes(w.cid).buffer, type: 'public-key' }],
    },
    extensions: { prf: { eval: { first: salt.buffer } } },
  });
  const ext = cred.getClientExtensionResults();
  const first = ext?.prf?.results?.first;
  if (!first) throw new SealError('authenticator returned no PRF result');
  return new Uint8Array(first);
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
  if (expiry) meta.exp = new Date(expiry).toISOString();
  if (note) meta.note = String(note);
  if (timeLock) meta.time = { salt: timeLock.saltB64 ?? bytesToB64u(timeLock.salt), n: timeLock.n };

  const env = { v: VERSION, t: type, meta, wrap: [], payload: {} };
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
  env.payload = { ct: bytesToB64u(await aesEncrypt(key, toBytes(String(data)))) };
  if (signer) await signEnvelope(env, signer, { pq });
  return env;
}

// ---------------------------------------------------------------- open

// creds: { password?, embeddedPassword?, privateKeys? (keypair JSON), prfAssertion?: fn(w)=>bytes }
// Returns { type, data, meta, env }. Throws SealError with a friendly message.
export async function open(str, creds = {}) {
  const env = await decodeEnvelope(str);
  const fragments = [];
  if (env.thr) {
    // One credential may satisfy several wrappers that share it; each share
    // (xi) may only count once toward the threshold.
    const seen = new Set();
    for (const w of env.wrap) {
      const f = await tryUnwrap(w, creds);
      if (f && !seen.has(f.x)) {
        seen.add(f.x);
        fragments.push(f);
      }
    }
  } else {
    for (const w of env.wrap) {
      const f = await tryUnwrap(w, creds);
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

  if (env.meta?.time) K = await hashChain(K, b64uToBytes(env.meta.time.salt), env.meta.time.n);

  const key = await importAesKey(K);
  const data = toStr(await aesDecrypt(key, b64uToBytes(env.payload.ct)));
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
