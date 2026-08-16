// Core envelope tests: round trips for every unlock method, tamper
// detection, thresholds, time-lock, signatures, legacy links.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';

import { bytesToB64u, b64uToBytes, randomBytes, concatBytes } from '../site/public/lib/b64.mjs';
import { ARGON2ID_FAST } from '../site/public/lib/kd.mjs';
import { deriveKey } from '../site/public/lib/kd.mjs';
import { aesEncrypt } from '../site/public/lib/aes.mjs';
import { splitSecret, combineShares } from '../site/public/lib/shamir.mjs';
import {
  seal,
  open,
  openLegacy,
  encodeEnvelope,
  decodeEnvelope,
  splitEmbedded,
  generateRecipientKeypair,
  generateSignerIdentity,
  signEnvelope,
  verifySignatures,
  makeTimeLock,
  isSealedLink,
} from '../site/public/lib/envelope.mjs';

const KDF = ARGON2ID_FAST;
const URL = 'https://example.com/very/secret/path?token=abc123';

test('b64u roundtrip', () => {
  const bytes = randomBytes(64);
  assert.deepEqual(b64uToBytes(bytesToB64u(bytes)), bytes);
  assert.ok(!bytesToB64u(bytes).includes('.'));
});

test('shamir: any 2 of 3 reconstruct, wrong combos fail', () => {
  const secret = randomBytes(32);
  const shares = splitSecret(secret, 3, 2);
  assert.equal(shares.length, 3);
  assert.deepEqual(combineShares([shares[0], shares[1]], 32), secret);
  assert.deepEqual(combineShares([shares[1], shares[2]], 32), secret);
  assert.deepEqual(combineShares([shares[0], shares[2]], 32), secret);
  assert.deepEqual(combineShares([shares[0], shares[1], shares[2]], 32), secret);
  assert.throws(() => combineShares([shares[0]], 32)); // 1 share cannot combine
  assert.throws(() => splitSecret(secret, 3, 1));
  assert.throws(() => splitSecret(secret, 3, 4));
});

test('password seal → open roundtrip', async () => {
  const env = await seal({ type: 'url', data: URL, passwords: ['correct horse'], kdf: KDF });
  const str = await encodeEnvelope(env);
  assert.ok(isSealedLink(str));
  const r = await open(str, { password: 'correct horse' });
  assert.equal(r.type, 'url');
  assert.equal(r.data, URL);
  assert.equal(r.meta.host, 'example.com');
  await assert.rejects(open(str, { password: 'wrong' }));
});

test('tampering with ciphertext is detected', async () => {
  const env = await seal({ type: 'text', data: 'top secret', passwords: ['pw'], kdf: KDF });
  const parsed = await decodeEnvelope(await encodeEnvelope(env));
  const ct = b64uToBytes(parsed.payload.ct);
  ct[ct.length - 1] ^= 1;
  parsed.payload.ct = bytesToB64u(ct);
  await assert.rejects(open(await encodeEnvelope(parsed), { password: 'pw' }));
});

test('embedded password: auto-open via link tail', async () => {
  const env = await seal({ type: 'url', data: URL, embedded: 'hunter2', kdf: KDF });
  const str = await encodeEnvelope(env);
  const full = `${str}.hunter2`;
  const { env: envStr, tail } = splitEmbedded(full);
  assert.equal(tail, 'hunter2');
  const r = await open(envStr, { embeddedPassword: tail });
  assert.equal(r.data, URL);
  // wrong embedded password fails
  await assert.rejects(open(envStr, { embeddedPassword: 'nope' }));
});

test('text payload (secrets, not URLs)', async () => {
  const env = await seal({ type: 'text', data: 'API_KEY_123456', passwords: ['pw'], kdf: KDF });
  const r = await open(await encodeEnvelope(env), { password: 'pw' });
  assert.equal(r.type, 'text');
  assert.equal(r.data, 'API_KEY_123456');
});

test('recipient keypair (hybrid X25519 + ML-KEM-768) roundtrip', async () => {
  const kp = await generateRecipientKeypair();
  const env = await seal({ type: 'url', data: URL, recipient: kp, kdf: KDF });
  const str = await encodeEnvelope(env);
  // wrong keypair fails
  const kp2 = await generateRecipientKeypair();
  await assert.rejects(open(str, { privateKeys: kp2 }));
  // right keypair works
  const r = await open(str, { privateKeys: kp });
  assert.equal(r.data, URL);
});

test('threshold 2-of-3: password + keypair', async () => {
  const kp = await generateRecipientKeypair();
  const env = await seal({
    type: 'url',
    data: URL,
    passwords: ['alpha'],
    embedded: 'beta',
    recipient: kp,
    threshold: 2,
    kdf: KDF,
  });
  assert.equal(env.thr.n, 3);
  assert.equal(env.thr.m, 2);
  const str = await encodeEnvelope(env);

  // 1 credential is not enough
  await assert.rejects(open(str, { password: 'alpha' }));
  await assert.rejects(open(str, { privateKeys: kp }));

  // any 2 of 3 work
  const a = await open(str, { password: 'alpha', privateKeys: kp });
  assert.equal(a.data, URL);
  const b = await open(str, { password: 'alpha', embeddedPassword: 'beta' });
  assert.equal(b.data, URL);
  const c = await open(str, { embeddedPassword: 'beta', privateKeys: kp });
  assert.equal(c.data, URL);
});

test('threshold 1-of-n: any single credential', async () => {
  const env = await seal({ type: 'url', data: URL, passwords: ['one'], embedded: 'two', threshold: 1, kdf: KDF });
  const str = await encodeEnvelope(env);
  const a = await open(str, { password: 'one' });
  assert.equal(a.data, URL);
  const b = await open(str, { embeddedPassword: 'two' });
  assert.equal(b.data, URL);
});

test('time-lock: key only appears after the grind', async () => {
  const saltB64 = bytesToB64u(randomBytes(16));
  const env = await seal({
    type: 'url',
    data: URL,
    passwords: ['pw'],
    timeLock: { saltB64, n: 5000 },
    kdf: KDF,
  });
  const str = await encodeEnvelope(env);
  const t0 = performance.now();
  const r = await open(str, { password: 'pw' });
  const dt = performance.now() - t0;
  assert.equal(r.data, URL);
  assert.ok(dt > 5, `time-lock should cost time, took ${dt}ms`);
});

test('makeTimeLock sanity', async () => {
  const tl = await makeTimeLock(5000, 1_000_000);
  assert.equal(tl.n, 5_000_000); // 5s at 1M hashes/s
});

test('signed seals verify; tampered payload invalidates', async () => {
  const id = await generateSignerIdentity('alice');
  const env = await seal({ type: 'url', data: URL, passwords: ['pw'], kdf: KDF, signer: id });
  const str = await encodeEnvelope(env);
  const parsed = await decodeEnvelope(str);
  const results = await verifySignatures(parsed);
  assert.equal(results.length >= 1, true);
  assert.ok(results.every((r) => r.ok));
  assert.equal(results[0].name, 'alice');

  // tamper with payload: signatures must fail
  const ct = b64uToBytes(parsed.payload.ct);
  ct[5] ^= 1;
  parsed.payload.ct = bytesToB64u(ct);
  const bad = await verifySignatures(parsed);
  assert.ok(bad.some((r) => r.ok === false));

  // tamper with meta (note): must also fail
  const parsed2 = await decodeEnvelope(str);
  parsed2.meta.note = 'forged';
  const bad2 = await verifySignatures(parsed2);
  assert.ok(bad2.some((r) => r.ok === false));
});

test('legacy v2 links (argon2id, deflate-compressed) still open', async () => {
  const salt = randomBytes(16);
  const key = await deriveKey({ algo: 'argon2id', m: 65536, t: 3, p: 1, s: bytesToB64u(salt) }, 'legacy-pw');
  const pt = zlib.deflateRawSync(Buffer.from(URL, 'utf8'));
  const sealed = await aesEncrypt(key, pt); // iv (12) || ct
  const iv = sealed.subarray(0, 12);
  const ct = sealed.subarray(12);
  const blob = `v2.${bytesToB64u(salt)}.${bytesToB64u(iv)}.${bytesToB64u(ct)}`;
  const r = await openLegacy(blob, 'legacy-pw');
  assert.equal(r.data, URL);
  assert.equal(r.type, 'url');
  await assert.rejects(openLegacy(blob, 'wrong'));
});

test('envelope links stay reasonable in size', async () => {
  // Node has no CompressionStream, so links are uncompressed here; browsers
  // deflate the envelope and produce much shorter links.
  const env = await seal({ type: 'url', data: 'https://example.com/a', passwords: ['pw'], kdf: KDF });
  const str = await encodeEnvelope(env);
  assert.ok(str.length < 500, `link too long: ${str.length}`);
});
