// Worker route tests: premium mode must accept every envelope generation
// the sealer emits (s3. legacy → s6. current), and the KV contract
// (conflict, fetch counter, burn-after-read) must hold.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../site/worker.js';

function mockKV() {
  const m = new Map();
  return {
    get: async (k, type) => {
      if (!m.has(k)) return null;
      const v = m.get(k);
      return type === 'json' ? JSON.parse(v) : v;
    },
    put: async (k, v) => m.set(k, v),
    delete: async (k) => m.delete(k),
  };
}

const post = (env, body) =>
  worker.fetch(new Request('https://x.test/api/link', { method: 'POST', body: JSON.stringify(body) }), env);

test('premium create accepts every envelope generation (s3.–s6.)', async () => {
  const env = { PREMIUM: 'true', SEAL_KV: mockKV() };
  for (const prefix of ['s3.', 's4.', 's5.', 's6.']) {
    const res = await post(env, { envelope: prefix + 'AAAA' });
    assert.equal(res.status, 201, `${prefix} envelope must be accepted`);
    const body = await res.json();
    assert.match(body.url, /^https:\/\/x\.test\/s\//);
  }
  // non-envelope payloads are still rejected
  const bad = await post(env, { envelope: 'u1.AAAA' });
  assert.equal(bad.status, 400);
});

test('premium: embedded-password tails are never stored', async () => {
  // s6.<env>.<password> would put a plaintext password in KV — the exact
  // property the product exists to avoid. The dot after the prefix marks it.
  const env = { PREMIUM: 'true', SEAL_KV: mockKV() };
  const res = await post(env, { envelope: 's6.AAAA.hunter2' });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /embedded-password tail/);
});

test('premium: short-redirect mode requires ALLOW_REDIRECTS', async () => {
  const env = { PREMIUM: 'true', SEAL_KV: mockKV() };
  // gated off by default — an open redirector is a phishing amplifier
  const denied = await post(env, { url: 'https://example.com' });
  assert.equal(denied.status, 403);
  const badUrl = await post(env, { url: 'javascript:alert(1)' });
  assert.equal(badUrl.status, 403); // gate runs before scheme validation

  const on = { PREMIUM: 'true', ALLOW_REDIRECTS: 'true', SEAL_KV: mockKV() };
  const ok = await post(on, { url: 'https://example.com/x' });
  assert.equal(ok.status, 201);
  const js = await post(on, { url: 'javascript:alert(1)' });
  assert.equal(js.status, 400); // still not http(s)
  const f = await worker.fetch(new Request('https://x.test/api/link/' + (await ok.json()).slug), on);
  assert.equal(f.status, 200);
  assert.equal((await f.json()).redirect, 'https://example.com/x');
});

test('premium: input validation (bad exp, bad slug, oversize body, embedded tail)', async () => {
  const env = { PREMIUM: 'true', SEAL_KV: mockKV() };
  const badExp = await post(env, { envelope: 's6.AAAA', exp: 'not-a-date' });
  assert.equal(badExp.status, 400);
  const goodExp = await post(env, { envelope: 's6.BBBB', exp: '2999-01-01' });
  assert.equal(goodExp.status, 201);
  const badSlug = await post(env, { slug: 'X', envelope: 's6.CCCC' });
  assert.equal(badSlug.status, 400); // uppercase not allowed
  const numSlug = await post(env, { slug: 12345, envelope: 's6.DDDD' });
  assert.equal(numSlug.status, 400); // non-string slug
  const huge = await worker.fetch(
    new Request('https://x.test/api/link', { method: 'POST', body: 'x'.repeat(25000) }),
    env
  );
  assert.equal(huge.status, 413);
});

test('premium: API responses are never cached', async () => {
  const env = { PREMIUM: 'true', SEAL_KV: mockKV() };
  const r = await post(env, { slug: 'nocache', envelope: 's6.EEEE', burn: true });
  assert.equal(r.headers.get('cache-control'), 'no-store');
  const f = await worker.fetch(new Request('https://x.test/api/link/nocache'), env);
  assert.equal(f.headers.get('cache-control'), 'no-store');
  // burn deleted BOTH keys — no orphaned meta row
  const kv = env.SEAL_KV;
  assert.equal(await kv.get('link:nocache'), null);
  assert.equal(await kv.get('meta:nocache'), null);
});

test('mutating API calls reject foreign origins', async () => {
  const env = { PREMIUM: 'true', SEAL_KV: mockKV() };
  const res = await worker.fetch(
    new Request('https://x.test/api/link', {
      method: 'POST',
      headers: { origin: 'https://evil.example' },
      body: JSON.stringify({ envelope: 's6.AAAA' }),
    }),
    env
  );
  assert.equal(res.status, 403);
  // same-origin works
  const ok = await worker.fetch(
    new Request('https://x.test/api/link', {
      method: 'POST',
      headers: { origin: 'https://x.test' },
      body: JSON.stringify({ envelope: 's6.AAAA' }),
    }),
    env
  );
  assert.equal(ok.status, 201);
});

test('slack: signature verification, freshness window, NaN timestamp', async () => {
  const env = { SLACK_SIGNING_SECRET: 'test-secret', PUBLIC_HOST: 'https://seal.test' };
  const post2 = async (body, ts, sig) =>
    worker.fetch(
      new Request('https://x.test/api/slack', {
        method: 'POST',
        headers: { 'x-slack-signature': sig, 'x-slack-request-timestamp': ts },
        body,
      }),
      env
    );
  const hmac = async (ts, body) => {
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode('test-secret'),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = new Uint8Array(
      await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`v0:${ts}:${body}`))
    );
    return 'v0=' + [...sig].map((b) => b.toString(16).padStart(2, '0')).join('');
  };

  const body = 'command=%2Fseal&text=' + encodeURIComponent('<https://example.com/secret|example.com>');
  const ts = String(Math.floor(Date.now() / 1000));
  const good = await post2(body, ts, await hmac(ts, body));
  assert.equal(good.status, 200);
  const reply = await good.json();
  assert.match(reply.text, /#prefill=https%3A%2F%2Fexample\.com%2Fsecret/); // no < or |label>

  const badSig = await post2(body, ts, 'v0=' + '0'.repeat(64));
  assert.equal(badSig.status, 401);
  const stale = await post2(body, String(Math.floor(Date.now() / 1000) - 1000), 'v0=00');
  assert.equal(stale.status, 401);
  const nan = await post2(body, 'not-a-number', 'v0=' + '0'.repeat(64));
  assert.equal(nan.status, 401); // NaN must not skip the freshness check

  const unconfigured = await worker.fetch(
    new Request('https://x.test/api/slack', { method: 'POST', body: 'x' }),
    {}
  );
  assert.equal(unconfigured.status, 503);
});

test('worker errors become JSON 500s, not HTML', async () => {
  const env = {
    PREMIUM: 'true',
    SEAL_KV: { get: async () => { throw new Error('kv exploded'); }, put: async () => {}, delete: async () => {} },
  };
  const res = await worker.fetch(new Request('https://x.test/api/link/abc'), env);
  assert.equal(res.status, 500);
  assert.equal(res.headers.get('content-type'), 'application/json; charset=utf-8');
  assert.deepEqual(await res.json(), { error: 'internal error' });
});

test('health endpoint advertises capabilities', async () => {
  const res = await worker.fetch(new Request('https://x.test/api/health'), { PREMIUM: 'false' });
  const body = await res.json();
  assert.deepEqual(body, { ok: true, stateless: true, premium: false, redirects: false });
});

test('premium: slug conflicts, fetch counting, burn-after-read', async () => {
  const env = { PREMIUM: 'true', SEAL_KV: mockKV() };
  const r1 = await post(env, { slug: 'taken', envelope: 's6.AAAA' });
  assert.equal(r1.status, 201);
  const r2 = await post(env, { slug: 'taken', envelope: 's6.BBBB' });
  assert.equal(r2.status, 409);

  await post(env, { slug: 'burnt', envelope: 's6.CCCC', burn: true });
  const f1 = await worker.fetch(new Request('https://x.test/api/link/burnt'), env);
  assert.equal(f1.status, 200);
  assert.equal((await f1.json()).meta.fetches, 1);
  const f2 = await worker.fetch(new Request('https://x.test/api/link/burnt'), env);
  assert.equal(f2.status, 410); // burn-after-read: gone

  const gone = await worker.fetch(new Request('https://x.test/api/link/never-existed'), env);
  assert.equal(gone.status, 410);
});

test('premium disabled without PREMIUM=true', async () => {
  const res = await worker.fetch(
    new Request('https://x.test/api/link', { method: 'POST', body: '{}' }),
    { PREMIUM: 'false' }
  );
  assert.equal(res.status, 404);
});
