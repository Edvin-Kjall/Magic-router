// Magic Router worker — deliberately almost empty.
//
// Stateless mode (default): the worker serves the static site from the
// ASSETS binding and answers three tiny API routes. It stores nothing:
// no KV, no D1, no Durable Objects, no logs of link data. Sealed links
// live entirely in their own URL; the fragment never reaches this code.
//
// Premium mode (optional, PREMIUM="true" + SEAL_KV binding): stores ONLY
// ciphertext envelopes server-side to add burn-after-read, expiry
// enforcement and fetch counters. The server still never sees a password
// or a destination. See docs/PREMIUM.md.

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  // API responses must never be cached — a burned or expired link served
  // from a cache would silently defeat both, and skew the fetch counter.
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
};

const json = (body, status = 200) => Response.json(body, { status, headers: JSON_HEADERS });

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (e) {
      console.error(
        JSON.stringify({ message: 'request failed', path: new URL(request.url).pathname, error: String(e?.message ?? e) })
      );
      return json({ error: 'internal error' }, 500);
    }
  },
};

async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === 'GET' && path === '/api/prove') return prove(request);
  if (request.method === 'GET' && path === '/api/health') {
    return json({
      ok: true,
      stateless: true,
      premium: env.PREMIUM === 'true',
      redirects: env.ALLOW_REDIRECTS === 'true',
    });
  }

  // Mutating API calls from a *different* web origin are never legitimate —
  // the API is same-origin only. (Slack and the CLI send no Origin header;
  // browsers always send one on cross-site POSTs.)
  if (path.startsWith('/api/') && request.method !== 'GET' && request.method !== 'HEAD') {
    const origin = request.headers.get('origin');
    if (origin && origin !== url.origin) {
      return json({ error: 'cross-origin requests are not allowed' }, 403);
    }
  }

  if (request.method === 'POST' && path === '/api/slack') return slack(request, env, url);
  if (path.startsWith('/api/link')) return premiumRoute(request, env, url, path);

  // Everything else: static assets (site/public), with SPA fallback so
  // /_u/... and /s/... deep links load index.html.
  return env.ASSETS.fetch(request);
}

// ------------------------------------------------------------- prove

// Returns exactly what this request looked like to the server. The point:
// whatever the client sealed is NOT in here — fragments are never sent.
function prove(request) {
  const url = new URL(request.url);
  const wanted = [
    'user-agent',
    'accept-language',
    'sec-fetch-mode',
    'sec-fetch-dest',
    'referer',
    'cf-connecting-ip',
    'cf-ipcountry',
    'cf-ray',
  ];
  const headers = {};
  for (const h of wanted) {
    const v = request.headers.get(h);
    if (v != null) headers[h] = v;
  }
  return json(
    {
      what_the_server_saw: {
        method: request.method,
        path: url.pathname,
        query: url.search || '(none)',
        fragment: '(never transmitted by browsers — your sealed data lives here, and this server will never see it)',
        headers,
      },
      conclusion:
        'The server saw this page request and nothing else. No ciphertext, no password, no destination.',
    }
  );
}

// ------------------------------------------------------------- slack

async function slack(request, env, url) {
  if (!env.SLACK_SIGNING_SECRET) {
    return json({ error: 'Slack is not configured on this instance' }, 503);
  }
  const body = await request.text();
  if (body.length > 16 * 1024) return new Response('body too large', { status: 413 });
  const sig = request.headers.get('x-slack-signature');
  const ts = request.headers.get('x-slack-request-timestamp');
  if (!sig || !ts) return new Response('bad request', { status: 400 });
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum) || Math.abs(Date.now() / 1000 - tsNum) > 300) {
    return new Response('stale request', { status: 401 });
  }
  const expected = 'v0=' + (await hmacHex(env.SLACK_SIGNING_SECRET, `v0:${ts}:${body}`));
  if (!secureCompare(sig, expected)) return new Response('bad signature', { status: 401 });

  const text = new URLSearchParams(body).get('text') || '';
  // Slack wraps links as <https://x|label> — match the URL without the
  // bracket/label furniture.
  let target = text.match(/https?:\/\/[^\s>|]+/i)?.[0] || text.trim();
  target = target.replace(/^</, '').replace(/>$/, '');
  const origin = env.PUBLIC_HOST || url.origin;
  // #prefill= keeps the destination out of the request the browser sends.
  return json({
    response_type: 'ephemeral',
    text: target
      ? `Seal that link: ${origin}/#prefill=${encodeURIComponent(target)}`
      : `Open the sealer: ${origin}/`,
  });
}

async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)));
  return [...sig].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function secureCompare(a, b) {
  const ab = new TextEncoder().encode(a);
  const bb = new TextEncoder().encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

// ------------------------------------------------------------ premium

const SLUG_RE = /^[a-z0-9_-]{3,64}$/;
const MAX_BODY = 24 * 1024;

async function premiumRoute(request, env, url, path) {
  if (env.PREMIUM !== 'true') {
    return json(
      { error: 'premium mode is not enabled on this instance — use fragment or /_u/ links instead' },
      404
    );
  }
  if (!env.SEAL_KV) {
    return json({ error: 'premium mode needs the SEAL_KV binding (see docs/PREMIUM.md)' }, 503);
  }
  const m = path.match(/^\/api\/link\/([a-z0-9_-]{3,64})$/);
  if (request.method === 'POST' && path === '/api/link') return premiumCreate(request, env, url);
  if (request.method === 'GET' && m) return premiumFetch(env, m[1]);
  if (request.method === 'DELETE' && m) return premiumDelete(env, m[1]);
  return json({ error: 'not found' }, 404);
}

async function premiumCreate(request, env, url) {
  const raw = await request.text();
  if (raw.length > MAX_BODY) return json({ error: 'body too large (max 24 KiB)' }, 413);
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    return json({ error: 'JSON body required' }, 400);
  }
  if (body == null || typeof body !== 'object') return json({ error: 'JSON object required' }, 400);
  const slug = body.slug ?? randomSlug();
  if (typeof slug !== 'string' || !SLUG_RE.test(slug)) {
    return json({ error: 'slug must be 3-64 chars of a-z0-9_-' }, 400);
  }

  // Short mode: plaintext redirect (no encryption — the caller's explicit
  // choice, and gated behind ALLOW_REDIRECTS because an unauthenticated
  // open redirector on your domain is a phishing amplifier).
  const redirect = typeof body.url === 'string' ? body.url : null;
  if (redirect != null) {
    if (env.ALLOW_REDIRECTS !== 'true') {
      return json({ error: 'short redirect mode is disabled — set ALLOW_REDIRECTS = "true" to enable it' }, 403);
    }
    if (!/^https?:\/\//i.test(redirect)) {
      return json({ error: 'url must start with http:// or https://' }, 400);
    }
    if (redirect.length > 2048) return json({ error: 'url too long (max 2048 chars)' }, 400);
  }

  let envelope = String(body.envelope ?? '');
  if (redirect) envelope = '';
  // s3./s4. are legacy encodings; the sealer has emitted s5./s6. since v5.
  if (!redirect && !/^s[3-6]\./.test(envelope)) {
    return json({ error: 'provide either url (short mode) or an s3.–s6. envelope' }, 400);
  }
  if (envelope.length > 16384) {
    return json({ error: 'envelope must be ≤16 KiB' }, 400);
  }
  // An embedded-password tail (s6.<env>.<password>) must never be stored:
  // the server holding it would hold a plaintext password — the exact
  // property this product exists to avoid.
  if (envelope.indexOf('.', 3) !== -1) {
    return json({ error: 'envelope must not carry an embedded-password tail' }, 400);
  }
  let exp = null;
  if (body.exp != null) {
    const t = Date.parse(body.exp);
    if (!Number.isFinite(t)) return json({ error: 'exp must be a parseable date' }, 400);
    exp = new Date(t).toISOString();
  }
  if (await env.SEAL_KV.get('link:' + slug)) {
    return json({ error: 'slug already taken' }, 409);
  }
  const row = {
    envelope,
    redirect,
    burn: body.burn === true,
    exp,
    created: Date.now(),
  };
  await env.SEAL_KV.put('link:' + slug, JSON.stringify(row));
  await env.SEAL_KV.put('meta:' + slug, JSON.stringify({ fetches: 0 }));
  return json({ slug, url: `${env.PUBLIC_HOST || url.origin}/s/${slug}` }, 201);
}

async function premiumFetch(env, slug) {
  const raw = await env.SEAL_KV.get('link:' + slug, 'json');
  if (!raw) return json({ error: 'gone' }, 410);
  if (raw.exp && Date.now() > Date.parse(raw.exp)) {
    await env.SEAL_KV.delete('link:' + slug);
    await env.SEAL_KV.delete('meta:' + slug);
    return json({ error: 'expired' }, 410);
  }
  const meta = (await env.SEAL_KV.get('meta:' + slug, 'json')) ?? { fetches: 0 };
  meta.fetches = (meta.fetches || 0) + 1;
  await env.SEAL_KV.put('meta:' + slug, JSON.stringify(meta));
  // Burn-after-read: delete before responding. Honest caveat: a client that
  // already fetched it once can still decrypt offline — see docs/PREMIUM.md.
  if (raw.burn) {
    await env.SEAL_KV.delete('link:' + slug);
    await env.SEAL_KV.delete('meta:' + slug);
  }
  const metaOut = { fetches: meta.fetches, burnt: raw.burn === true, exp: raw.exp };
  return json(raw.redirect ? { redirect: raw.redirect, meta: metaOut } : { envelope: raw.envelope, meta: metaOut });
}

async function premiumDelete(env, slug) {
  const existed = (await env.SEAL_KV.get('link:' + slug)) !== null;
  if (existed) {
    await env.SEAL_KV.delete('link:' + slug);
    await env.SEAL_KV.delete('meta:' + slug);
  }
  return json({ revoked: existed });
}

function randomSlug() {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'; // no 0/O/1/l/I confusion
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let out = '';
  for (const b of bytes) out += alphabet[b % alphabet.length];
  return out;
}
