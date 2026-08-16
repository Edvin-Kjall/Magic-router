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

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8' };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'GET' && path === '/api/prove') return prove(request);
    if (request.method === 'GET' && path === '/api/health') {
      return Response.json({ ok: true, stateless: true, premium: env.PREMIUM === 'true' });
    }
    if (request.method === 'POST' && path === '/api/slack') return slack(request, env, url);
    if (path.startsWith('/api/link')) return premiumRoute(request, env, url, path);

    // Everything else: static assets (site/public), with SPA fallback so
    // /_u/... and /s/... deep links load index.html.
    return env.ASSETS.fetch(request);
  },
};

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
  return Response.json(
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
    },
    { headers: JSON_HEADERS }
  );
}

// ------------------------------------------------------------- slack

async function slack(request, env, url) {
  if (!env.SLACK_SIGNING_SECRET) {
    return Response.json({ error: 'Slack is not configured on this instance' }, { status: 503, headers: JSON_HEADERS });
  }
  const body = await request.text();
  const sig = request.headers.get('x-slack-signature');
  const ts = request.headers.get('x-slack-request-timestamp');
  if (!sig || !ts) return new Response('bad request', { status: 400 });
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return new Response('stale request', { status: 401 });
  const expected = 'v0=' + (await hmacHex(env.SLACK_SIGNING_SECRET, `v0:${ts}:${body}`));
  if (!secureCompare(sig, expected)) return new Response('bad signature', { status: 401 });

  const text = new URLSearchParams(body).get('text') || '';
  const target = text.match(/https?:\/\/\S+/i)?.[0] || text.trim();
  const origin = env.PUBLIC_HOST || url.origin;
  return Response.json({
    response_type: 'ephemeral',
    text: target
      ? `Seal that link: ${origin}/?url=${encodeURIComponent(target)}`
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

async function premiumRoute(request, env, url, path) {
  if (env.PREMIUM !== 'true') {
    return Response.json(
      { error: 'premium mode is not enabled on this instance — use fragment or /_u/ links instead' },
      { status: 404, headers: JSON_HEADERS }
    );
  }
  if (!env.SEAL_KV) {
    return Response.json({ error: 'premium mode needs the SEAL_KV binding (see docs/PREMIUM.md)' }, { status: 503, headers: JSON_HEADERS });
  }
  const m = path.match(/^\/api\/link\/([a-z0-9_-]+)$/);
  if (request.method === 'POST' && path === '/api/link') return premiumCreate(request, env, url);
  if (request.method === 'GET' && m) return premiumFetch(env, m[1]);
  if (request.method === 'DELETE' && m) return premiumDelete(env, m[1]);
  return Response.json({ error: 'not found' }, { status: 404, headers: JSON_HEADERS });
}

async function premiumCreate(request, env, url) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'JSON body required' }, { status: 400, headers: JSON_HEADERS });
  }
  const slug = body.slug ?? randomSlug();
  if (!SLUG_RE.test(slug)) return Response.json({ error: 'slug must be 3-64 chars of a-z0-9_-' }, { status: 400, headers: JSON_HEADERS });
  const envelope = String(body.envelope ?? '');
  if (!envelope.startsWith('s3.') || envelope.length > 16384) {
    return Response.json({ error: 'envelope must be an s3. link (≤16 KiB)' }, { status: 400, headers: JSON_HEADERS });
  }
  if (await env.SEAL_KV.get('link:' + slug)) {
    return Response.json({ error: 'slug already taken' }, { status: 409, headers: JSON_HEADERS });
  }
  const row = {
    envelope,
    burn: body.burn === true,
    exp: body.exp ? new Date(body.exp).toISOString() : null,
    created: Date.now(),
  };
  await env.SEAL_KV.put('link:' + slug, JSON.stringify(row));
  await env.SEAL_KV.put('meta:' + slug, JSON.stringify({ fetches: 0 }));
  return Response.json(
    { slug, url: `${env.PUBLIC_HOST || url.origin}/s/${slug}` },
    { status: 201, headers: JSON_HEADERS }
  );
}

async function premiumFetch(env, slug) {
  const raw = await env.SEAL_KV.get('link:' + slug, 'json');
  if (!raw) return Response.json({ error: 'gone' }, { status: 410, headers: JSON_HEADERS });
  if (raw.exp && Date.now() > Date.parse(raw.exp)) {
    await env.SEAL_KV.delete('link:' + slug);
    return Response.json({ error: 'expired' }, { status: 410, headers: JSON_HEADERS });
  }
  const meta = (await env.SEAL_KV.get('meta:' + slug, 'json')) ?? { fetches: 0 };
  meta.fetches = (meta.fetches || 0) + 1;
  await env.SEAL_KV.put('meta:' + slug, JSON.stringify(meta));
  // Burn-after-read: delete before responding. Honest caveat: a client that
  // already fetched it once can still decrypt offline — see docs/PREMIUM.md.
  if (raw.burn) await env.SEAL_KV.delete('link:' + slug);
  return Response.json({ envelope: raw.envelope, meta: { fetches: meta.fetches, burnt: raw.burn === true, exp: raw.exp } }, { headers: JSON_HEADERS });
}

async function premiumDelete(env, slug) {
  const existed = (await env.SEAL_KV.get('link:' + slug)) !== null;
  if (existed) {
    await env.SEAL_KV.delete('link:' + slug);
    await env.SEAL_KV.delete('meta:' + slug);
  }
  return Response.json({ revoked: existed }, { headers: JSON_HEADERS });
}

function randomSlug() {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'; // no 0/O/1/l/I confusion
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let out = '';
  for (const b of bytes) out += alphabet[b % alphabet.length];
  return out;
}
