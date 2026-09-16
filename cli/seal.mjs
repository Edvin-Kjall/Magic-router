#!/usr/bin/env node
// seal — command-line sealer for Magic Router links.
//
//   seal create --url https://example.com --password "pw" --host https://seal.example
//   seal create --text "API_KEY" --embed "pw" --delay 2h --sign alice.json
//   seal create --url https://x --password p1 --password p2 --threshold 2
//   seal open <link> --password pw
//   seal open <link> --key seal-key.json
//   seal keygen --recipient            # writes seal-key.json
//   seal keygen --identity alice       # writes seal-identity-alice.json
//   seal info <link>
//   seal passphrase [--words 8]
//
// Same format and crypto as the web app: every link this tool creates opens
// in the browser, and every browser link opens here.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  seal,
  open,
  openLegacy,
  encodeEnvelope,
  decodeEnvelope,
  splitEmbedded,
  extractLinkFragment,
  isPlainLink,
  decodePlainUrl,
  describeEnvelope,
  generateRecipientKeypair,
  generateSignerIdentity,
  verifySignatures,
  makeTimeLock,
  parseDuration,
  expiryStatus,
  SealError,
} from '../site/public/lib/envelope.js';
import { estimateHashRate, formatDuration } from '../site/public/lib/timelock.js';
import { toString as qrTerminal } from 'qrcode';
import { setDeepTokens, setDeepTokensV1 } from '../site/public/lib/dict.js';

const here = dirname(fileURLToPath(import.meta.url));

// Load the deep dictionaries (same ones the page downloads) so CLI links
// are just as small and old u2. links still open. Missing files = shallow.
try {
  setDeepTokens(JSON.parse(readFileSync(join(here, '..', 'site', 'public', 'deep-v2.json'), 'utf8')));
} catch {
  /* shallow dictionary only */
}
try {
  setDeepTokensV1(JSON.parse(readFileSync(join(here, '..', 'site', 'public', 'deep-v1.json'), 'utf8')));
} catch {
  /* no legacy deep dictionary */
}

const HELP = `
Magic Router CLI — stateless encrypted links.

Usage:
  seal create  --url <destination> | --text <secret>
               [--password <pw>]... [--embed <pw>] [--recipient <seal-key.json>]
               [--threshold <m>] [--delay <30s|5m|2h|1d>] [--expires <ISO-date>]
               [--note <text>] [--sign <seal-identity.json>] [--pq] [--preview]
               [--host <origin>] [--path] [--qr] [--json]
               [--store [--slug <s>] [--burn]]

  seal open    <link> [--password <pw>]... [--key <seal-key.json>] [--json]
  seal keygen  --recipient | --identity <name> [--out <file>]
  seal info    <link>
  seal passphrase [--words <n>]

Notes:
  --password may be repeated; each password becomes its own unlock method.
  --embed puts the password in the link itself (auto-open) — the link then
  IS the credential. Treat it accordingly.
  --delay adds a time-lock: sequential SHA-256 grind before the payload
  opens. Honest caveat: client-side delay, bypassable by editing the page.
  --host + --path emit a path-style URL (/_u/...) — the server sees the
  ciphertext but still cannot decrypt it.
  --store posts the envelope to the host's premium API and prints the short
  /s/<slug> URL (server stores ciphertext only; needs PREMIUM on the host).
  --burn makes the hosted envelope self-delete after one fetch.
  open also accepts hosted https://host/s/<slug> links directly.
`.trim();

function fail(msg) {
  // SealError messages already carry a "seal: " prefix — don't double it.
  console.error('seal: ' + String(msg).replace(/^seal:\s*/, ''));
  process.exit(1);
}

// argv scanner: --flag value, --flag=value, --boolflag, repeatable flags.
// A value flag without a value is an error, never a silent `true`.
const BOOL_FLAGS = new Set(['json', 'qr', 'path', 'help', 'pq', 'preview', 'store', 'burn']);
const VALUE_FLAGS = new Set([
  'url', 'text', 'embed', 'recipient', 'threshold', 'delay', 'expires',
  'note', 'sign', 'out', 'host', 'key', 'words', 'identity', 'slug',
]);
const PASSWORD_ALIASES = new Set(['password', 'pw', 'pwd']);

function parseArgs(argv) {
  const out = { _: [], f: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) {
      out._.push(a);
      continue;
    }
    const eq = a.indexOf('=');
    if (eq !== -1) {
      addFlag(out, a.slice(2, eq), a.slice(eq + 1));
      continue;
    }
    const k = a.slice(2);
    if (BOOL_FLAGS.has(k)) {
      addFlag(out, k, true);
      continue;
    }
    if (!PASSWORD_ALIASES.has(k) && !VALUE_FLAGS.has(k)) {
      fail(`unknown option --${k} — try: seal --help`);
    }
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      addFlag(out, k, next);
      i++;
    } else if (k === 'recipient') {
      addFlag(out, k, 'seal-key.json'); // bare --recipient: the default file
    } else {
      fail(`--${k} needs a value${next === undefined ? '' : ` (--${next.slice(2)} follows it)`}`);
    }
  }
  return out;
}

function addFlag(out, k, v) {
  // --password/--pw/--pwd are one repeatable flag; everything else is scalar.
  if (PASSWORD_ALIASES.has(k)) {
    (out.f.password ??= []).push(v);
  } else {
    out.f[k] = v;
  }
}

async function cmdCreate(args) {
  const f = args.f;
  if (f.url && f.text) fail('give either --url or --text, not both');
  const type = f.text ? 'text' : 'url';
  const data = f.text ?? f.url;
  if (!data) fail('create needs --url <destination> or --text <secret>');
  const passwords = (f.password ?? []).map(String);
  const opts = { type, data };
  if (passwords.length) opts.passwords = passwords;
  if (f.embed) opts.embedded = String(f.embed);
  if (f.recipient) {
    opts.recipient = JSON.parse(readFileSync(f.recipient, 'utf8'));
  }
  if (f.threshold != null) {
    const m = Number(f.threshold);
    if (!Number.isInteger(m) || m < 1) fail('--threshold must be a whole number ≥ 1');
    opts.threshold = m;
  }
  if (f.delay) {
    const ms = parseDuration(f.delay);
    const rate = await estimateHashRate();
    opts.timeLock = await makeTimeLock(ms, rate);
  }
  if (f.expires) opts.expiry = f.expires;
  if (f.note) opts.note = String(f.note);
  if (f.sign) opts.signer = JSON.parse(readFileSync(f.sign, 'utf8'));
  if (f.pq) {
    if (!f.sign) fail('--pq only makes sense together with --sign');
    opts.pq = true;
  }
  if (f.preview) opts.preview = true;

  const env = await seal(opts);
  const frag = await encodeEnvelope(env);
  const tail = opts.embedded != null ? '.' + encodeURIComponent(opts.embedded) : '';
  const full = frag + tail;
  const url = f.host ? `${f.host}${f.path ? '/_u/' : '/#'}${full}` : null;

  // Premium: store the ciphertext envelope on the host, get a short
  // /s/<slug> link. The server sees the envelope only — never a password.
  if (f.store || f.slug || f.burn) {
    if (!f.store) fail('--slug/--burn only make sense together with --store');
    if (!f.host) fail('--store needs --host <origin>');
    if (opts.embedded != null) {
      fail('embedded-password links cannot be hosted — the password tail must never reach the server');
    }
    const res = await fetch(f.host.replace(/\/+$/, '') + '/api/link', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        slug: f.slug || undefined,
        envelope: frag,
        burn: f.burn === true || undefined,
        exp: opts.expiry ? new Date(opts.expiry).toISOString() : undefined,
      }),
    });
    const hosted = await res.json().catch(() => ({}));
    if (!res.ok) fail(`store failed: ${hosted.error || `HTTP ${res.status}`}`);
    if (f.json) console.log(JSON.stringify({ fragment: full, url: hosted.url }));
    else {
      console.log('hosted link:');
      console.log('  ' + hosted.url);
    }
    return;
  }

  if (f.json) {
    console.log(JSON.stringify({ fragment: full, url }));
  } else {
    console.log('sealed link:');
    console.log('  ' + (url ?? full));
  }
  if (f.qr) {
    const target = url ?? full;
    const qr = await qrTerminal(target, { type: 'terminal', small: true });
    console.log(qr);
  }
}

// https://host/s/<slug> → fetch the hosted envelope (ciphertext only) from
// the premium API. Redirect rows print the destination straight away.
async function resolveHosted(link) {
  const m = /^(https?:\/\/[^/]+)\/s\/([a-z0-9_-]{3,64})\/?$/i.exec(String(link).trim());
  if (!m) return link;
  const res = await fetch(`${m[1]}/api/link/${m[2]}`);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    fail(res.status === 410 ? `hosted link is gone — ${body.error || 'burned, expired, or never existed'}` : `hosted link fetch failed: ${body.error || `HTTP ${res.status}`}`);
  }
  if (body.redirect) return { redirect: body.redirect, meta: body.meta };
  if (body.meta?.fetches != null) {
    process.stderr.write(
      `hosted link · fetched ${body.meta.fetches}×${body.meta.burnt ? ' · burned after this fetch' : ''}\n`
    );
  }
  return body.envelope;
}

async function cmdOpen(args, link) {
  const f = args.f;
  const resolved = await resolveHosted(link);
  if (resolved && typeof resolved === 'object' && resolved.redirect) {
    if (f.json) console.log(JSON.stringify({ type: 'url', data: resolved.redirect, meta: resolved.meta }));
    else console.log(resolved.redirect);
    return;
  }
  const str = extractLinkFragment(resolved);
  if (isPlainLink(str)) {
    // Plain (unencrypted) short links: no credentials, just decode.
    const url = await decodePlainUrl(str);
    if (f.json) console.log(JSON.stringify({ type: 'url', data: url }));
    else console.log(url);
    return;
  }
  const passwords = (f.password ?? []).map(String);
  const creds = {};
  if (passwords.length === 1) creds.password = passwords[0];
  else if (passwords.length > 1) creds.passwords = passwords;
  if (f.key) creds.privateKeys = JSON.parse(readFileSync(f.key, 'utf8'));

  let r;
  if (/^v[12]\./.test(str)) {
    if (!passwords.length) fail('legacy link needs --password');
    r = await openLegacy(str, passwords[0]);
  } else {
    const { env: envStr, tail } = splitEmbedded(str);
    if (tail) creds.embeddedPassword = tail;
    const env = await decodeEnvelope(envStr);
    if (env.meta?.time) {
      const rate = await estimateHashRate();
      const eta = formatDuration((env.meta.time.n / rate) * 1000);
      process.stderr.write(`time-lock: grinding ${env.meta.time.n} hashes (≈ ${eta})...\n`);
    }
    r = await open(envStr, creds);
  }

  if (f.json) {
    console.log(JSON.stringify(r, null, 2));
  } else {
    console.log(r.data);
  }
}

async function cmdInfo(args, link) {
  const resolved = await resolveHosted(link);
  if (resolved && typeof resolved === 'object' && resolved.redirect) {
    console.log(JSON.stringify({ type: 'redirect', encrypted: false, url: resolved.redirect, meta: resolved.meta }, null, 2));
    return;
  }
  const str = extractLinkFragment(resolved);
  if (isPlainLink(str)) {
    console.log(JSON.stringify({ type: 'plain', encrypted: false, url: await decodePlainUrl(str) }, null, 2));
    return;
  }
  if (/^v[12]\./.test(str)) {
    console.log('legacy link (pre-v3). Upgrade: open it in the web app and reseal.');
    return;
  }
  const env = await decodeEnvelope(str);
  const d = describeEnvelope(env);
  const ex = expiryStatus(env.meta);
  console.log(JSON.stringify(
    {
      type: d.type,
      host: d.host,
      note: d.note,
      expires: ex ? { at: ex.at, expired: ex.expired } : null,
      timeLock: d.time ? { n: d.time.n } : null,
      threshold: d.threshold,
      methods: d.methods,
      signed: d.signed,
      signatures: (await verifySignatures(env)).map((s) => `${s.name}/${s.alg}:${s.ok ? 'ok' : 'BAD'}`),
    },
    null,
    2
  ));
}

async function cmdKeygen(args) {
  if (args.f.recipient) {
    const kp = await generateRecipientKeypair();
    const out = args.f.out ?? 'seal-key.json';
    writeFileSync(out, JSON.stringify(kp, null, 2));
    console.log(`recipient keypair written to ${out} (hybrid X25519 + ML-KEM-768)`);
    console.log('Keep the file private. Anyone sealing TO you needs only the public part;');
    console.log('opening a link needs the whole file.');
  } else if (args.f.identity) {
    const name = String(args.f.identity).replace(/\.json$/, '');
    const id = await generateSignerIdentity(name);
    const out = args.f.out ?? `seal-identity-${name.replace(/\W+/g, '-')}.json`;
    writeFileSync(out, JSON.stringify(id, null, 2));
    console.log(`signer identity "${name}" written to ${out} (Ed25519 + ML-DSA-65)`);
  } else {
    fail('keygen needs --recipient or --identity <name>');
  }
}

async function cmdPassphrase(args) {
  const words = Number(args.f.words ?? 8);
  if (!(words >= 4 && words <= 20)) fail('--words must be between 4 and 20');
  const file = join(here, '..', 'site', 'public', 'data', 'eff-large.txt');
  const list = readFileSync(file, 'utf8')
    .split('\n')
    .map((l) => l.split('\t')[1])
    .filter(Boolean);
  const out = [];
  for (let i = 0; i < words; i++) {
    let idx = 0;
    for (let d = 0; d < 5; d++) {
      const buf = new Uint32Array(1);
      crypto.getRandomValues(buf);
      idx = idx * 6 + Math.floor((buf[0] / 2 ** 32) * 6);
    }
    out.push(list[idx]);
  }
  console.log(out.join(' '));
}

async function main() {
  const argv = process.argv.slice(2);
  if (!argv.length || argv.includes('--help') || argv.includes('-h')) {
    console.log(HELP);
    return;
  }
  const cmd = argv[0];
  try {
    const args = parseArgs(argv.slice(1));
    switch (cmd) {
      case 'create':
      case 'seal':
        await cmdCreate(args);
        break;
      case 'open':
      case 'unlock':
        if (!args._.length) fail('open needs a link');
        await cmdOpen(args, args._[0]);
        break;
      case 'info':
        if (!args._.length) fail('info needs a link');
        await cmdInfo(args, args._[0]);
        break;
      case 'keygen':
        await cmdKeygen(args);
        break;
      case 'passphrase':
        await cmdPassphrase(args);
        break;
      default:
        fail(`unknown command "${cmd}" — try: seal --help`);
    }
  } catch (e) {
    fail(e instanceof SealError ? e.message : e?.message || String(e));
  }
}

main().catch((e) => fail(e?.message ?? String(e)));
