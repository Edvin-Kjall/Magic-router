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
`.trim();

function fail(msg) {
  console.error('seal: ' + msg);
  process.exit(1);
}

// argv scanner: --flag value, --flag=value, --boolflag, repeatable flags
function parseArgs(argv) {
  const bools = new Set(['json', 'qr', 'path', 'help', 'burn', 'pq', 'preview']);
  const out = { _: [], f: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) {
      out._.push(a);
      continue;
    }
    const eq = a.indexOf('=');
    if (eq !== -1) {
      const k = a.slice(2, eq);
      const v = a.slice(eq + 1);
      addFlag(out, k, v, bools);
      continue;
    }
    const k = a.slice(2);
    const next = argv[i + 1];
    if (!bools.has(k) && next !== undefined && !next.startsWith('--')) {
      addFlag(out, k, next, bools);
      i++;
    } else {
      addFlag(out, k, true, bools);
    }
  }
  return out;
}

function addFlag(out, k, v, bools) {
  if (bools.has(k) || k === 'password' || k === 'pwd' || k === 'pw') {
    (out.f[k] ??= []).push(v);
  } else {
    out.f[k] = v;
  }
}

function extractLink(input) {
  let s = String(input);
  const hash = s.indexOf('#');
  if (hash !== -1) s = s.slice(hash + 1);
  const u = s.indexOf('/_u/');
  if (u !== -1) s = s.slice(u + 4);
  try {
    s = decodeURIComponent(s);
  } catch {
    /* raw */
  }
  return s;
}

async function cmdCreate(args) {
  const f = args.f;
  const type = f.text ? 'text' : 'url';
  const data = f.text ?? f.url;
  if (!data) fail('create needs --url <destination> or --text <secret>');
  const passwords = (f.password ?? []).map(String);
  const opts = { type, data };
  if (passwords.length) opts.passwords = passwords;
  if (f.embed) opts.embedded = String(f.embed);
  if (f.recipient) {
    const j = f.recipient === true ? 'seal-key.json' : f.recipient;
    opts.recipient = JSON.parse(readFileSync(j, 'utf8'));
  }
  if (f.threshold) opts.threshold = Number(f.threshold);
  if (f.delay) {
    const ms = parseDuration(f.delay);
    const rate = await estimateHashRate();
    opts.timeLock = await makeTimeLock(ms, rate);
  }
  if (f.expires) opts.expiry = f.expires;
  if (f.note) opts.note = String(f.note);
  if (f.sign) opts.signer = JSON.parse(readFileSync(f.sign, 'utf8'));
  if (f.pq) opts.pq = true;
  if (f.preview) opts.preview = true;

  const env = await seal(opts);
  const frag = await encodeEnvelope(env);
  const tail = opts.embedded != null ? '.' + encodeURIComponent(opts.embedded) : '';
  const full = frag + tail;
  const url = f.host ? `${f.host}${f.path ? '/_u/' : '/#'}${full}` : null;

  if (f.json) {
    console.log(JSON.stringify({ fragment: full, url }));
  } else {
    console.log('sealed link:');
    console.log('  ' + (url ?? full));
    if (f.host && !url) console.log('  (fragment only: ' + full + ')');
  }
  if (f.qr) {
    const target = url ?? full;
    const qr = await qrTerminal(target, { type: 'terminal', small: true });
    console.log(qr);
  }
}

async function cmdOpen(args, link) {
  const f = args.f;
  const str = extractLink(link);
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
  } else if (r.type === 'url') {
    console.log(r.data);
  } else {
    console.log(r.data);
  }
}

async function cmdInfo(args, link) {
  const str = extractLink(link);
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
  const args = parseArgs(argv.slice(1));
  try {
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

main();
