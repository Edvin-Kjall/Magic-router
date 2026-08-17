// scripts/gen-dict.mjs — regenerate site/public/lib/dict.js from
// data/top-1000-domains.txt (Cisco Umbrella top-1M) plus a curated Nordic list.
// Run: node scripts/gen-dict.mjs
//
// Dictionary policy — the append-only invariant:
//   * Core TOKENS indexes are frozen once shipped. This script only APPENDS
//     to the CORE list below (never reorders, never deletes).
//   * One-byte slots are capped at 250 (0xFF is the escape byte).
//   * Full domains go into the EXTENDED table (3-byte tokens) only when they
//     beat core tokenization: greedy core cost of the domain > 3 bytes.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..');

// ---- append-only core tokens (the original hand-written 162) ----
const CORE = [
  // schemes & hosts
  'https://', 'http://', 'www.', '.com', '.se', '.org', '.net', '.io', '.dev',
  '.app', '.co', '.ai', '.gov', '.edu', '.cloud', '.workers', '.workers.dev',
  'localhost', 'example.com', 'example',
  // structure & punctuation
  '://', '//', '/', '?', '&', '=', '-', '_', '.', '%20', '+', ':', '#', '!', '*',
  '(', ')', ',', ';', "'", '"', ' ',
  // common path prefixes
  '/news', '/blog', '/article', '/articles', '/api', '/v1', '/v2', '/v3',
  '/search', '/login', '/signin', '/signup', '/register', '/logout',
  '/home', '/about', '/contact', '/help', '/faq', '/index', '/page',
  '/user', '/users', '/account', '/settings', '/profile', '/dashboard',
  '/admin', '/post', '/posts', '/product', '/products', '/shop', '/store',
  '/cart', '/checkout', '/image', '/images', '/img', '/video', '/videos',
  '/file', '/files', '/download', '/upload', '/docs', '/doc', '/wiki', '/watch',
  // words
  'index', 'html', 'htm', 'php', 'json', 'xml', 'pdf', 'true', 'false', 'null',
  'news', 'article', 'search', 'query', 'page', 'user', 'users', 'post', 'blog',
  // extensions
  '.html', '.htm', '.php', '.json', '.xml', '.pdf', '.png', '.jpg', '.jpeg',
  '.gif', '.svg', '.webp', '.mp4', '.mp3', '.zip', '.js', '.css', '.ts',
  // query keys
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term', 'utm_id',
  'ref', 'q=', 'id=', 'page=', 'lang=', 'hl=', 'sort=', 'order=', 'search=',
  'query=', 'key=', 'token=', 'type=', 'cat=', 'category=', 'redirect',
  // big domains
  'google', 'facebook', 'twitter', 'instagram', 'youtube', 'linkedin',
  'github', 'amazon', 'netflix', 'wikipedia', 'reddit', 'apple', 'microsoft',
];

// ---- unconditional TLD additions (generic wins for any URL with these) ----
const EXTRA_TLDS = [
  '.de', '.uk', '.co.uk', '.fr', '.nl', '.ru', '.it', '.es', '.br', '.in',
  '.jp', '.cn', '.ca', '.au', '.fi', '.no', '.dk', '.pl', '.ch', '.at', '.be',
  '.ie', '.nz', '.za', '.nu', '.tv', '.gg',
];

// ---- curated Nordic/Swedish domains, ranked ahead of the global list ----
const NORDIC = [
  'svt.se', 'tv4.se', 'svtplay.se', 'aftonbladet.se', 'expressen.se', 'dn.se',
  'gp.se', 'sydsvenskan.se', 'di.se', 'sr.se', 'sverigesradio.se', 'blocket.se',
  'tradera.com', 'prisjakt.nu', 'hemnet.se', 'booli.se', 'ica.se', 'coop.se',
  'willys.se', 'ikea.se', 'elgiganten.se', 'mediamarkt.se', 'komplett.se',
  'inet.se', 'webhallen.com', 'netonnet.se', 'cdon.se', 'adlibris.se',
  'bokus.com', 'akademibokhandeln.se', 'mathem.se', 'foodora.se', 'wolt.com',
  'klarna.com', 'swish.nu', 'bankid.com', 'avanza.se', 'nordnet.se',
  'swedbank.se', 'seb.se', 'nordea.se', 'handelsbanken.se', 'lansforsakringar.se',
  'skandia.se', 'folksam.se', 'if.se', 'trygghansa.se', 'hitta.se', 'eniro.se',
  'ratsit.se', 'allabolag.se', 'arbetsformedlingen.se', 'forsakringskassan.se',
  'skatteverket.se', '1177.se', 'polisen.se', 'msb.se', 'krisinformation.se',
  'regeringen.se', 'riksdagen.se', 'svenskaspel.se', 'atg.se', 'skistar.com',
  'sl.se', 'sj.se', 'stockholm.se', 'malmo.se', 'goteborg.se',
  'vg.no', 'nrk.no', 'dagbladet.no', 'finn.no',
  'yle.fi', 'hs.fi', 'iltalehti.fi', 'is.fi',
  'dr.dk', 'bt.dk', 'ekstrabladet.dk', 'dba.dk', 'boliga.dk',
];

// ---- input domains (dedup, lowercase) ----
const data = readFileSync(join(repo, 'data', 'top-1000-domains.txt'), 'utf8')
  .split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
const seen = new Set();
const orderedNordic = [];
const orderedGlobal = [];
for (const raw of [...NORDIC, ...data]) {
  const d = raw.toLowerCase();
  if (seen.has(d)) continue;
  seen.add(d);
  (NORDIC.includes(raw) ? orderedNordic : orderedGlobal).push(d);
}

// ---- core label tokens ----
const core = [...CORE, ...EXTRA_TLDS];
const coreSet = new Set(core);
const tldTokens = core.filter((t) => t.startsWith('.')).sort((a, b) => b.length - a.length);
const labels = [];
const CORE_LIMIT = 250; // leave slack under 255; 0xFF is the escape byte
const NORDIC_LABEL_CAP = 32; // Nordic sites get premium 1-byte slots first...
function pickLabels(list, cap) {
  for (const d of list) {
    if (labels.length >= cap) return;
    const tld = tldTokens.find((t) => d.endsWith(t) && d.length > t.length);
    if (!tld) continue;
    const label = d.slice(0, d.length - tld.length);
    if (label.length < 3 || label.includes('.')) continue;
    if (coreSet.has(label) || labels.includes(label)) continue;
    labels.push(label);
  }
}
pickLabels(orderedNordic, NORDIC_LABEL_CAP);
pickLabels(orderedGlobal, CORE_LIMIT - core.length); // ...then global by rank
const fullCore = [...core, ...labels];

// ---- greedy core cost: 1 byte per token, 2 per literal byte ----
function buildTrie(tokens) {
  const root = {};
  tokens.forEach((tok, idx) => {
    let node = root;
    for (let i = 0; i < tok.length; i++) {
      const c = tok.charCodeAt(i) & 0xff;
      node = node[c] ?? (node[c] = {});
    }
    node.end = idx;
  });
  return root;
}
const trie = buildTrie(fullCore);
function coreCost(s) {
  let cost = 0;
  let i = 0;
  while (i < s.length) {
    let node = trie;
    let match = -1;
    let matchLen = 0;
    let j = i;
    let len = 0;
    while (j < s.length && (node = node[s.charCodeAt(j) & 0xff])) {
      j++;
      len++;
      if (node.end !== undefined) {
        match = node.end;
        matchLen = len;
      }
    }
    if (match !== -1) {
      cost += 1;
      i += matchLen;
    } else {
      cost += 2;
      i++;
    }
  }
  return cost;
}

// ---- extended table: full domains that beat core tokenization ----
const extended = [];
for (const d of [...orderedNordic, ...orderedGlobal]) {
  if (coreCost(d) > 3) extended.push(d);
}

// ---------------------------------------------------------------- emit
const list = (arr) => '[\n' + arr.map((s) => '  ' + JSON.stringify(s)).join(',\n') + '\n]';

const out = `// Shared URL dictionary — "preset dictionary" compression (the technique
// Brotli uses to beat raw deflate on short strings). Common URL fragments
// are replaced with 1-byte token indexes; 0xFF escapes a literal byte.
// Greedy longest-match via a trie.
//
// Append-only invariant: core TOKENS indexes are frozen once shipped. The
// list below is regenerated by scripts/gen-dict.mjs from
// data/top-1000-domains.txt (Cisco Umbrella top-1M, deduped) plus a curated
// Nordic list — additions may be appended, never reordered or removed.
//
// Extended tokens: full domains from the top-1000 list, encoded as 3 bytes
// (0xFF, 0x80|hi, lo). They are only emitted when they beat the core tokens,
// so links that don't need them stay readable by older pages (payload flags
// 1/2). Streams that DO use them carry payload flag 3/4 (u1: flag bits
// 4+5); an old page misdecoding one always hits a >=0x80 byte, so it fails
// loudly with an invalid URL instead of silently landing somewhere wrong.

const TOKENS = ${list(fullCore)};

if (TOKENS.length > 255) throw new Error('dictionary too large');

// Full-domain extended tokens (Cisco Umbrella top-1000 + curated Nordic,
// minus domains the core tokens already cover in <=3 bytes).
const EXTENDED = ${list(extended)};

function buildTrie() {
  const root = {};
  TOKENS.forEach((tok, idx) => {
    let node = root;
    for (let i = 0; i < tok.length; i++) {
      const c = tok.charCodeAt(i) & 0xff;
      node = node[c] ?? (node[c] = {});
    }
    node.end = idx;
  });
  return root;
}
const TRIE = buildTrie();

const EXT_BY_FIRST = [];
for (let i = 0; i < EXTENDED.length; i++) {
  const c = EXTENDED[i].charCodeAt(0) & 0xff;
  (EXT_BY_FIRST[c] ?? (EXT_BY_FIRST[c] = [])).push(i);
}

const ESC = 0xff;

// longest valid core-token match at bytes[i] (never a dead prefix)
function trieMatch(bytes, i) {
  let node = TRIE;
  let match = -1;
  let matchLen = 0;
  let j = i;
  let len = 0;
  while (j < bytes.length && (node = node[bytes[j] & 0xff])) {
    j++;
    len++;
    if (node.end !== undefined) {
      match = node.end;
      matchLen = len;
    }
  }
  return { match, matchLen };
}

// longest extended (full-domain) match at bytes[i]
function extMatch(bytes, i) {
  const bucket = EXT_BY_FIRST[bytes[i] & 0xff];
  if (!bucket) return { len: 0, idx: -1 };
  let len = 0;
  let idx = -1;
  for (const t of bucket) {
    const s = EXTENDED[t];
    if (s.length <= len || i + s.length > bytes.length) continue;
    let ok = true;
    for (let k = 0; k < s.length; k++) {
      if ((s.charCodeAt(k) & 0xff) !== bytes[i + k]) { ok = false; break; }
    }
    if (ok) { len = s.length; idx = t; }
  }
  return { len, idx };
}

// v1 (legacy) compressor: core tokens + 0xFF <byte> literal escapes.
export function dictCompress(bytes) {
  const out = [];
  let i = 0;
  while (i < bytes.length) {
    const { match, matchLen } = trieMatch(bytes, i);
    if (match !== -1) {
      out.push(match);
      i += matchLen;
    } else {
      out.push(ESC, bytes[i]);
      i++;
    }
  }
  return new Uint8Array(out);
}

// v2 compressor: adds 3-byte extended tokens when they beat the core, and
// v2 literal escapes (NUL/high bytes). Returns extended=true whenever the
// stream needs the v2 decoder, i.e. payload flags 3/4 instead of 1/2.
export function dictCompressEx(bytes) {
  const out = [];
  let i = 0;
  let extended = false;
  while (i < bytes.length) {
    const { match, matchLen } = trieMatch(bytes, i);
    const e = extMatch(bytes, i);
    if (match !== -1 && (e.len === 0 || matchLen * 3 >= e.len)) {
      out.push(match);
      i += matchLen;
    } else if (e.len > 0) {
      out.push(ESC, 0x80 | (e.idx >> 8), e.idx & 0xff);
      extended = true;
      i += e.len;
    } else {
      const b = bytes[i];
      if (b === 0) { out.push(ESC, 0, 0); extended = true; }
      else if (b < 0x80) out.push(ESC, b);
      else { out.push(ESC, 0, b); extended = true; }
      i++;
    }
  }
  return { bytes: new Uint8Array(out), extended };
}

// v1 decoder (payload flags 1/2 and u1 bit4-only links).
export function dictDecompressLegacy(bytes) {
  const out = [];
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === ESC) {
      out.push(bytes[++i] ?? 0);
    } else {
      const tok = TOKENS[b];
      if (tok === undefined) throw new Error(\`unknown dictionary token \${b}\`);
      for (let k = 0; k < tok.length; k++) out.push(tok.charCodeAt(k) & 0xff);
    }
  }
  return new Uint8Array(out);
}

// v2 decoder (payload flags 3/4, u1 bit4+bit5): 0xFF hi>=0x80 lo = extended
// token; 0xFF 0x00 b = literal b (NUL or high byte); 0xFF b = literal b.
export function dictDecompress(bytes) {
  const out = [];
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === ESC) {
      const n = bytes[++i];
      if (n === undefined) { out.push(0); break; }
      if (n >= 0x80) {
        const idx = ((n & 0x7f) << 8) | (bytes[++i] ?? 0);
        const s = EXTENDED[idx];
        if (s === undefined) throw new Error(\`unknown extended token \${idx}\`);
        for (let k = 0; k < s.length; k++) out.push(s.charCodeAt(k) & 0xff);
      } else if (n === 0) {
        out.push(bytes[++i] ?? 0);
      } else {
        out.push(n);
      }
    } else {
      const tok = TOKENS[b];
      if (tok === undefined) throw new Error(\`unknown dictionary token \${b}\`);
      for (let k = 0; k < tok.length; k++) out.push(tok.charCodeAt(k) & 0xff);
    }
  }
  return new Uint8Array(out);
}

export { TOKENS, EXTENDED };
`;

writeFileSync(join(repo, 'site', 'public', 'lib', 'dict.js'), out);
console.log(JSON.stringify({
  coreTokens: fullCore.length,
  tldTokens: EXTRA_TLDS.length,
  labelTokens: labels.length,
  extended: extended.length,
}));
console.log('labels:', labels.join(' '));
console.log('first extended:', extended.slice(0, 25).join(' '));
console.log('last extended:', extended.slice(-10).join(' '));
