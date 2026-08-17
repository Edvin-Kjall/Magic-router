// scripts/gen-dict.mjs — regenerate site/public/lib/dict.js from
// data/top-1000-domains.txt (Cisco Umbrella top-1M, worldwide ranking).
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

// ---- input domains (dedup, lowercase) ----
const data = readFileSync(join(repo, 'data', 'top-1000-domains.txt'), 'utf8')
  .split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
const seen = new Set();
const ordered = [];
for (const raw of data) {
  const d = raw.toLowerCase();
  if (seen.has(d)) continue;
  seen.add(d);
  ordered.push(d);
}

// ---- core label tokens ----
const core = [...CORE, ...EXTRA_TLDS];
const coreSet = new Set(core);
const tldTokens = core.filter((t) => t.startsWith('.')).sort((a, b) => b.length - a.length);
const labels = [];
const CORE_LIMIT = 250; // leave slack under 255; 0xFF is the escape byte
for (const d of ordered) {
  if (labels.length >= CORE_LIMIT - core.length) break;
  const tld = tldTokens.find((t) => d.endsWith(t) && d.length > t.length);
  if (!tld) continue;
  const label = d.slice(0, d.length - tld.length);
  if (label.length < 3 || label.includes('.')) continue;
  if (coreSet.has(label) || labels.includes(label)) continue;
  labels.push(label);
}
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

// ---- worldwide locale prefixes and common path words (extended table) ----
// Generic tokens for international site structures: locale paths appear on
// every global site, product/pricing/support words on every marketing site.
const GLOBAL_WORDS = [
  // locale prefixes
  '/sv-se', '/sv', '/en', '/en-us', '/en-gb', '/en-au', '/en-ca', '/en-in',
  '/de', '/de-de', '/fr', '/fr-fr', '/fr-ca', '/es', '/es-es', '/es-mx',
  '/it', '/it-it', '/pt', '/pt-br', '/nl', '/nl-nl', '/pl', '/pl-pl',
  '/ru', '/ru-ru', '/ja', '/ja-jp', '/zh', '/zh-cn', '/zh-tw', '/ko',
  '/ko-kr', '/ar', '/tr', '/tr-tr', '/id', '/vi', '/th', '/hi', '/cs',
  '/ro', '/el', '/hu', '/fi', '/no', '/nb', '/da', '/uk', '/uk-ua',
  '/intl', '/international', '/global',
  // common site words
  'registrar', 'pricing', 'plans', 'features', 'careers', 'jobs', 'support',
  'community', 'status', 'privacy', 'terms', 'policy', 'legal', 'press',
  'investors', 'partners', 'affiliates', 'enterprise', 'solutions',
  'resources', 'customers', 'events', 'get-started', 'sign-up', 'log-in',
  'create-account', 'forgot-password', 'reset-password', 'changelog',
  'release-notes', 'whats-new', 'learn-more', 'free-trial', 'book-a-demo',
];

// ---- extended table: full domains and words that beat core tokenization ----
const extended = [];
const extSeen = new Set();
for (const s of [...ordered, ...GLOBAL_WORDS]) {
  if (extSeen.has(s)) continue;
  if (coreCost(s) > 3) {
    extSeen.add(s);
    extended.push(s);
  }
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
// data/top-1000-domains.txt (Cisco Umbrella top-1M, worldwide ranking,
// deduped) — additions may be appended, never reordered or removed.
//
// Extended tokens: full domains from the worldwide top-1000 plus generic
// locale prefixes and common site words, encoded as 3 bytes
// (0xFF, 0x80|hi, lo). They are only emitted when they beat the core
// tokens, so links that don't need them stay readable by older pages
// (payload flags 1/2). Streams that DO use them carry payload flag 3/4
// (u1: flag bits 4+5); an old page misdecoding one always hits a >=0x80
// byte, so it fails loudly with an invalid URL instead of silently
// landing somewhere wrong.
//
// Stream tiers (payload flag byte / u1 bits):
//   legacy (1/2, bit4)       core tokens + 0xFF <byte> literals
//   v2     (3/4, bit4+5)     + extended tokens and high-byte literals
//   v3     (5/6, bit4+5+6)   + literal runs: 0xFF 0x00 n <n bytes>
//                            (long unknown words cost n+2 instead of 2n)

const TOKENS = ${list(fullCore)};

if (TOKENS.length > 255) throw new Error('dictionary too large');

// Extended tokens (Cisco Umbrella worldwide top-1000 + locale/word tokens,
// minus anything the core tokens already cover in <=3 bytes).
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

// v2/v3 compressor: adds 3-byte extended tokens when they beat the core,
// plus literal runs for long unknown words. Returns the stream tier:
//   'legacy' — core tokens + 0xFF <byte> escapes (payload flags 1/2)
//   'v2'     — extended tokens or high-byte literals (payload flags 3/4)
//   'v3'     — literal runs used (payload flags 5/6, u1 bit4+5+6)
export function dictCompressEx(bytes) {
  const out = [];
  let i = 0;
  let usedV2 = false;
  let usedRun = false;
  while (i < bytes.length) {
    const { match, matchLen } = trieMatch(bytes, i);
    const e = extMatch(bytes, i);
    if (match !== -1 && (e.len === 0 || matchLen * 3 >= e.len)) {
      out.push(match);
      i += matchLen;
    } else if (e.len > 0) {
      out.push(ESC, 0x80 | (e.idx >> 8), e.idx & 0xff);
      usedV2 = true;
      i += e.len;
    } else {
      // maximal run of bytes with no token match at any position
      let run = 0;
      while (i + run < bytes.length &&
             trieMatch(bytes, i + run).match === -1 &&
             extMatch(bytes, i + run).len === 0) run++;
      if (run >= 3) {
        while (run > 0) {
          const n = Math.min(run, 255);
          out.push(ESC, 0, n);
          for (let k = 0; k < n; k++) out.push(bytes[i + k]);
          i += n;
          run -= n;
        }
        usedRun = true;
      } else {
        for (let k = 0; k < run; k++) {
          const b = bytes[i];
          if (b === 0 || b >= 0x80) { out.push(ESC, 0, b); usedV2 = true; }
          else out.push(ESC, b);
          i++;
        }
      }
    }
  }
  const tier = usedRun ? 'v3' : usedV2 ? 'v2' : 'legacy';
  return { bytes: new Uint8Array(out), tier };
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

// v3 decoder (payload flags 5/6, u1 bit4+5+6): adds literal runs —
// 0xFF 0x00 n <n literal bytes>. Extended tokens and 0xFF b literals
// decode exactly as in v2.
export function dictDecompressV3(bytes) {
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
        const len = bytes[++i] ?? 0;
        for (let k = 0; k < len; k++) out.push(bytes[++i] ?? 0);
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
