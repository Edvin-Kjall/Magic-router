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
  // camelCase query keys (e-commerce and catalog sites)
  'productId', 'categoryId', 'itemId', 'orderId', 'userId', 'sessionId',
  'cartId', 'storeId', 'brandId', 'colorId', 'sizeId', 'styleId',
  'articleId', 'productCode', 'articleNumber', 'catalogId', 'langId',
  'siteId', 'pageId', 'variantId', 'skuId', 'quantity', 'productName',
  'pageSize', 'sortBy', 'filterBy', 'countryCode', 'currencyCode',
  // underscore locale paths (retailer i18n routes)
  '/sv_se', '/en_us', '/en_gb', '/en_au', '/en_ca', '/de_de', '/fr_fr',
  '/es_es', '/it_it', '/nl_nl', '/pt_br', '/ja_jp', '/zh_cn', '/ko_kr',
  '/ru_ru', '/tr_tr', '/pl_pl', '/da_dk', '/fi_fi', '/nb_no',
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

// ================================================================ deep dict
// The DEEP dictionary is a downloadable asset (site/public/deep-v1.json.gz,
// served at /deep-v1.json.gz), fetched once and cached by the browser. It is
// NOT in the page bundle, so it can be orders of magnitude bigger: top-10k
// domains, the EFF common-words list, and curated tech/AI terms. Links that
// use it carry payload flags 7/8 (encrypted) or the u2. prefix (plain) and
// cost the opener one download — the 3-5 s budget the user opted into.
//
// Deep streams keep the core 1-byte tokens and v3 literal runs, and encode
// deep tokens as 3 bytes: 0xFF (0x80|hi) lo. The table is frozen at
// deep-v1: future changes ship as deep-v2 with a new link prefix.

const DEEP_TLDS = [
  '.us', '.me', '.eu', '.info', '.biz', '.cc', '.xyz', '.top', '.vip',
  '.site', '.online', '.shop', '.store', '.live', '.news', '.media',
  '.world', '.email', '.tech', '.link', '.club', '.pro', '.space', '.fun',
  '.icu', '.lol', '.wiki', '.win', '.games', '.life', '.love', '.one',
  '.run', '.zone', '.plus', '.page', '.digital', '.agency', '.studio',
  '.academy', '.company', '.expert', '.guru', '.systems', '.solutions',
  '.technology', '.software', '.ninja', '.codes', '.directory', '.services',
];

const TECH_WORDS = [
  // AI labs & models
  'deepseek', 'openrouter', 'openrouter.ai', '/deepseek', 'chatgpt', 'openai',
  'anthropic', 'claude', 'gemini', 'grok', 'llama', 'mistral', 'qwen',
  'perplexity', 'huggingface', 'kaggle', 'colab', 'jupyter', 'pytorch',
  'tensorflow', 'keras', 'numpy', 'pandas', 'scikit-learn', 'transformers',
  'diffusers', 'langchain', 'llamaindex', 'arxiv', 'paperswithcode',
  'replicate', 'together', 'fireworks', 'groq', 'cerebras', 'nvidia',
  // API/ML vocabulary
  'model', 'models', 'chat', 'completions', 'embeddings', 'assistants',
  'threads', 'runs', 'messages', 'fine-tuning', 'fine-tunes', 'inference',
  'endpoint', 'endpoints', 'playground', 'dashboard', 'api-reference',
  'getting-started', 'quickstart', 'tutorial', 'tutorials', 'examples',
  'credits', 'billing', 'usage', 'tokens', 'context', 'parameters',
  'temperature', 'stream', 'streaming', 'prompt', 'prompts', 'completion',
  'response', 'responses', 'generation', 'generations', 'multimodal',
  'vision', 'audio', 'speech', 'transcription', 'translation', 'vector',
  'vectors', 'retrieval', 'rag', 'agents', 'agent', 'workflow',
  'workflows', 'automation', 'deploy', 'deployment', 'preview',
  'production', 'sandbox', 'self-hosted', 'open-source',
  // model families & version suffixes (shared across every AI provider)
  'flash', 'flash-lite', 'flash-thinking', 'v1', 'v2', 'v3', 'v4', 'v5',
  'v6', 'v7', 'v8', 'pro', 'lite', 'mini', 'nano', 'turbo', 'sonnet',
  'haiku', 'opus', 'nova', 'spark', 'reasoning', 'reasoner', 'coder',
  'math', 'thinking', 'think', 'gpt-4o', 'gpt-4', 'gpt-3',
  // docs & support vocabulary
  'developer', 'developers', 'restoration', 'faq', 'guide', 'guides',
  'reference', 'learn', 'learning', 'integrations', 'best-practices',
  'troubleshooting', 'installation', 'configuration', 'migration',
  'upgrade', 'walkthrough', 'overview',
  // dev ecosystem
  'docker', 'kubernetes', 'helm', 'terraform', 'ansible', 'gitlab',
  'bitbucket', 'stackoverflow', 'devto', 'hashnode', 'discord', 'telegram',
  'slack', 'notion', 'linear', 'figma', 'canva', 'vercel', 'netlify',
  'cloudflare', 'fly', 'railway', 'render', 'heroku', 'digitalocean',
  'hetzner', 'supabase', 'firebase', 'planetscale', 'neon', 'turso',
  'upstash', 'redis', 'mongodb', 'postgres', 'postgresql', 'mysql',
  'sqlite', 'duckdb', 'clickhouse', 'snowflake', 'databricks', 'bigquery',
  'redshift', 'kafka', 'rabbitmq', 'grpc', 'graphql', 'rest', 'websocket',
  'oauth', 'jwt', 'serverless', 'edge', 'cdn', 's3', 'ec2', 'lambda',
  'cloudfront', 'dynamodb', 'sagemaker', 'bedrock', 'copilot', 'cursor',
  'windsurf', 'vscode', 'jetbrains', 'intellij', 'pycharm', 'webstorm',
];

// ---- build the deep table ----
// Order = value: the extended table and tech/word tokens come first; the
// first HOT_LIMIT entries also get 2-byte hot codes (see dict.js).
const HOT_LIMIT = 1280;
const deep10k = readFileSync(join(repo, 'data', 'top-10000-domains.txt'), 'utf8')
  .split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
const effWords = readFileSync(join(repo, 'site', 'public', 'data', 'eff-large.txt'), 'utf8')
  .split('\n')
  .map((l) => l.split('\t').pop().trim().toLowerCase())
  .filter((w) => /^[a-z]{2,}$/.test(w));
const deep = [];
const deepSeen = new Set();
for (const s of [...extended, ...TECH_WORDS, ...GLOBAL_WORDS, ...DEEP_TLDS, ...deep10k, ...effWords]) {
  const t = String(s).toLowerCase();
  if (deepSeen.has(t)) continue;
  if (t.length < 2) continue;
  if (coreCost(t) <= 3) continue; // core tokens already cover it
  deepSeen.add(t);
  deep.push(t);
}
if (deep.length >= 32768) throw new Error('deep dictionary exceeds the 15-bit code space');
if (deep.length < HOT_LIMIT) throw new Error('deep dictionary smaller than the hot zone');

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

if (TOKENS.length > 250) throw new Error('dictionary too large (codes 250-254 are reserved for deep hot tokens)');

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

// ALL core-token matches at bytes[i] (for the optimal DP tokenizer)
function trieMatches(bytes, i) {
  const out = [];
  let node = TRIE;
  for (let j = i; j < bytes.length; j++) {
    node = node[bytes[j] & 0xff];
    if (!node) break;
    if (node.end !== undefined) out.push({ len: j - i + 1, idx: node.end });
  }
  return out;
}

// ALL extended-token matches at bytes[i]
function extMatchesAll(bytes, i) {
  const out = [];
  const bucket = EXT_BY_FIRST[bytes[i] & 0xff];
  if (bucket) {
    for (const t of bucket) {
      const s = EXTENDED[t];
      if (i + s.length > bytes.length) continue;
      let ok = true;
      for (let k = 0; k < s.length; k++) {
        if ((s.charCodeAt(k) & 0xff) !== bytes[i + k]) { ok = false; break; }
      }
      if (ok) out.push({ len: s.length, idx: t });
    }
  }
  return out;
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

// Optimal (dynamic-programming) tokenizer shared by the shallow and deep
// compressors. Greedy longest-match is provably suboptimal when a short
// token shadows a longer one one byte later (e.g. ".cloud" hiding the
// "cloudflare" label). Options per position: core token (1 B), ext token
// (3 B), literal (2 B), literal run of L>=3 (L+2 B).
function tokenizeDP(bytes, matchSrc) {
  const n = bytes.length;
  const dp = new Float64Array(n + 1);
  const kind = new Int8Array(n);   // 0 literal · 1 core · 2 ext · 3 run
  const ref = new Int32Array(n);   // token index / run length
  const len = new Int16Array(n);   // consumed bytes
  for (let i = n - 1; i >= 0; i--) {
    let best = 2 + dp[i + 1];
    let bk = 0;
    let br = 0;
    let bl = 1;
    for (const m of trieMatches(bytes, i)) {
      const c = 1 + dp[i + m.len];
      if (c < best) { best = c; bk = 1; br = m.idx; bl = m.len; }
    }
    for (const src of matchSrc) {
      for (const m of src.matches(bytes, i)) {
        const c = src.cost + dp[i + m.len];
        if (c < best) { best = c; bk = 2; br = src.offset + m.idx; bl = m.len; }
      }
    }
    const maxL = Math.min(255, n - i);
    for (let L = 3; L <= maxL; L++) {
      const c = L + 2 + dp[i + L];
      if (c < best) { best = c; bk = 3; br = L; bl = L; }
    }
    dp[i] = best;
    kind[i] = bk;
    ref[i] = br;
    len[i] = bl;
  }
  return { kind, ref, len, n };
}

// v2/v3 compressor: extended tokens + literal runs, optimally tokenized.
// Returns the stream tier:
//   'legacy' — core tokens + 0xFF <byte> escapes (payload flags 1/2)
//   'v2'     — extended tokens or high-byte literals (payload flags 3/4)
//   'v3'     — literal runs used (payload flags 5/6, u1 bit4+5+6)
export function dictCompressEx(bytes) {
  const n = bytes.length;
  if (n === 0) return { bytes: new Uint8Array(0), tier: 'legacy' };
  const { kind, ref, len } = tokenizeDP(bytes, [{ matches: extMatchesAll, cost: 3, offset: 0 }]);
  const out = [];
  let usedV2 = false;
  let usedRun = false;
  let i = 0;
  while (i < n) {
    const k = kind[i];
    if (k === 0) {
      const b = bytes[i];
      if (b === 0 || b >= 0x80) { out.push(ESC, 0, b); usedV2 = true; }
      else out.push(ESC, b);
      i++;
    } else if (k === 1) {
      out.push(ref[i]);
      i += len[i];
    } else if (k === 2) {
      out.push(ESC, 0x80 | (ref[i] >> 8), ref[i] & 0xff);
      usedV2 = true;
      i += len[i];
    } else {
      const L = len[i];
      out.push(ESC, 0, L);
      for (let k2 = 0; k2 < L; k2++) out.push(bytes[i + k2]);
      usedRun = true;
      i += L;
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

// =============================================================== deep dict
// Downloadable dictionaries (deep-v1.json.gz / deep-v2.json.gz at the site
// root). deep-v1 is FROZEN: older u2. links and payload flags 7/8 decode
// against it forever. deep-v2 is the current table, used by u3. links and
// payload flags 9/10. Each is fetched once and cached (Cache API in
// browsers). Deep tokens are 3 bytes: 0xFF (0x80|hi) lo, indexing the
// active table; the 1280 hottest entries also get 2-byte codes 250-254.

let DEEP = null;        // current table (deep-v2)
let DEEP_V1 = null;     // frozen table (deep-v1)
let DEEP_BY_FIRST = null;
let deepPromise = null;
let deepV1Promise = null;

function buildBuckets(arr) {
  const b = [];
  for (let i = 0; i < arr.length; i++) {
    const c = String(arr[i]).charCodeAt(0) & 0xff;
    (b[c] ?? (b[c] = [])).push(i);
  }
  return b;
}

export function setDeepTokens(arr) {
  DEEP = arr;
  DEEP_BY_FIRST = buildBuckets(arr);
  return arr;
}

export function setDeepTokensV1(arr) {
  DEEP_V1 = arr;
  return arr;
}

export function hasDeep() {
  return DEEP !== null;
}

async function fetchDeepBytes(name) {
  // browser: Cache API around the same-origin asset
  if (typeof caches !== 'undefined') {
    try {
      const cache = await caches.open('mr-deep-dict-' + name);
      const url = new URL(name, globalThis.location.href).href;
      let res = await cache.match(url);
      if (!res) {
        res = await fetch(url);
        if (res.ok) cache.put(url, res.clone());
      }
      if (!res.ok) throw new Error('deep dictionary fetch failed');
      return new Uint8Array(await res.arrayBuffer());
    } catch {
      /* fall through to network */
    }
  }
  if (typeof location !== 'undefined' && location.href) {
    const res = await fetch(new URL(name, location.href).href);
    if (!res.ok) throw new Error('deep dictionary fetch failed');
    return new Uint8Array(await res.arrayBuffer());
  }
  // Node (CLI/tests): read the asset from the repo next to this module
  try {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const p = fileURLToPath(new URL('../' + name, import.meta.url));
    return new Uint8Array(readFileSync(p));
  } catch {
    /* fall through */
  }
  throw new Error('deep dictionary unavailable');
}

async function gunzipMaybe(bytes) {
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    if (typeof DecompressionStream !== 'undefined') {
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
      return new Uint8Array(await new Response(stream).arrayBuffer());
    }
    try {
      const zlib = await import('node:zlib');
      return new Uint8Array(zlib.gunzipSync(bytes));
    } catch {
      /* fall through */
    }
  }
  return bytes;
}

async function loadDeep(name) {
  const bytes = await fetchDeepBytes(name);
  const raw = await gunzipMaybe(bytes);
  return JSON.parse(new TextDecoder().decode(raw));
}

export async function ensureDeepDict() {
  if (DEEP) return DEEP;
  if (deepPromise) return deepPromise;
  deepPromise = loadDeep('deep-v2.json.gz').then(setDeepTokens);
  try {
    return await deepPromise;
  } catch (err) {
    deepPromise = null;
    throw err;
  }
}

export async function ensureDeepDictV1() {
  if (DEEP_V1) return DEEP_V1;
  if (deepV1Promise) return deepV1Promise;
  deepV1Promise = loadDeep('deep-v1.json.gz').then(setDeepTokensV1);
  try {
    return await deepV1Promise;
  } catch (err) {
    deepV1Promise = null;
    throw err;
  }
}

// ALL hot-token matches at bytes[i] (deep table prefix, 2-byte codes)
const HOT_LIMIT = 5 * 256;
function hotMatchesAll(bytes, i) {
  const out = [];
  const bucket = DEEP_BY_FIRST?.[bytes[i] & 0xff];
  if (bucket) {
    for (const t of bucket) {
      if (t >= HOT_LIMIT) continue;
      const s = String(DEEP[t]);
      if (i + s.length > bytes.length) continue;
      let ok = true;
      for (let k = 0; k < s.length; k++) {
        if ((s.charCodeAt(k) & 0xff) !== bytes[i + k]) { ok = false; break; }
      }
      if (ok) out.push({ len: s.length, idx: t });
    }
  }
  return out;
}

// ALL deep-token matches at bytes[i]
function deepMatchesAll(bytes, i) {
  const out = [];
  const bucket = DEEP_BY_FIRST?.[bytes[i] & 0xff];
  if (bucket) {
    for (const t of bucket) {
      const s = String(DEEP[t]);
      if (i + s.length > bytes.length) continue;
      let ok = true;
      for (let k = 0; k < s.length; k++) {
        if ((s.charCodeAt(k) & 0xff) !== bytes[i + k]) { ok = false; break; }
      }
      if (ok) out.push({ len: s.length, idx: t });
    }
  }
  return out;
}

// deep compressor: core tokens (1 B) + hot tokens (2 B, deep idx < 1280)
// + deep tokens (3 B) + literal runs — optimally tokenized via DP
export function dictCompressDeep(bytes) {
  const n = bytes.length;
  if (n === 0) return { bytes: new Uint8Array(0), usedDeep: false };
  const { kind, ref, len } = tokenizeDP(bytes, [
    { matches: hotMatchesAll, cost: 2, offset: 0 },
    { matches: deepMatchesAll, cost: 3, offset: 1 << 20 },
  ]);
  const out = [];
  let usedDeep = false;
  let i = 0;
  while (i < n) {
    const k = kind[i];
    if (k === 0) {
      const b = bytes[i];
      if (b === 0 || b >= 0x80) out.push(ESC, 0, b);
      else out.push(ESC, b);
      i++;
    } else if (k === 1) {
      out.push(ref[i]);
      i += len[i];
    } else if (k === 2) {
      const idx = ref[i];
      if (idx >= (1 << 20)) {
        const didx = idx - (1 << 20);
        out.push(ESC, 0x80 | (didx >> 8), didx & 0xff);
      } else {
        out.push(250 + (idx >> 8), idx & 0xff);
      }
      usedDeep = true;
      i += len[i];
    } else {
      const L = len[i];
      out.push(ESC, 0, L);
      for (let k2 = 0; k2 < L; k2++) out.push(bytes[i + k2]);
      i += L;
    }
  }
  return { bytes: new Uint8Array(out), usedDeep };
}

// deep decoder (payload flags 7/8, u2. links): same grammar as v3, but the
// 0xFF hi>=0x80 codes index DEEP instead of EXTENDED.
export function dictDecompressDeep(bytes) {
  const out = [];
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === ESC) {
      const n = bytes[++i];
      if (n === undefined) { out.push(0); break; }
      if (n >= 0x80) {
        const idx = ((n & 0x7f) << 8) | (bytes[++i] ?? 0);
        const s = DEEP?.[idx];
        if (s === undefined) throw new Error(\`unknown deep token \${idx}\`);
        for (let k = 0; k < s.length; k++) out.push(s.charCodeAt(k) & 0xff);
      } else if (n === 0) {
        const len = bytes[++i] ?? 0;
        for (let k = 0; k < len; k++) out.push(bytes[++i] ?? 0);
      } else {
        out.push(n);
      }
    } else if (b >= 250) {
      const idx = (b - 250) * 256 + (bytes[++i] ?? 0);
      const s = DEEP?.[idx];
      if (s === undefined) throw new Error(\`unknown hot token \${idx}\`);
      for (let k = 0; k < s.length; k++) out.push(s.charCodeAt(k) & 0xff);
    } else {
      const tok = TOKENS[b];
      if (tok === undefined) throw new Error(\`unknown dictionary token \${b}\`);
      for (let k = 0; k < tok.length; k++) out.push(tok.charCodeAt(k) & 0xff);
    }
  }
  return new Uint8Array(out);
}

// deep-v1 decoder (payload flags 7/8, u2. links): identical grammar to
// dictDecompressDeep but indexes the frozen DEEP_V1 table instead.
export function dictDecompressDeepV1(bytes) {
  const out = [];
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === ESC) {
      const n = bytes[++i];
      if (n === undefined) { out.push(0); break; }
      if (n >= 0x80) {
        const idx = ((n & 0x7f) << 8) | (bytes[++i] ?? 0);
        const s = DEEP_V1?.[idx];
        if (s === undefined) throw new Error(\`unknown deep-v1 token \${idx}\`);
        for (let k = 0; k < s.length; k++) out.push(s.charCodeAt(k) & 0xff);
      } else if (n === 0) {
        const len = bytes[++i] ?? 0;
        for (let k = 0; k < len; k++) out.push(bytes[++i] ?? 0);
      } else {
        out.push(n);
      }
    } else if (b >= 250) {
      const idx = (b - 250) * 256 + (bytes[++i] ?? 0);
      const s = DEEP_V1?.[idx];
      if (s === undefined) throw new Error(\`unknown deep-v1 hot token \${idx}\`);
      for (let k = 0; k < s.length; k++) out.push(s.charCodeAt(k) & 0xff);
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

// deep dictionary asset: plain JSON for debugging + gzipped for serving.
// deep-v1 is FROZEN (older u2. links decode against it forever); the
// regenerated table ships as deep-v2 and links reference it via the u3.
// prefix and payload flags 9/10.
import { gzipSync } from 'node:zlib';
const deepJson = JSON.stringify(deep);
writeFileSync(join(repo, 'site', 'public', 'deep-v2.json'), deepJson + '\n');
writeFileSync(join(repo, 'site', 'public', 'deep-v2.json.gz'), gzipSync(deepJson, { level: 9 }));
console.log(JSON.stringify({
  coreTokens: fullCore.length,
  tldTokens: EXTRA_TLDS.length,
  labelTokens: labels.length,
  extended: extended.length,
  deep: deep.length,
  deepJsonBytes: deepJson.length,
  deepGzBytes: gzipSync(deepJson, { level: 9 }).length,
}));
console.log('labels:', labels.join(' '));
console.log('first extended:', extended.slice(0, 25).join(' '));
console.log('last extended:', extended.slice(-10).join(' '));
