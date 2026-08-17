// Shared URL dictionary — "preset dictionary" compression (the technique
// Brotli uses to beat raw deflate on short strings). Common URL fragments
// are replaced with 1-byte token indexes; 0xFF escapes a literal byte.
// Greedy longest-match via a trie. Fixed at format-version time: the table
// is immutable, so encoder and decoder never need to negotiate it.

const TOKENS = [
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

if (TOKENS.length > 255) throw new Error('dictionary too large');

// trie: { [byte]: trieNode, end?: tokenIndex }
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

const ESC = 0xff;

export function dictCompress(bytes) {
  const out = [];
  let i = 0;
  while (i < bytes.length) {
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
        matchLen = len; // only consume the VALID match, never the dead prefix
      }
    }
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

export function dictDecompress(bytes) {
  const out = [];
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === ESC) {
      out.push(bytes[++i] ?? 0);
    } else {
      const tok = TOKENS[b];
      if (tok === undefined) throw new Error(`unknown dictionary token ${b}`);
      for (let k = 0; k < tok.length; k++) out.push(tok.charCodeAt(k) & 0xff);
    }
  }
  return new Uint8Array(out);
}
