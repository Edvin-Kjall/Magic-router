// Magic Router — all UI logic. Encryption, decryption and key derivation
// run entirely in this browser; the server only ever serves static files.

import {
  seal,
  open,
  openLegacy,
  encodeEnvelope,
  decodeEnvelope,
  splitEmbedded,
  isSealedLink,
  describeEnvelope,
  generateRecipientKeypair,
  generateSignerIdentity,
  verifySignatures,
  makeTimeLock,
  parseDuration,
  expiryStatus,
  SealError,
} from './lib/envelope.js';
import { estimateHashRate, formatDuration } from './lib/timelock.js';
import { toCanvas } from 'qrcode';

const CFG = {
  repo: 'https://github.com/Edvin-Kjall/Magic-router',
  file: (p) => `${CFG.repo}/blob/main/${p}`,
};

const $ = (id) => document.getElementById(id);

let hashRate = 0; // SHA-256 chain hashes/sec on this device
let signerIdentity = null; // {name, ed25519, mldsa65}
let currentLink = null; // { str, env?, tail, mode, hostedMeta? }
let wordlist = null;

// ------------------------------------------------------------- helpers

function showView(name) {
  for (const v of ['create', 'open', 'prove', 'faq']) {
    $('view-' + v).hidden = v !== name;
  }
  for (const b of document.querySelectorAll('.nav-btn')) {
    b.classList.toggle('active', b.dataset.view === name);
  }
}

function err(e) {
  const box = $('create-err');
  const box2 = $('open-err');
  const msg = e instanceof SealError ? e.message : e?.message || String(e);
  if (!$('view-create').hidden) {
    box.textContent = '⚠ ' + msg;
    box.hidden = false;
  } else {
    box2.textContent = '⚠ ' + msg;
    box2.hidden = false;
  }
}

async function readFileText(input) {
  const f = input.files?.[0];
  if (!f) return null;
  return await f.text();
}

function download(name, text) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

// ------------------------------------------------------------ diceware

async function loadWordlist() {
  if (wordlist) return wordlist;
  let res = await fetch('/eff-large.txt');
  if (!res.ok) res = await fetch('/data/eff-large.txt');
  if (!res.ok) throw new Error('wordlist unavailable');
  const text = await res.text();
  wordlist = text
    .split('\n')
    .map((l) => l.split('\t')[1])
    .filter(Boolean);
  return wordlist;
}

function diceRoll() {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return 1 + Math.floor((buf[0] / 2 ** 32) * 6);
}

async function generatePassphrase(words = 8) {
  const list = await loadWordlist();
  const out = [];
  for (let i = 0; i < words; i++) {
    let idx = 0;
    for (let d = 0; d < 5; d++) idx = idx * 6 + (diceRoll() - 1);
    out.push(list[idx]);
  }
  return out.join(' ');
}

// -------------------------------------------------------- create: methods

function addMethodRow(kind) {
  const row = document.createElement('div');
  row.className = 'method-row';
  row.dataset.kind = kind;
  const label = document.createElement('span');
  label.className = 'kind-label';
  label.textContent = { pass: 'password', embed: 'embedded pw', prf: 'passkey', pub: 'recipient key' }[kind];
  row.appendChild(label);

  if (kind === 'pass' || kind === 'embed') {
    const input = document.createElement('input');
    input.type = 'password';
    input.placeholder =
      kind === 'pass' ? 'password for the recipient' : 'password riding in the link (auto-open)';
    input.autocomplete = 'new-password';
    row.appendChild(input);
  } else if (kind === 'prf') {
    const p = document.createElement('span');
    p.className = 'hint';
    p.textContent = 'the recipient unlocks with Touch ID / Windows Hello — enrollment happens on create';
    row.appendChild(p);
  } else if (kind === 'pub') {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,application/json';
    input.title = 'recipient’s public key file (seal-key.json)';
    row.appendChild(input);
  }
  const rm = document.createElement('button');
  rm.type = 'button';
  rm.className = 'remove';
  rm.textContent = '✕';
  rm.title = 'remove';
  rm.addEventListener('click', () => {
    row.remove();
    updateThresholdUI();
  });
  row.appendChild(rm);
  $('methods').appendChild(row);
  updateThresholdUI();
}

function updateThresholdUI() {
  const rows = [...document.querySelectorAll('#methods .method-row')];
  const n = rows.length;
  $('methods-count').textContent = n ? `${n} method${n > 1 ? 's' : ''} — any one unlocks` : '';
  const wrap = $('threshold-wrap');
  wrap.hidden = n < 2;
  if (n >= 2) $('threshold').max = n;
}

function collectMethods() {
  const out = { passwords: [], embedded: null, recipient: null, prf: false };
  for (const row of document.querySelectorAll('#methods .method-row')) {
    const kind = row.dataset.kind;
    if (kind === 'pass') {
      const v = row.querySelector('input').value;
      if (v) out.passwords.push(v);
    } else if (kind === 'embed') {
      const v = row.querySelector('input').value;
      if (v) out.embedded = v;
    } else if (kind === 'prf') {
      out.prf = true;
    } else if (kind === 'pub') {
      const f = row.querySelector('input').files?.[0];
      if (f) out.recipient = f;
    }
  }
  return out;
}

// ------------------------------------------------------------ create

async function onCreate(e) {
  e.preventDefault();
  const errBox = $('create-err');
  errBox.hidden = true;
  const btn = $('create-btn');
  btn.disabled = true;
  btn.textContent = 'Sealing…';
  try {
    const type = document.querySelector('input[name="payload-type"]:checked').value;
    const data =
      type === 'url' ? $('payload-url').value.trim() : $('payload-text').value.trim();
    if (!data) throw new SealError('Enter a destination URL or secret text first');

    const m = collectMethods();
    const opts = { type, data };
    if (m.passwords.length) opts.passwords = m.passwords;
    if (m.embedded != null) opts.embedded = m.embedded;
    if (m.prf) opts.prf = true;
    if (m.recipient) {
      opts.recipient = JSON.parse(await m.recipient.text());
    }
    const rows = [...document.querySelectorAll('#methods .method-row')];
    if (rows.length >= 2) {
      const thr = Number($('threshold').value);
      if (thr >= 1) opts.threshold = thr;
    }
    const tlSel = $('timelock').value;
    if (tlSel !== 'off') {
      const ms = parseDuration(tlSel);
      opts.timeLock = await makeTimeLock(ms, hashRate || 1e6);
    }
    if ($('expiry').value) opts.expiry = $('expiry').value;
    if ($('note').value.trim()) opts.note = $('note').value.trim();
    if (signerIdentity) opts.signer = signerIdentity;

    const env = await seal(opts);
    const frag = await encodeEnvelope(env);
    const tail = opts.embedded != null ? '.' + encodeURIComponent(opts.embedded) : '';
    const full = frag + tail;
    currentLink = { str: full, env };
    const linkUrl = $('path-toggle').checked
      ? `${location.origin}/_u/${full}`
      : `${location.origin}/#${full}`;
    $('link-out').value = linkUrl;
    await toCanvas($('qr-canvas'), linkUrl, { width: 240, margin: 1 });
    $('create-result').hidden = false;
    const sealEl = $('wax-seal');
    sealEl.classList.remove('broken', 'breaking');
    sealEl.classList.remove('stamping');
    void sealEl.offsetWidth; // restart animation
    sealEl.classList.add('stamping');
    $('share-btn').hidden = typeof navigator.share !== 'function';
    $('create-result').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (e2) {
    err(e2);
  } finally {
    btn.disabled = false;
    btn.textContent = '🕯️ Create sealed link';
  }
}

// -------------------------------------------------------------- open

function detectLink() {
  const path = location.pathname;
  if (path.startsWith('/s/') && path.length > 3) {
    return { mode: 'hosted', slug: decodeURIComponent(path.slice(3)) };
  }
  const frag = location.hash.slice(1);
  if (frag) return { mode: 'self', str: frag };
  if (path.startsWith('/_u/') && path.length > 4) {
    return { mode: 'self', str: decodeURIComponent(path.slice(4)) };
  }
  return null;
}

async function route() {
  const link = detectLink();
  if (!link) {
    showView('create');
    return;
  }
  showView('open');
  $('open-result').hidden = true;
  $('open-gone').hidden = true;
  try {
    if (link.mode === 'hosted') {
      const res = await fetch(`/api/link/${encodeURIComponent(link.slug)}`);
      if (!res.ok) {
        $('open-gone').hidden = false;
        return;
      }
      const body = await res.json();
      currentLink = { str: body.envelope, tail: null, mode: 'hosted', hostedMeta: body.meta };
      await beginOpen(body.envelope, null, body.meta);
    } else {
      let str = link.str;
      try {
        str = decodeURIComponent(str);
      } catch {
        /* keep raw */
      }
      if (/^v[12]\./.test(str)) {
        legacyOpen(str);
        return;
      }
      const { env: envStr, tail } = splitEmbedded(str);
      currentLink = { str: envStr, tail, mode: 'self' };
      await beginOpen(envStr, tail);
    }
  } catch (e2) {
    err(e2);
  }
}

function legacyOpen(str) {
  $('open-pw-wrap').hidden = false;
  $('open-keyfile-wrap').hidden = true;
  $('open-passkey-btn').hidden = true;
  $('open-thr').textContent = 'Legacy link (pre-v3 format). Enter the password.';
  $('open-form').onsubmit = async (e) => {
    e.preventDefault();
    $('open-err').hidden = true;
    try {
      const r = await openLegacy(str, $('open-pw').value);
      showResult(r, null);
    } catch (e2) {
      err(e2);
    }
  };
}

async function beginOpen(envStr, tail, hostedMeta) {
  const env = await decodeEnvelope(envStr);
  currentLink.env = env;
  const d = describeEnvelope(env);

  // meta
  $('open-host').textContent = d.host ? `→ ${d.host}` : 'destination preview unavailable';
  $('open-note').hidden = !d.note;
  $('open-note').textContent = d.note ? `“${d.note}”` : '';
  const ex = expiryStatus(env.meta);
  $('open-exp').textContent = '';
  if (ex) {
    $('open-exp').textContent = ex.expired
      ? ' · expired'
      : ` · expires ${new Date(ex.at).toLocaleString()}`;
  }

  // signatures
  const sigs = await verifySignatures(env);
  if (sigs.length) {
    const names = sigs.map((s) => `${s.name} (${s.alg}: ${s.ok ? 'valid ✓' : 'INVALID ✗'})`);
    $('open-sig-results').textContent = 'Sealed by ' + names.join(', ');
  } else {
    $('open-sig-results').textContent = d.signed.length
      ? 'Signature check unavailable in this browser'
      : 'Unsigned link — sealed anonymously';
  }

  // threshold info
  if (env.thr) {
    $('open-thr').textContent = `This link needs ${env.thr.m} of ${env.thr.n} credentials. Provide as many as you have and unlock.`;
  } else {
    $('open-thr').textContent = '';
  }

  const kinds = new Set(d.methods);
  $('open-pw-wrap').hidden = !kinds.has('pass');
  $('open-keyfile-wrap').hidden = !kinds.has('pub');
  $('open-passkey-btn').hidden = !kinds.has('prf');
  if (hostedMeta?.fetches != null) {
    $('open-exp').textContent += ` · fetched ${hostedMeta.fetches} time(s)`;
  }

  // embedded password present in the link tail → auto-unlock
  if (kinds.has('embed') && tail) {
    $('open-form').hidden = true;
    $('open-err').hidden = true;
    try {
      const r = await open(envStr, { embeddedPassword: tail });
      showResult(r, env);
      return;
    } catch (e2) {
      err(e2);
      $('open-form').hidden = false;
    }
  }

  $('open-form').hidden = false;
  $('open-form').onsubmit = async (e) => {
    e.preventDefault();
    await doOpen(envStr, env);
  };
  $('open-passkey-btn').onclick = async () => {
    await doOpen(envStr, env);
  };
}

async function doOpen(envStr, env) {
  $('open-err').hidden = true;
  const creds = {};
  if (!$('open-pw-wrap').hidden && $('open-pw').value) creds.password = $('open-pw').value;
  if (currentLink.tail) creds.embeddedPassword = currentLink.tail;
  if (!$('open-keyfile-wrap').hidden && $('open-keyfile').files?.[0]) {
    creds.privateKeys = JSON.parse(await readFileText($('open-keyfile')));
  }

  // time-lock UX
  const tl = env.meta?.time;
  if (tl) {
    $('timelock-box').hidden = false;
    const eta = hashRate ? formatDuration((tl.n / hashRate) * 1000) : 'a while';
    $('timelock-eta').textContent = `≈ ${eta} on this device`;
    $('open-btn').disabled = true;
    $('open-passkey-btn').disabled = true;
  }

  try {
    const r = await open(envStr, creds);
    showResult(r, env);
  } catch (e2) {
    err(e2);
  } finally {
    $('timelock-box').hidden = true;
    $('open-btn').disabled = false;
    $('open-passkey-btn').disabled = false;
  }
}

function showResult(r, env) {
  $('open-result').hidden = false;
  $('open-form').hidden = true;
  $('open-passkey-btn').hidden = true;
  const sealEl = $('wax-seal');
  sealEl.classList.remove('stamping');
  sealEl.classList.add('broken', 'breaking');
  if (r.type === 'url') {
    $('result-title').textContent = 'Unsealed';
    $('result-url-wrap').hidden = false;
    $('result-text-wrap').hidden = true;
    $('result-url').textContent = r.data;
    let host = r.data;
    try {
      host = new URL(r.data).hostname;
    } catch {
      /* raw string */
    }
    $('continue-host').textContent = host;
    $('continue-btn').onclick = () => location.replace(r.data);
  } else {
    $('result-title').textContent = 'Secret text';
    $('result-url-wrap').hidden = true;
    $('result-text-wrap').hidden = false;
    $('result-text').value = r.data;
    $('result-text-copy').onclick = () => {
      navigator.clipboard.writeText(r.data);
      $('result-text-copy').textContent = 'copied ✓';
    };
  }
  if (env?.meta?.sig?.length) {
    $('result-sig').textContent = `Signed by ${env.meta.sig.map((s) => s.name).join(', ')}`;
  }
  $('open-result').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// -------------------------------------------------------------- prove

async function runProve() {
  const out = $('prove-out');
  try {
    const res = await fetch('/api/prove');
    const data = await res.json();
    out.textContent = JSON.stringify(data, null, 2) + '\n\n// note: the fragment (#...) never appears above because\n// browsers never transmit it. Your link data never reached this server.';
  } catch {
    out.textContent =
      '// /api/prove is unavailable on this static host.\n' +
      '// That is itself the proof: this page is a static file. The sealed\n' +
      '// part of the link lives after "#", and browsers never send fragments\n' +
      '// to servers. Deploy the Worker (see README) for the live check.';
  }
}

// --------------------------------------------------------------- init

function bindStatic() {
  $('brand-home').addEventListener('click', () => (location.hash = ''));
  document.querySelectorAll('.nav-btn').forEach((b) => {
    b.addEventListener('click', () => showView(b.dataset.view));
  });
  $('source-link').href = CFG.file('site/public/app.js');
  $('footer-repo').href = CFG.repo;
  $('footer-spec').href = CFG.file('spec/ENVELOPE.md');
  $('footer-security').href = CFG.file('SECURITY.md');
  $('prove-btn').addEventListener('click', runProve);
  $('copy-btn').addEventListener('click', () => {
    $('link-out').select();
    navigator.clipboard.writeText($('link-out').value).catch(() => document.execCommand('copy'));
  });
  $('share-btn').addEventListener('click', async () => {
    try {
      await navigator.share({ title: 'Sealed link', text: $('link-out').value });
    } catch {
      /* user cancelled */
    }
  });
  $('new-link-btn').addEventListener('click', () => {
    $('create-result').hidden = true;
    showView('create');
  });
  $('gen-pass-use').addEventListener('click', () => {
    const last = [...document.querySelectorAll('#methods .method-row input[type="password"]')].pop();
    if (last) last.value = $('gen-pass-out').value;
  });
  document.querySelectorAll('input[name="payload-type"]').forEach((r) => {
    r.addEventListener('change', () => {
      const isUrl = document.querySelector('input[name="payload-type"]:checked').value === 'url';
      $('payload-url').hidden = !isUrl;
      $('payload-text').hidden = isUrl;
    });
  });
  document.querySelectorAll('[data-method]').forEach((b) => {
    b.addEventListener('click', () => addMethodRow(b.dataset.method));
  });
  $('gen-pass').addEventListener('click', async () => {
    try {
      $('gen-pass-out').value = await generatePassphrase(8);
      $('gen-pass-use').hidden = false;
    } catch (e2) {
      $('gen-pass-out').placeholder = 'wordlist failed to load';
    }
  });
  $('gen-identity').addEventListener('click', async () => {
    try {
      const name = $('identity-name').value.trim() || 'anonymous';
      const id = await generateSignerIdentity(name);
      signerIdentity = id;
      download(`seal-identity-${name.replace(/\W+/g, '-')}.json`, JSON.stringify(id, null, 2));
      $('identity-status').textContent = `Identity “${name}” generated (Ed25519 + ML-DSA-65) and downloaded. Links you create will be signed with it.`;
    } catch (e2) {
      $('identity-status').textContent = '⚠ identity generation not supported in this browser';
    }
  });
  $('identity-file').addEventListener('change', async () => {
    try {
      const text = await readFileText($('identity-file'));
      if (!text) return;
      signerIdentity = JSON.parse(text);
      $('identity-status').textContent = `Signing as “${signerIdentity.name}”.`;
    } catch {
      $('identity-status').textContent = '⚠ could not read identity file';
    }
  });
  $('create-form').addEventListener('submit', onCreate);
}

async function init() {
  bindStatic();
  // prefill from ?url= (Slack, Raycast, shortcuts, bookmarklet)
  const pre = new URLSearchParams(location.search).get('url');
  if (pre) {
    showView('create');
    $('payload-url').value = pre;
    if (![...document.querySelectorAll('#methods .method-row')].length) addMethodRow('pass');
  } else {
    addMethodRow('pass');
  }
  estimateHashRate().then((r) => (hashRate = r)).catch(() => {});
  await route();
}

init();
