// Magic Router — UI logic. Quiet on the surface: one input, one button.
// Everything exotic lives in the Advanced tab and feeds the same seal flow.
// Encryption, decryption and key derivation run entirely in this browser.

import {
  seal,
  open,
  openLegacy,
  encodeEnvelope,
  decodeEnvelope,
  splitEmbedded,
  isSealedLink,
  isPlainLink,
  encodePlainUrl,
  decodePlainUrl,
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
import { ensureDeepDict } from './lib/dict.js';

const CFG = {
  repo: 'https://github.com/Edvin-Kjall/Magic-router',
  file: (p) => `${CFG.repo}/blob/main/${p}`,
};

const $ = (id) => document.getElementById(id);

let hashRate = 0;
let signerIdentity = null; // { name, ed25519, mldsa65 }
let currentLink = null; // { str, env?, tail, mode, hostedMeta? }
let wordlist = null;
let qrRendered = false;

// ------------------------------------------------------------- helpers

function showView(name) {
  for (const v of ['create', 'open', 'advanced', 'about']) {
    $('view-' + v).hidden = v !== name;
  }
  for (const b of document.querySelectorAll('.nav-btn')) {
    b.classList.toggle('active', b.dataset.view === name);
  }
}

function err(e, target = 'create') {
  const box = $(target === 'create' ? 'create-err' : 'open-err');
  const msg = e instanceof SealError ? e.message : e?.message || String(e);
  box.textContent = msg;
  box.hidden = false;
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
  wordlist = text.split('\n').map((l) => l.split('\t')[1]).filter(Boolean);
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

// -------------------------------------------------------- advanced state

function activeAdvanced() {
  const out = [];
  if ($('adv-prf').checked) out.push('Passkey');
  if ($('adv-pub').checked) out.push('Recipient key');
  if ($('adv-pw2').checked) out.push('Second password');
  if ($('adv-thr').checked) out.push('Require all');
  if ($('adv-embed').checked) out.push('Auto-open');
  if ($('adv-timelock').value !== 'off') out.push('Time-lock ' + $('adv-timelock').value);
  if ($('adv-expiry').value) out.push('Expires');
  if ($('adv-sign').checked) out.push('Signed' + ($('adv-sign-pq').checked ? ' (PQ)' : ''));
  if ($('adv-note').value.trim()) out.push('Note');
  if ($('adv-path').checked) out.push('Path-style');
  if ($('adv-preview').checked) out.push('Preview');
  if ($('adv-plain').checked) out.push('Short (no encryption)');
  return out;
}

function updateAdvancedSummary() {
  const items = activeAdvanced();
  const pill = $('advanced-summary');
  if (!items.length) {
    pill.hidden = true;
    return;
  }
  $('advanced-summary-text').textContent = 'Advanced on: ' + items.join(' · ');
  pill.hidden = false;
}

function clearAdvanced() {
  for (const id of ['adv-prf', 'adv-pub', 'adv-pw2', 'adv-thr', 'adv-embed', 'adv-sign', 'adv-sign-pq', 'adv-path', 'adv-preview', 'adv-plain']) {
    $(id).checked = false;
  }
  $('adv-timelock').value = 'off';
  $('adv-expiry').value = '';
  $('adv-note').value = '';
  $('adv-pw2-value').value = '';
  $('adv-pub-file').value = '';
  $('adv-identity-file').value = '';
  $('adv-identity-name').value = '';
  signerIdentity = null;
  $('identity-status').textContent = '';
  refreshAdvancedRows();
  updateAdvancedSummary();
}

function refreshAdvancedRows() {
  $('adv-pub-row').hidden = !$('adv-pub').checked;
  $('adv-pw2-row').hidden = !$('adv-pw2').checked;
  $('adv-sign-row').hidden = !$('adv-sign').checked;
  $('adv-sign-pq').closest('.switch-row').hidden = !$('adv-sign').checked;
  $('adv-thr').disabled = !($('adv-prf').checked || $('adv-pub').checked || $('adv-pw2').checked);
}

// ------------------------------------------------------------- create

function buildSealOpts() {
  const raw = $('payload').value.trim();
  if (!raw) throw new SealError('What are you protecting? Paste a link or a secret first.');
  const type = /^https?:\/\//i.test(raw) ? 'url' : 'text';
  const opts = { type, data: raw };

  const pw = $('pw').value;
  const passwords = [];
  let methodCount = 0;

  if ($('adv-embed').checked) {
    if (!pw) throw new SealError('Auto-open uses the password field — type one first.');
    opts.embedded = pw;
    methodCount++;
  } else if (pw) {
    passwords.push(pw);
    methodCount++;
  }
  if ($('adv-pw2').checked) {
    const p2 = $('adv-pw2-value').value;
    if (!p2) throw new SealError('Second password is on — fill in their password (Advanced tab).');
    passwords.push(p2);
    methodCount++;
  }
  if ($('adv-prf').checked) {
    opts.prf = true;
    methodCount++;
  }
  if ($('adv-pub').checked) {
    const f = $('adv-pub-file').files?.[0];
    if (!f) throw new SealError('Recipient key is on — pick their public key file (Advanced tab).');
    opts.recipient = f;
    methodCount++;
  }
  if (passwords.length) opts.passwords = passwords;
  if (!methodCount) throw new SealError('Add a password first — or use Advanced for passkeys and keys.');

  if ($('adv-thr').checked) {
    if (methodCount < 2) throw new SealError('"Require every method" needs at least two methods.');
    opts.threshold = methodCount;
  }
  const tl = $('adv-timelock').value;
  return { opts, tl };
}

async function onCreate(e) {
  e.preventDefault();
  $('create-err').hidden = true;
  const btn = $('create-btn');
  btn.disabled = true;
  btn.textContent = 'Sealing…';
  try {
    // Plain mode: no encryption, just compression. Anyone with the link can
    // read the destination — short, stateless, frictionless.
    if ($('adv-plain').checked) {
      const raw = $('payload').value.trim();
      if (!/^https?:\/\//i.test(raw)) throw new SealError('Short mode needs a URL — it must start with https://');
      const full = await encodePlainUrl(raw);
      // encodePlainUrl returns the URL itself when compression can't win —
      // never wrap a non-link in the router prefix in that case.
      const isLink = full !== raw;
      const linkUrl = !isLink
        ? raw
        : $('adv-path').checked
          ? `${location.origin}/_u/${full}`
          : `${location.origin}/#${full}`;
      $('link-out').value = linkUrl;
      if (!isLink) {
        $('result-hint').textContent =
          'No compression win: this URL would only get longer as a link, so here it is unchanged. Sharing it directly is the shortest possible form.';
      } else if (linkUrl.length >= raw.length) {
        // Honesty: the router's own host prefix means short destinations
        // are shorter on their own.
        $('result-hint').textContent =
          `Your destination is already short (${raw.length} characters) — this link would be longer than just sharing the URL itself. No shortening service can beat a URL this small.`;
      } else {
        $('result-hint').textContent =
          'This link is not encrypted — anyone with it can see and open the destination. Short, but no secrets.';
      }
      $('create-form').hidden = true;
      $('create-result').hidden = false;
      qrRendered = false;
      $('qr-canvas').hidden = true;
      $('qr-toggle').textContent = 'Show QR code';
      const orb = $('seal-orb');
      orb.classList.remove('stamping');
      void orb.offsetWidth;
      orb.classList.add('stamping');
      $('share-btn').hidden = typeof navigator.share !== 'function';
      return;
    }
    const { opts, tl } = buildSealOpts();
    if (opts.recipient instanceof File) {
      opts.recipient = JSON.parse(await opts.recipient.text());
    }
    if (tl !== 'off') {
      opts.timeLock = await makeTimeLock(parseDuration(tl), hashRate || 1e6);
    }
    if ($('adv-preview').checked) opts.preview = true;
    if ($('adv-expiry').value) opts.expiry = $('adv-expiry').value;
    if ($('adv-note').value.trim()) opts.note = $('adv-note').value.trim();
    if ($('adv-sign').checked) {
      if (!signerIdentity) throw new SealError('Signing is on — generate or upload an identity (Advanced tab).');
      opts.signer = signerIdentity;
      opts.pq = $('adv-sign-pq').checked;
    }

    const env = await seal(opts);
    const frag = await encodeEnvelope(env);
    const tail = opts.embedded != null ? '.' + encodeURIComponent(opts.embedded) : '';
    const full = frag + tail;
    currentLink = { str: full, env };
    const linkUrl = $('adv-path').checked
      ? `${location.origin}/_u/${full}`
      : `${location.origin}/#${full}`;
    $('link-out').value = linkUrl;
    $('result-hint').textContent =
      'Share it however you like. Send the password separately — a different message or app is strongest.';

    $('create-form').hidden = true;
    $('create-result').hidden = false;
    qrRendered = false;
    $('qr-canvas').hidden = true;
    $('qr-toggle').textContent = 'Show QR code';
    const orb = $('seal-orb');
    orb.classList.remove('stamping');
    void orb.offsetWidth;
    orb.classList.add('stamping');
    $('share-btn').hidden = typeof navigator.share !== 'function';
  } catch (e2) {
    err(e2);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Seal Link';
  }
}

function resetCreate() {
  $('create-result').hidden = true;
  $('create-form').hidden = false;
  $('payload').value = '';
  $('pw').value = '';
  $('pw').type = 'password';
  $('pw-toggle').textContent = '👁';
  $('create-err').hidden = true;
  $('seal-orb').classList.remove('stamping');
}

// --------------------------------------------------------------- open

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
  $('open-sealed').hidden = false;
  $('open-result').hidden = true;
  $('open-gone').hidden = true;
  $('open-form').hidden = false;
  try {
    if (link.mode === 'hosted') {
      const res = await fetch(`/api/link/${encodeURIComponent(link.slug)}`);
      if (!res.ok) {
        $('open-form').hidden = true;
        $('open-gone').hidden = false;
        return;
      }
      const body = await res.json();
      // Premium short slugs: plaintext redirect, no unlock step.
      if (body.redirect) {
        location.replace(body.redirect);
        return;
      }
      currentLink = { str: body.envelope, tail: null, mode: 'hosted', hostedMeta: body.meta };
      await beginOpen(body.envelope, null, body.meta);
    } else {
      let str = link.str;
      try {
        str = decodeURIComponent(str);
      } catch {
        /* keep raw */
      }
      // Stateless short mode: unencrypted, compressed URL — open instantly.
      if (isPlainLink(str)) {
        const url = await decodePlainUrl(str);
        if (/^https?:\/\//i.test(url)) {
          location.replace(url);
          return;
        }
        showView('create');
        return;
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
    err(e2, 'open');
  }
}

function legacyOpen(str) {
  $('open-pw-wrap').hidden = false;
  $('open-keyfile-wrap').hidden = true;
  $('open-passkey-btn').hidden = true;
  $('open-host').textContent = 'Legacy link';
  $('open-thr').hidden = false;
  $('open-thr').textContent = 'An older link format. Enter its password.';
  $('open-form').onsubmit = async (e) => {
    e.preventDefault();
    $('open-err').hidden = true;
    try {
      const r = await openLegacy(str, $('open-pw').value);
      showResult(r, null);
    } catch (e2) {
      err(e2, 'open');
    }
  };
}

async function beginOpen(envStr, tail, hostedMeta) {
  const env = await decodeEnvelope(envStr);
  currentLink.env = env;
  const d = describeEnvelope(env);

  $('open-host').textContent = d.host ? `→ ${d.host}` : '';
  const scanLine = $('open-scan-line');
  if (d.host) {
    scanLine.hidden = false;
    $('open-scan-link').href =
      'https://transparencyreport.google.com/safe-browsing/search?url=' + encodeURIComponent(d.host);
  } else {
    scanLine.hidden = true;
  }
  $('open-note').hidden = !d.note;
  $('open-note').textContent = d.note ? `“${d.note}”` : '';
  const ex = expiryStatus(env.meta);
  $('open-exp').textContent = '';
  if (ex) {
    $('open-exp').textContent = ex.expired
      ? ' · expired'
      : ` · expires ${new Date(ex.at).toLocaleDateString()}`;
  }
  if (hostedMeta?.fetches != null) $('open-exp').textContent += ` · opened ${hostedMeta.fetches}×`;

  const sigs = await verifySignatures(env);
  $('open-sig-results').hidden = !sigs.length;
  if (sigs.length) {
    // Group by name: "Sealed by alice ✓ (Ed25519 + ML-DSA-65)" or ✗.
    const byName = new Map();
    for (const s of sigs) {
      if (!byName.has(s.name)) byName.set(s.name, []);
      byName.get(s.name).push(s);
    }
    const parts = [];
    for (const [name, list] of byName) {
      const ok = list.every((s) => s.ok);
      const algs = list.map((s) => s.alg).join(' + ');
      parts.push(`${name} ${ok ? '✓' : '— signature invalid ✗'} (${algs})`);
    }
    $('open-sig-results').textContent = 'Sealed by ' + parts.join(', ');
  }

  $('open-thr').hidden = !env.thr;
  if (env.thr) {
    $('open-thr').textContent = `This link needs ${env.thr.m} of ${env.thr.n} credentials. Give it what you have and unlock.`;
  }

  const kinds = new Set(d.methods);
  $('open-pw-wrap').hidden = !kinds.has('pass');
  $('open-keyfile-wrap').hidden = !kinds.has('pub');
  $('open-passkey-btn').hidden = !kinds.has('prf');

  if (kinds.has('embed') && tail) {
    $('open-form').hidden = true;
    $('open-err').hidden = true;
    try {
      const r = await open(envStr, { embeddedPassword: tail });
      // Auto-open mode: the password traveled in the link, so redirect
      // straight to the destination. Secret text still shows here.
      if (r.type === 'url') {
        location.replace(r.data);
        return;
      }
      showResult(r, env);
      return;
    } catch (e2) {
      err(e2, 'open');
      $('open-form').hidden = false;
    }
  }

  $('open-form').hidden = false;
  $('open-form').onsubmit = async (e) => {
    e.preventDefault();
    await doOpen(envStr, env);
  };
  $('open-passkey-btn').onclick = async () => doOpen(envStr, env);
}

async function doOpen(envStr, env) {
  $('open-err').hidden = true;
  const creds = {};
  if (!$('open-pw-wrap').hidden && $('open-pw').value) creds.password = $('open-pw').value;
  if (currentLink.tail) creds.embeddedPassword = currentLink.tail;
  if (!$('open-keyfile-wrap').hidden && $('open-keyfile').files?.[0]) {
    creds.privateKeys = JSON.parse(await readFileText($('open-keyfile')));
  }

  const tl = env.meta?.time;
  if (tl) {
    $('timelock-box').hidden = false;
    $('timelock-eta').textContent = hashRate
      ? `about ${formatDuration((tl.n / hashRate) * 1000)}`
      : 'a little while';
    $('open-btn').disabled = true;
    $('open-passkey-btn').disabled = true;
  }
  try {
    const r = await open(envStr, creds);
    showResult(r, env);
  } catch (e2) {
    err(e2, 'open');
  } finally {
    $('timelock-box').hidden = true;
    $('open-btn').disabled = false;
    $('open-passkey-btn').disabled = false;
  }
}

function showResult(r, env) {
  $('open-sealed').hidden = true;
  $('open-form').hidden = true;
  $('open-passkey-btn').hidden = true;
  $('open-result').hidden = false;
  const orb = $('seal-orb-open');
  orb.classList.add('broken');
  if (r.type === 'url') {
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
    // Google Safe Browsing — official Google verdict for the exact URL,
    // free, no account. Opens in a new tab with no referrer.
    $('scan-btn').onclick = () => {
      window.open(
        'https://transparencyreport.google.com/safe-browsing/search?url=' + encodeURIComponent(r.data),
        '_blank',
        'noopener,noreferrer'
      );
    };
  } else {
    $('result-url-wrap').hidden = true;
    $('result-text-wrap').hidden = false;
    $('result-text').value = r.data;
    $('result-text-copy').onclick = () => {
      navigator.clipboard.writeText(r.data);
      $('result-text-copy').textContent = 'Copied ✓';
    };
  }
}

// --------------------------------------------------------------- prove

async function runProve() {
  const out = $('prove-out');
  out.hidden = false;
  try {
    const res = await fetch('/api/prove');
    const data = await res.json();
    out.textContent = JSON.stringify(data, null, 2);
  } catch {
    out.textContent =
      'This static host has no server API — which is itself the proof: everything\n' +
      'you sealed lives after the "#", and browsers never send fragments to servers.\n' +
      'Deploy the Worker (see the repo README) for the live confession.';
  }
}

// ---------------------------------------------------------------- init

function bindStatic() {
  $('brand-home').addEventListener('click', () => {
    location.hash = '';
    showView('create');
  });
  document.querySelectorAll('.nav-btn').forEach((b) => {
    b.addEventListener('click', () => showView(b.dataset.view));
  });

  $('footer-repo').href = CFG.repo;
  $('footer-spec').href = CFG.file('spec/ENVELOPE.md');
  $('footer-security').href = CFG.file('SECURITY.md');
  $('footer-prove').addEventListener('click', (e) => {
    e.preventDefault();
    showView('about');
  });
  $('prove-btn').addEventListener('click', runProve);

  // Tresorit Send: jump to Create with the file link prefilled
  $('seal-tresorit-btn').addEventListener('click', () => {
    const v = $('tresorit-link-in').value.trim();
    if (!/^https?:\/\//i.test(v)) {
      $('tresorit-link-in').focus();
      return;
    }
    showView('create');
    $('payload').value = v;
    $('payload').scrollIntoView({ behavior: 'smooth', block: 'center' });
    $('pw').focus();
  });

  // create
  $('create-form').addEventListener('submit', onCreate);
  $('pw-toggle').addEventListener('click', () => {
    const p = $('pw');
    p.type = p.type === 'password' ? 'text' : 'password';
    $('pw-toggle').textContent = p.type === 'password' ? '👁' : '🙈';
  });
  $('gen-pass').addEventListener('click', async () => {
    try {
      const p = $('pw');
      p.value = await generatePassphrase(8);
      p.type = 'text';
      $('pw-toggle').textContent = '🙈';
    } catch {
      $('gen-pass').textContent = 'Passphrase list failed to load';
    }
  });
  $('copy-btn').addEventListener('click', () => {
    $('link-out').select();
    navigator.clipboard.writeText($('link-out').value).catch(() => document.execCommand('copy'));
    $('copy-btn').textContent = 'Copied ✓';
    setTimeout(() => ($('copy-btn').textContent = 'Copy link'), 1500);
  });
  $('share-btn').addEventListener('click', async () => {
    try {
      await navigator.share({ title: 'Sealed link', text: $('link-out').value });
    } catch {
      /* cancelled */
    }
  });
  $('new-link-btn').addEventListener('click', resetCreate);
  $('qr-toggle').addEventListener('click', async () => {
    const canvas = $('qr-canvas');
    if (canvas.hidden) {
      canvas.hidden = false;
      $('qr-toggle').textContent = 'Hide QR code';
      if (!qrRendered) {
        await toCanvas(canvas, $('link-out').value, { width: 240, margin: 1 });
        qrRendered = true;
      }
    } else {
      canvas.hidden = true;
      $('qr-toggle').textContent = 'Show QR code';
    }
  });

  // advanced
  for (const id of ['adv-prf', 'adv-pub', 'adv-pw2', 'adv-thr', 'adv-embed', 'adv-sign', 'adv-sign-pq', 'adv-path', 'adv-preview', 'adv-plain']) {
    $(id).addEventListener('change', () => {
      refreshAdvancedRows();
      updateAdvancedSummary();
    });
  }
  for (const id of ['adv-timelock', 'adv-expiry', 'adv-note']) {
    $(id).addEventListener('change', updateAdvancedSummary);
  }
  $('advanced-clear').addEventListener('click', clearAdvanced);
  $('gen-keypair').addEventListener('click', async () => {
    try {
      const kp = await generateRecipientKeypair();
      download('seal-key.json', JSON.stringify(kp, null, 2));
      $('identity-status').textContent =
        'Key pair downloaded. Give seal-key.json to the recipient; to seal TO them, upload the same file above.';
    } catch (e2) {
      $('identity-status').textContent = '⚠ key generation failed in this browser';
    }
  });
  $('gen-identity').addEventListener('click', async () => {
    try {
      const name = $('adv-identity-name').value.trim() || 'anonymous';
      const id = await generateSignerIdentity(name);
      signerIdentity = id;
      download(`seal-identity-${name.replace(/\W+/g, '-')}.json`, JSON.stringify(id, null, 2));
      $('identity-status').textContent = `Identity “${name}” generated and downloaded (Ed25519 + ML-DSA-65).`;
      updateAdvancedSummary();
    } catch {
      $('identity-status').textContent = '⚠ identity generation not supported in this browser';
    }
  });
  $('adv-identity-file').addEventListener('change', async () => {
    try {
      const text = await readFileText($('adv-identity-file'));
      if (!text) return;
      signerIdentity = JSON.parse(text);
      $('identity-status').textContent = `Signing as “${signerIdentity.name}”.`;
    } catch {
      $('identity-status').textContent = '⚠ could not read identity file';
    }
  });
}

async function init() {
  bindStatic();
  refreshAdvancedRows();

  // Warm the deep dictionary cache in the background: first seal/open of a
  // deep link then needs no wait at all.
  ensureDeepDict().catch(() => {});

  const pre = new URLSearchParams(location.search).get('url');
  if (pre) {
    showView('create');
    $('payload').value = pre;
  }

  estimateHashRate().then((r) => (hashRate = r)).catch(() => {});
  await route();
}

init();
