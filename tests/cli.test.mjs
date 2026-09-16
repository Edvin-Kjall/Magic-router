// CLI round-trip tests: create links with node cli/seal.mjs, open them back.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const CLI = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'cli', 'seal.mjs');
const URL_TARGET = 'https://example.com/cli-secret?x=1';

async function sealCli(...args) {
  const { stdout } = await run(process.execPath, [CLI, 'create', '--json', ...args], { timeout: 120000 });
  return JSON.parse(stdout.trim().split('\n').pop());
}

async function openCli(link, ...args) {
  const { stdout } = await run(process.execPath, [CLI, 'open', '--json', link, ...args], { timeout: 120000 });
  return JSON.parse(stdout.trim());
}

test('cli: password round trip', async () => {
  const { fragment } = await sealCli('--url', URL_TARGET, '--password', 'cli-pass');
  assert.ok(fragment.startsWith('s6.'));
  const r = await openCli(fragment, '--password', 'cli-pass');
  assert.equal(r.data, URL_TARGET);
  assert.equal(r.type, 'url');
});

test('cli: wrong password exits non-zero', async () => {
  const { fragment } = await sealCli('--url', URL_TARGET, '--password', 'right');
  await assert.rejects(openCli(fragment, '--password', 'wrong'), (err) => err.code === 1);
});

test('cli: embedded password auto-open', async () => {
  const { fragment } = await sealCli('--url', URL_TARGET, '--embed', 'hunter2');
  const r = await openCli(fragment, '--password', 'unused');
  assert.equal(r.data, URL_TARGET);
});

test('cli: multi-password threshold 2-of-2', async () => {
  const { fragment } = await sealCli('--url', URL_TARGET, '--password', 'aaa', '--password', 'bbb', '--threshold', '2');
  await assert.rejects(openCli(fragment, '--password', 'aaa'), (err) => err.code === 1);
  const r = await openCli(fragment, '--password', 'aaa', '--password', 'bbb');
  assert.equal(r.data, URL_TARGET);
});

test('cli: recipient keypair round trip', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'seal-cli-'));
  try {
    const keyfile = join(dir, 'seal-key.json');
    await run(process.execPath, [CLI, 'keygen', '--recipient', '--out', keyfile], { timeout: 60000 });
    const kp = JSON.parse(readFileSync(keyfile, 'utf8'));
    assert.ok(kp.x25519.priv && kp.mlkem.priv);

    const { fragment } = await sealCli('--url', URL_TARGET, '--recipient', keyfile);
    const wrongDir = mkdtempSync(join(tmpdir(), 'seal-cli-wrong-'));
    const wrongKey = join(wrongDir, 'k.json');
    await run(process.execPath, [CLI, 'keygen', '--recipient', '--out', wrongKey], { timeout: 60000 });
    await assert.rejects(openCli(fragment, '--key', wrongKey), (err) => err.code === 1);

    const r = await openCli(fragment, '--key', keyfile);
    assert.equal(r.data, URL_TARGET);
    rmSync(wrongDir, { recursive: true, force: true });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('cli: signed links verify', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'seal-cli-'));
  try {
    const idfile = join(dir, 'alice.json');
    await run(process.execPath, [CLI, 'keygen', '--identity', 'alice', '--out', idfile], { timeout: 60000 });
    const { fragment } = await sealCli('--url', URL_TARGET, '--password', 'pw', '--sign', idfile);
    const { stdout } = await run(process.execPath, [CLI, 'info', fragment], { timeout: 60000 });
    const info = JSON.parse(stdout);
    assert.ok(info.signed.includes('alice'));
    assert.ok(info.signatures.some((s) => s.includes('alice/') && s.endsWith(':ok')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('cli: time-locked link', async () => {
  const { fragment } = await sealCli('--url', URL_TARGET, '--password', 'pw', '--delay', '200ms');
  const r = await openCli(fragment, '--password', 'pw');
  assert.equal(r.data, URL_TARGET);
});

test('cli: full URL input with fragment works', async () => {
  const { fragment } = await sealCli('--url', URL_TARGET, '--password', 'pw');
  const r = await openCli('https://seal.example/#' + fragment, '--password', 'pw');
  assert.equal(r.data, URL_TARGET);
});

// ------------------------------------------------- regression: 2026-09 fixes

test('cli: value flags without a value fail instead of sealing with "true"', async () => {
  await assert.rejects(
    run(process.execPath, [CLI, 'create', '--url', URL_TARGET, '--password'], { timeout: 60000 }),
    (err) => err.code === 1 && /--password needs a value/.test(err.stderr)
  );
  await assert.rejects(
    run(process.execPath, [CLI, 'create', '--url', URL_TARGET, '--password', 'pw', '--note'], { timeout: 60000 }),
    (err) => err.code === 1 && /--note needs a value/.test(err.stderr)
  );
});

test('cli: --pw/--pwd aliases are passwords', async () => {
  const { fragment } = await sealCli('--url', URL_TARGET, '--pw', 'alias-pw');
  const r = await openCli(fragment, '--pwd', 'alias-pw');
  assert.equal(r.data, URL_TARGET);
});

test('cli: single-password link opens with multiple candidates', async () => {
  const { fragment } = await sealCli('--url', URL_TARGET, '--password', 'real');
  const r = await openCli(fragment, '--password', 'wrong', '--password', 'real');
  assert.equal(r.data, URL_TARGET);
});

test('cli: opens plain (u0/u1) short links', async () => {
  const { stdout } = await run(
    process.execPath,
    [CLI, 'open', 'https://host/#u0.Cinosida.se/nyheter/a%2525b'],
    { timeout: 60000 }
  );
  assert.equal(stdout.trim(), 'https://inosida.se/nyheter/a%25b');
  const { stdout: out2 } = await run(
    process.execPath,
    [CLI, 'open', 'u1.BHd3dzIuaG0uY29tL3N2X3NlL2RhbS9ueWhldGVyL3NlLWFsbGEuaHRtbD9wcm9kdWN0SWQ9MTM1MTY0OTAwMg'],
    { timeout: 60000 }
  );
  assert.equal(out2.trim(), 'https://www2.hm.com/sv_se/dam/nyheter/se-alla.html?productId=1351649002');
});

test('cli: unknown flags are rejected', async () => {
  await assert.rejects(
    run(process.execPath, [CLI, 'create', '--url', URL_TARGET, '--passwd', 'x'], { timeout: 60000 }),
    (err) => err.code === 1 && /unknown option/.test(err.stderr)
  );
});

test('cli: passphrase generator', async () => {
  const { stdout } = await run(process.execPath, [CLI, 'passphrase', '--words', '4'], { timeout: 60000 });
  const words = stdout.trim().split(/\s+/);
  assert.equal(words.length, 4);
  assert.ok(words.every((w) => /^[a-z]+$/.test(w)), `EFF words only, got ${words}`);
});

test('cli: hosted /s/ links open over the premium API', async () => {
  const { fragment } = await sealCli('--url', URL_TARGET, '--password', 'hosted-pw');
  const srv = createServer((req, res) => {
    if (req.url === '/api/link/testslug') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ envelope: fragment, meta: { fetches: 1, burnt: false, exp: null } }));
    } else {
      res.statusCode = 410;
      res.end(JSON.stringify({ error: 'gone' }));
    }
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const link = `http://127.0.0.1:${srv.address().port}/s/testslug`;
    const r = await openCli(link, '--password', 'hosted-pw');
    assert.equal(r.data, URL_TARGET);
    // a missing slug reports "gone"
    await assert.rejects(
      openCli(`http://127.0.0.1:${srv.address().port}/s/nosuchslug`, '--password', 'x'),
      (err) => err.code === 1 && /gone/.test(err.stderr)
    );
  } finally {
    srv.close();
  }
});

test('cli: --store posts the ciphertext envelope and prints the /s/ link', async () => {
  let captured = null;
  const srv = createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/api/link') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        captured = JSON.parse(body);
        res.setHeader('content-type', 'application/json');
        res.statusCode = 201;
        res.end(JSON.stringify({ slug: captured.slug || 'auto1234', url: 'http://h.test/s/' + (captured.slug || 'auto1234') }));
      });
    } else {
      res.statusCode = 404;
      res.end('{}');
    }
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const host = `http://127.0.0.1:${srv.address().port}`;
    const { stdout } = await run(
      process.execPath,
      [CLI, 'create', '--url', URL_TARGET, '--password', 'pw', '--host', host, '--store', '--slug', 'myslug', '--burn'],
      { timeout: 60000 }
    );
    assert.match(stdout, /http:\/\/h\.test\/s\/myslug/);
    assert.equal(captured.slug, 'myslug');
    assert.equal(captured.burn, true);
    assert.match(captured.envelope, /^s6\./);
    assert.ok(!captured.envelope.slice(3).includes('.'), 'envelope must not carry a tail');
  } finally {
    srv.close();
  }
});

test('cli: --store + --embed is refused (tail can never be hosted)', async () => {
  await assert.rejects(
    run(
      process.execPath,
      [CLI, 'create', '--url', URL_TARGET, '--embed', 'pw', '--host', 'http://x', '--store'],
      { timeout: 60000 }
    ),
    (err) => err.code === 1 && /cannot be hosted/.test(err.stderr)
  );
});

test('cli: npm package layout ships dictionaries and wordlist', async () => {
  // "files" in package.json must cover everything cli/seal.mjs reads at
  // runtime, or an npm-installed seal silently loses deep links and
  // passphrase generation.
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  const files = pkg.files.join('\n');
  for (const needed of ['site/public/data', 'deep-v1.json', 'deep-v2.json']) {
    assert.ok(files.includes(needed), `package.json files must include ${needed}`);
  }
});
