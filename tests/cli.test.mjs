// CLI round-trip tests: create links with node cli/seal.mjs, open them back.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
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
