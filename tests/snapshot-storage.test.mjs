// SPDX-License-Identifier: GPL-3.0-only
// Real local files + an explicit fake storage contract. NOT Rust/core/peer/GnuPG/Immich proof.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { StorageBridgeError } from '../src/core-storage.mjs';
import { parseArguments, runSnapshotStorage } from '../scripts/snapshot-storage.mjs';

const CIPHER = Buffer.from('opaque synthetic ciphertext placeholder, not an actual encrypted photo archive');
const HASH = createHash('sha256').update(CIPHER).digest('hex');
const SCRIPT = fileURLToPath(new URL('../scripts/snapshot-storage.mjs', import.meta.url));

async function setup(t) {
  const root = await mkdtemp(join(tmpdir(), 'image-snapshot-storage-'));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true }));
  const bundle = join(root, 'snapshot');
  await mkdir(bundle, { mode: 0o700 });
  await writeFile(join(bundle, 'snapshot.pgp'), CIPHER, { mode: 0o600 });
  // Deliberately a symlink to a missing path: any attempt to open/copy a key is a bug.
  await symlink(join(root, 'MUST-NOT-READ-RECOVERY-KEY'), join(bundle, 'recovery.key'));
  const receipt = { version: 1, kind: 'volparossa-immich-snapshot', cipher_file: 'snapshot.pgp',
    cipher_sha256: HASH, cipher_bytes: CIPHER.length, encryption: 'OpenPGP-AES256',
    source_consistency: 'operator-asserted-quiesced-copy' };
  const receiptPath = join(bundle, 'receipt.json');
  await writeFile(receiptPath, JSON.stringify(receipt), { mode: 0o600 });
  const config = { version: 1, coreBinary: process.execPath, controlSocket: join(root, 'control.sock'),
    identity: join(root, 'identity'), passphraseFile: join(root, 'passphrase'), stateDirectory: join(root, 'journal'),
    providers: ['11', '22', '33'].map(key => ({ key: key.repeat(32), grant: join(root, `grant-${key}`) })),
    copies: 2, fragmentBytes: 16 * 1024 ** 2, lifetimeSeconds: 604800, deadlineMs: 30000 };
  const configPath = join(root, 'storage.json');
  await writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
  const calls = [];
  let nextStatus = 'complete';
  let nextCode = 'ok';
  const fake = Object.fromEntries(['create', 'deposit', 'status', 'progress', 'restore', 'renew', 'delete'].map(operation =>
    [operation, async (...args) => {
      calls.push({ operation, args });
      if (operation === 'create') {
        try { await mkdir(config.stateDirectory, { mode: 0o700 }); }
        catch { throw new StorageBridgeError('output_exists'); }
        await writeFile(join(config.stateDirectory, 'original-journal'), 'stable-placement', { mode: 0o600 });
      }
      if (operation === 'restore' && nextStatus === 'complete') {
        await writeFile(args[0].output, CIPHER, { mode: 0o600, flag: 'wx' });
      }
      return { version: 1, operation, status: nextStatus, code: nextCode,
        local_process_joined: true, remote_cleanup_confirmed: false,
        restore_verified: operation === 'restore' && nextStatus === 'complete',
        storage: { logical_ciphertext_bytes: CIPHER.length, read_consumes_archive: false } };
    }]));
  let opens = 0;
  const storageFactory = async value => { assert.equal(value, configPath); opens++; return fake; };
  const options = operation => ({ operation, config: configPath });
  return { root, bundle, receipt, receiptPath, config, configPath, calls, fake, storageFactory, options,
    get opens() { return opens; }, status(value, code = 'test_retained_incomplete') { nextStatus = value; nextCode = code; } };
}

test('create and deposit take only the exact receipt-verified snapshot.pgp, never the key/bundle', async t => {
  const f = await setup(t);
  const created = await runSnapshotStorage({ ...f.options('create'), bundle: f.bundle }, f);
  const deposited = await runSnapshotStorage({ ...f.options('deposit'), bundle: f.bundle }, f);
  assert.equal(created.status, 'complete');
  assert.equal(deposited.snapshot_ciphertext_checked, true);
  assert.deepEqual(f.calls.map(call => call.operation), ['create', 'deposit']);
  assert.deepEqual(f.calls[0].args[0], { input: join(f.bundle, 'snapshot.pgp'), sha256: HASH, alreadyEncrypted: true });
  assert.deepEqual(f.calls[1].args[0], { input: join(f.bundle, 'snapshot.pgp'), alreadyEncrypted: true });
  assert.equal(await readFile(join(f.config.stateDirectory, 'original-journal'), 'utf8'), 'stable-placement');
  assert.ok(!JSON.stringify(f.calls).includes('recovery.key'));
  assert.equal(created.immich_restore_proven, false);
  assert.equal(deposited.snapshot_decrypted, false);
  assert.ok(!JSON.stringify(deposited).includes(f.root));
});

test('interrupted deposit resumes on identical input/config without recreating journal', async t => {
  const f = await setup(t);
  await runSnapshotStorage({ ...f.options('create'), bundle: f.bundle }, f);
  const before = await lstat(f.config.stateDirectory);
  f.status('incomplete');
  const first = await runSnapshotStorage({ ...f.options('deposit'), bundle: f.bundle }, f);
  assert.equal(first.status, 'incomplete');
  assert.equal(first.remote_cleanup_confirmed, false);
  f.status('complete');
  await runSnapshotStorage(f.options('progress'), f);
  await runSnapshotStorage({ ...f.options('deposit'), bundle: f.bundle }, f);
  assert.deepEqual(f.calls[1].args, f.calls[3].args);
  assert.equal(f.calls.filter(call => call.operation === 'create').length, 1);
  assert.equal((await lstat(f.config.stateDirectory)).ino, before.ino);
  assert.equal(await readFile(join(f.config.stateDirectory, 'original-journal'), 'utf8'), 'stable-placement');
});

test('repeated create refuses existing journal and leaves originals untouched', async t => {
  const f = await setup(t);
  const request = { ...f.options('create'), bundle: f.bundle };
  await runSnapshotStorage(request, f);
  await assert.rejects(runSnapshotStorage(request, f), { code: 'output_exists' });
  assert.equal(await readFile(join(f.config.stateDirectory, 'original-journal'), 'utf8'), 'stable-placement');
  assert.deepEqual(await readFile(join(f.bundle, 'snapshot.pgp')), CIPHER);
});

test('status/progress/renew/delete forward only their own operation; no automatic create', async t => {
  const f = await setup(t);
  await rm(f.bundle, { recursive: true }); // These journal operations do not require a surviving local bundle.
  for (const operation of ['status', 'progress', 'renew', 'delete']) {
    const options = f.options(operation);
    if (operation === 'renew') options['lifetime-seconds'] = '3600';
    await runSnapshotStorage(options, f);
  }
  assert.deepEqual(f.calls.map(call => call.operation), ['status', 'progress', 'renew', 'delete']);
  assert.deepEqual(f.calls[2].args[0], { lifetimeSeconds: 3600 });
  assert.equal(f.calls[3].args.length, 1);
});

test('restore uses independently retained original receipt and a new private bundle; does not decrypt', async t => {
  const f = await setup(t);
  await rm(join(f.bundle, 'snapshot.pgp')); // Retrieval must not quietly copy a surviving local archive.
  const output = join(f.root, 'restored-bundle');
  const result = await runSnapshotStorage({ ...f.options('restore'), receipt: f.receiptPath, output }, f);
  assert.deepEqual(f.calls[0].args[0], { output: join(output, 'snapshot.pgp'), sha256: HASH });
  assert.equal(result.recovery_bundle_ready, true);
  assert.equal(result.snapshot_decrypted, false);
  assert.equal(result.immich_restore_proven, false);
  assert.deepEqual(await readFile(join(output, 'snapshot.pgp')), CIPHER);
  assert.deepEqual(JSON.parse(await readFile(join(output, 'receipt.json'), 'utf8')), f.receipt);
  assert.equal((await lstat(output)).mode & 0o777, 0o700);
  assert.equal((await lstat(join(output, 'receipt.json'))).mode & 0o777, 0o600);
  await assert.rejects(lstat(join(output, 'recovery.key')), { code: 'ENOENT' });
  await assert.rejects(runSnapshotStorage({ ...f.options('restore'), receipt: f.receiptPath, output }, f), { code: 'output_exists' });
  assert.equal(f.calls.length, 1);
});

test('incomplete or unverified restore never publishes success receipt; failed output is retained', async t => {
  const f = await setup(t);
  f.status('incomplete');
  const output = join(f.root, 'incomplete');
  const result = await runSnapshotStorage({ ...f.options('restore'), receipt: f.receiptPath, output }, f);
  assert.equal(result.recovery_bundle_ready, false);
  assert.equal(result.snapshot_ciphertext_checked, false);
  assert.ok((await lstat(output)).isDirectory());
  await assert.rejects(lstat(join(output, 'receipt.json')), { code: 'ENOENT' });
  f.status('complete');
  const original = f.fake.restore;
  f.fake.restore = async (...args) => ({ ...await original(...args), restore_verified: false });
  const unverified = join(f.root, 'unverified');
  await assert.rejects(runSnapshotStorage({ ...f.options('restore'), receipt: f.receiptPath, output: unverified }, f),
    { code: 'restore_not_verified' });
  assert.deepEqual(await readFile(join(unverified, 'snapshot.pgp')), CIPHER);
  await assert.rejects(lstat(join(unverified, 'receipt.json')), { code: 'ENOENT' });
});

test('cipher corruption, wrong length or forged expected hash fail before opening storage', async t => {
  for (const kind of ['contents', 'size', 'hash']) {
    const f = await setup(t);
    if (kind === 'contents') await writeFile(join(f.bundle, 'snapshot.pgp'), Buffer.alloc(CIPHER.length, 0x23));
    if (kind === 'size') await writeFile(join(f.bundle, 'snapshot.pgp'), 'short');
    if (kind === 'hash') await writeFile(f.receiptPath, JSON.stringify({ ...f.receipt, cipher_sha256: 'ab'.repeat(32) }));
    await assert.rejects(runSnapshotStorage({ ...f.options('create'), bundle: f.bundle }, f),
      { code: kind === 'size' ? 'cipher_size_mismatch' : 'cipher_hash_mismatch' });
    assert.equal(f.opens, 0);
  }
});

test('unexpected receipt fields/formats/path or >64GiB reject before core; no extension-based encryption trust', async t => {
  for (const change of [{ cipher_file: 'recovery.key' }, { encryption: 'plaintext' },
    { source_consistency: 'live-database' }, { cipher_bytes: 64 * 1024 ** 3 + 1 },
    { cipher_bytes: 0 }, { cipher_bytes: '100' }, { kind: 'another-archive' },
    { private_names: ['do-not-accept'] }]) {
    const f = await setup(t);
    await writeFile(f.receiptPath, JSON.stringify({ ...f.receipt, ...change }));
    await assert.rejects(runSnapshotStorage({ ...f.options('create'), bundle: f.bundle }, f), { code: 'invalid_snapshot_receipt' });
    assert.equal(f.opens, 0);
  }
});

test('more than 256 fragments rejects before reading the large cipher or creating core state', async t => {
  const f = await setup(t);
  await writeFile(f.configPath, JSON.stringify({ ...f.config, fragmentBytes: 1 }));
  await writeFile(f.receiptPath, JSON.stringify({ ...f.receipt, cipher_bytes: 257 }));
  await assert.rejects(runSnapshotStorage({ ...f.options('create'), bundle: f.bundle }, f), { code: 'invalid_fragment_plan' });
  assert.equal(f.opens, 0);
});

test('sparse >64GiB cipher rejects via stat without allocating/reading its contents', async t => {
  const f = await setup(t);
  await truncate(join(f.bundle, 'snapshot.pgp'), 64 * 1024 ** 3 + 1);
  await assert.rejects(runSnapshotStorage({ ...f.options('deposit'), bundle: f.bundle }, f), { code: 'private_file_required' });
  assert.equal(f.opens, 0);
});

test('receipt/cipher permissions and symlinks reject without leaking paths', async t => {
  for (const name of ['receipt.json', 'snapshot.pgp']) {
    const f = await setup(t);
    await chmod(join(f.bundle, name), 0o644);
    await assert.rejects(runSnapshotStorage({ ...f.options('deposit'), bundle: f.bundle }, f), { code: 'private_file_required' });
    assert.equal(f.opens, 0);
  }
  const f = await setup(t);
  await rm(join(f.bundle, 'snapshot.pgp'));
  await symlink(f.receiptPath, join(f.bundle, 'snapshot.pgp'));
  await assert.rejects(runSnapshotStorage({ ...f.options('deposit'), bundle: f.bundle }, f), error => {
    assert.ok(!error.message.includes(f.root)); return true;
  });
  assert.equal(f.opens, 0);
});

test('restore forbids an existing destination, journal overlap and exposed parent', async t => {
  const f = await setup(t);
  for (const output of [f.bundle, f.config.stateDirectory]) {
    await assert.rejects(runSnapshotStorage({ ...f.options('restore'), receipt: f.receiptPath, output }, f));
  }
  const exposed = join(f.root, 'exposed');
  await mkdir(exposed, { mode: 0o755 });
  await assert.rejects(runSnapshotStorage({ ...f.options('restore'), receipt: f.receiptPath, output: join(exposed, 'new') }, f),
    { code: 'private_directory_required' });
  assert.equal(f.calls.length, 0);
});

test('pre-cancellation never opens storage; signal reaches the actual storage call', async t => {
  const f = await setup(t);
  await assert.rejects(runSnapshotStorage(f.options('status'), { ...f, signal: AbortSignal.abort() }), { code: 'cancelled' });
  assert.equal(f.opens, 0);
  const controller = new AbortController();
  await runSnapshotStorage(f.options('status'), { ...f, signal: controller.signal });
  assert.equal(f.calls[0].args[0].signal, controller.signal);
});

test('storage/receipt byte mismatch cannot become a completed snapshot operation', async t => {
  const f = await setup(t);
  const original = f.fake.deposit;
  f.fake.deposit = async (...args) => ({ ...await original(...args), storage: { logical_ciphertext_bytes: CIPHER.length + 1 } });
  await assert.rejects(runSnapshotStorage({ ...f.options('deposit'), bundle: f.bundle }, f), { code: 'snapshot_size_mismatch' });
});

test('argument parser admits only explicit operation-specific options', () => {
  assert.deepEqual(parseArguments(['renew', '--config', '/private/config', '--lifetime-seconds', '3600']),
    { operation: 'renew', config: '/private/config', 'lifetime-seconds': '3600' });
  for (const argv of [[], ['status', '--config', '/x', '--bundle', '/y'],
    ['restore', '--config', '/x', '--output', '/y'], ['delete', '--config', '/x', '--shell', 'sh'],
    ['renew', '--config', '/x', '--lifetime-seconds', '1e5'], ['create', '--config', '/x', '--bundle', '/y', 'extra'],
    ['status', '--config', '/first', '--config', '/second'],
    ['toString', '--config', '/x']]) assert.throws(() => parseArguments(argv), { code: 'invalid_arguments' });
});

test('actual CLI help and errors are executable and closed, without core startup', () => {
  const help = spawnSync(process.execPath, [SCRIPT, '--help'], { encoding: 'utf8', cwd: dirname(SCRIPT) });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /Only snapshot\.pgp is uploaded/);
  const invalid = spawnSync(process.execPath, [SCRIPT, 'restore', '--secret', 'DO-NOT-PRINT'], { encoding: 'utf8' });
  assert.equal(invalid.status, 1);
  assert.deepEqual(JSON.parse(invalid.stderr), { version: 1, status: 'failed', code: 'invalid_arguments' });
  assert.ok(!invalid.stderr.includes('DO-NOT-PRINT'));
});
