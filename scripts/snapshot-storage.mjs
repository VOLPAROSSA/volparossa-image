#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// Explicit owner-side orchestration. The core remains the only placement/journal authority.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, join, normalize, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { CoreStorage, StorageBridgeError } from '../src/core-storage.mjs';

const ARCHIVE_MAX = 64 * 1024 ** 3;
const RECEIPT_KEYS = ['version', 'kind', 'cipher_file', 'cipher_sha256', 'cipher_bytes',
  'encryption', 'source_consistency'];
const FLAGS = {
  create: ['config', 'bundle'], deposit: ['config', 'bundle'],
  status: ['config'], progress: ['config'], delete: ['config'],
  restore: ['config', 'receipt', 'output'], renew: ['config', 'lifetime-seconds'],
};

export class SnapshotStorageError extends Error {
  constructor(code) { super(code); this.name = 'SnapshotStorageError'; this.code = code; }
}
function check(condition, code) { if (!condition) throw new SnapshotStorageError(code); }
function integer(value, minimum, maximum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}
function path(value) {
  check(typeof value === 'string' && value.length <= 4096 && isAbsolute(value)
    && value !== sep && normalize(value) === value && !/[\x00-\x1f\x7f]/.test(value), 'invalid_path');
  return value;
}
async function privateDirectory(value) {
  path(value);
  const info = await lstat(value);
  check(info.isDirectory() && info.uid === process.getuid() && (info.mode & 0o7777) === 0o700
    && await realpath(value) === value, 'private_directory_required');
}
function sameFile(left, right) {
  return ['dev', 'ino', 'mode', 'uid', 'nlink', 'size', 'mtimeNs', 'ctimeNs']
    .every(key => left[key] === right[key]);
}
async function privateFile(value, maximum) {
  path(value);
  await privateDirectory(dirname(value));
  const handle = await open(value, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await handle.stat({ bigint: true });
    check(info.isFile() && info.uid === BigInt(process.getuid()) && info.nlink === 1n
      && (info.mode & 0o7777n) === 0o600n && info.size > 0n && info.size <= BigInt(maximum)
      && sameFile(info, await lstat(value, { bigint: true })), 'private_file_required');
    return { handle, info };
  } catch (error) { await handle.close(); throw error; }
}
async function readJson(value, maximum) {
  const { handle, info } = await privateFile(value, maximum);
  try {
    const bytes = Buffer.alloc(Number(info.size) + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    check(offset === Number(info.size) && sameFile(info, await handle.stat({ bigint: true }))
      && sameFile(info, await lstat(value, { bigint: true })), 'local_input_changed');
    try {
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, offset)));
    } catch { throw new SnapshotStorageError('invalid_local_json'); }
  } finally { await handle.close(); }
}
async function receipt(value) {
  const raw = await readJson(value, 4096);
  check(raw !== null && typeof raw === 'object' && !Array.isArray(raw)
    && Object.keys(raw).length === RECEIPT_KEYS.length
    && Object.keys(raw).every(key => RECEIPT_KEYS.includes(key))
    && raw.version === 1 && raw.kind === 'volparossa-immich-snapshot'
    && raw.cipher_file === 'snapshot.pgp' && typeof raw.cipher_sha256 === 'string'
    && /^[a-f0-9]{64}$/.test(raw.cipher_sha256)
    && integer(raw.cipher_bytes, 1, ARCHIVE_MAX) && raw.encryption === 'OpenPGP-AES256'
    && raw.source_consistency === 'operator-asserted-quiesced-copy', 'invalid_snapshot_receipt');
  return Object.freeze(raw);
}
function interrupted(signal, deadline) {
  check(!signal?.aborted, 'cancelled');
  check(Date.now() < deadline, 'timed_out');
}
async function verifyCipher(value, expected, signal, deadline) {
  const { handle, info } = await privateFile(value, ARCHIVE_MAX);
  try {
    check(info.size === BigInt(expected.cipher_bytes), 'cipher_size_mismatch');
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(256 * 1024);
    let offset = 0;
    while (offset < expected.cipher_bytes) {
      interrupted(signal, deadline);
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, expected.cipher_bytes - offset), offset);
      check(bytesRead > 0, 'cipher_changed');
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    check(sameFile(info, await handle.stat({ bigint: true }))
      && sameFile(info, await lstat(value, { bigint: true })), 'cipher_changed');
    check(hash.digest('hex') === expected.cipher_sha256, 'cipher_hash_mismatch');
  } finally { await handle.close(); }
}
function fragmentPlan(config, bytes) {
  check(Array.isArray(config.providers) && integer(config.providers.length, 3, 8)
    && integer(config.fragmentBytes, 1, 1024 ** 3), 'invalid_fragment_plan');
  const size = Math.min(config.fragmentBytes, Math.floor(bytes / config.providers.length));
  check(size > 0 && Math.ceil(bytes / size) <= 256, 'invalid_fragment_plan');
}
async function newBundle(value, stateDirectory) {
  path(value);
  check(value !== stateDirectory && !value.startsWith(`${stateDirectory}${sep}`)
    && !stateDirectory.startsWith(`${value}${sep}`), 'overlapping_restore_journal');
  await privateDirectory(dirname(value));
  try { await mkdir(value, { mode: 0o700 }); }
  catch (error) {
    if (error.code === 'EEXIST') throw new SnapshotStorageError('output_exists');
    throw error;
  }
  await privateDirectory(value);
}
async function writeReceipt(bundle, expected) {
  const handle = await open(join(bundle, 'receipt.json'),
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(`${JSON.stringify(expected)}\n`); await handle.sync(); }
  finally { await handle.close(); }
  const directory = await open(bundle, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await directory.sync(); } finally { await directory.close(); }
}

export function parseArguments(argv) {
  try {
    const { values, positionals, tokens } = parseArgs({ args: argv, strict: true, allowPositionals: true, tokens: true,
      options: Object.fromEntries(['config', 'bundle', 'receipt', 'output', 'lifetime-seconds']
        .map(key => [key, { type: 'string' }])) });
    const operation = positionals[0];
    check(positionals.length === 1 && Object.hasOwn(FLAGS, operation), 'invalid_arguments');
    const required = FLAGS[operation];
    check(Object.keys(values).length === required.length && required.every(key => values[key]), 'invalid_arguments');
    check(tokens.filter(token => token.kind === 'option').length === required.length, 'invalid_arguments');
    if (operation === 'renew') {
      check(/^[1-9][0-9]*$/.test(values['lifetime-seconds'])
        && integer(Number(values['lifetime-seconds']), 1, 2678400), 'invalid_arguments');
    }
    return Object.freeze({ operation, ...values });
  } catch { throw new SnapshotStorageError('invalid_arguments'); }
}

// The factory is an in-process test seam only. The CLI always opens the real CoreStorage bridge.
export async function runSnapshotStorage(options, { signal, storageFactory = value => CoreStorage.open(value) } = {}) {
  try {
    check(Object.hasOwn(FLAGS, options.operation), 'invalid_arguments');
    const { operation, config: configPath } = options;
    interrupted(signal, Infinity);
    const config = await readJson(configPath, 65536);
    check(config !== null && typeof config === 'object' && !Array.isArray(config), 'invalid_configuration');
    path(config.stateDirectory);
    check(integer(config.deadlineMs ?? 1800000, 100, 1800000), 'invalid_configuration');
    const deadline = Date.now() + (config.deadlineMs ?? 1800000);
    let expected;
    let input;
    if (operation === 'create' || operation === 'deposit') {
      await privateDirectory(options.bundle);
      expected = await receipt(join(options.bundle, 'receipt.json'));
      if (operation === 'create') fragmentPlan(config, expected.cipher_bytes);
      input = join(options.bundle, 'snapshot.pgp');
      await verifyCipher(input, expected, signal, deadline);
    } else if (operation === 'restore') expected = await receipt(options.receipt);
    interrupted(signal, deadline);
    const storage = await storageFactory(configPath);
    let result;
    if (operation === 'create') {
      result = await storage.create({ input, sha256: expected.cipher_sha256, alreadyEncrypted: true }, { signal });
    } else if (operation === 'deposit') {
      result = await storage.deposit({ input, alreadyEncrypted: true }, { signal });
    } else if (operation === 'restore') {
      await newBundle(options.output, config.stateDirectory);
      result = await storage.restore({ output: join(options.output, 'snapshot.pgp'), sha256: expected.cipher_sha256 }, { signal });
    } else if (operation === 'renew') {
      check(integer(Number(options['lifetime-seconds']), 1, 2678400), 'invalid_arguments');
      result = await storage.renew({ lifetimeSeconds: Number(options['lifetime-seconds']) }, { signal });
    } else result = await storage[operation]({ signal });
    if (expected && result.status === 'complete') {
      check(result.storage?.logical_ciphertext_bytes === expected.cipher_bytes, 'snapshot_size_mismatch');
    }
    let recovered = false;
    if (operation === 'restore' && result.status === 'complete') {
      check(result.restore_verified === true && result.local_process_joined === true, 'restore_not_verified');
      // CoreStorage already verified the entire returned file against the retained hash.
      interrupted(signal, Infinity);
      await writeReceipt(options.output, expected);
      recovered = true;
    }
    return Object.freeze({ ...result, snapshot_operation: operation,
      snapshot_ciphertext_checked: operation === 'create' || operation === 'deposit' || recovered,
      recovery_bundle_ready: recovered, snapshot_decrypted: false, immich_restore_proven: false });
  } catch (error) {
    if (error instanceof SnapshotStorageError || error instanceof StorageBridgeError) throw error;
    throw new SnapshotStorageError('snapshot_storage_failed');
  }
}

const HELP = `Snapshot storage bridge (Linux / Node 24; no automatic create/retry/decrypt)
  create|deposit --config /private/storage.json --bundle /private/snapshot
  status|progress|delete --config /private/storage.json
  renew --config /private/storage.json --lifetime-seconds 604800
  restore --config /private/storage.json --receipt /private/snapshot/receipt.json --output /private/new-bundle
Only snapshot.pgp is uploaded. Keep receipt, core journal and recovery.key independently private.
Restore creates ciphertext + receipt only; supply the recovery key and decrypt separately.
`;

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length === 3 && process.argv[2] === '--help') process.stdout.write(HELP);
  else {
    const controller = new AbortController();
    const abort = () => controller.abort();
    process.on('SIGINT', abort);
    process.on('SIGTERM', abort);
    try {
      const result = await runSnapshotStorage(parseArguments(process.argv.slice(2)), { signal: controller.signal });
      process.stdout.write(`${JSON.stringify(result)}\n`);
      process.exitCode = result.status === 'complete' ? 0 : 1;
    } catch (error) {
      process.stderr.write(`${JSON.stringify({ version: 1, status: 'failed', code: error.code })}\n`);
      process.exitCode = 1;
    } finally {
      process.off('SIGINT', abort);
      process.off('SIGTERM', abort);
    }
  }
}
