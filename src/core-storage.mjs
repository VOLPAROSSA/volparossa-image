// SPDX-License-Identifier: GPL-3.0-only
// Linux development bridge; peer placement, signatures and accounting belong to the core.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, normalize, sep } from 'node:path';

const ARCHIVE_MAX = 64 * 1024 ** 3;
const REPORT_MAX = 2 * 1024 ** 2;
const HASH = /^[a-f0-9]{64}$/;
const OPERATIONS = new Set(['create', 'deposit', 'status', 'progress', 'restore', 'renew', 'delete']);
const FALSE_FLAGS = ['metadata_overhead_measured', 'current_remote_availability_proven',
  'independent_failure_domains_proven', 'network_contribution_credit', 'automatic_repair',
  'automatic_handoff', 'read_consumes_archive', 'erasure_coding'];
const CONFIG_KEYS = ['version', 'coreBinary', 'controlSocket', 'identity', 'passphraseFile',
  'stateDirectory', 'providers', 'copies', 'fragmentBytes', 'lifetimeSeconds', 'deadlineMs'];
const CONSTRUCT = Symbol('private constructor');

export class StorageBridgeError extends Error {
  constructor(code) {
    super(code);
    this.name = 'StorageBridgeError';
    this.code = code;
  }
}
function requireThat(condition, code = 'invalid_request') {
  if (!condition) throw new StorageBridgeError(code);
}
function integer(value, minimum, maximum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}
function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function onlyKeys(value, keys) {
  requireThat(object(value) && Object.keys(value).every(key => keys.includes(key)));
}
function absolute(value) {
  requireThat(typeof value === 'string' && value.length <= 4096 && isAbsolute(value)
    && normalize(value) === value && value !== sep && !/[\x00-\x1f\x7f]/.test(value));
  return value;
}
async function directory(path) {
  absolute(path);
  const metadata = await lstat(path);
  requireThat(metadata.isDirectory() && metadata.uid === process.getuid()
    && (metadata.mode & 0o7777) === 0o700 && await realpath(path) === path, 'private_directory_required');
}
async function privateFile(path, maximum) {
  absolute(path);
  await directory(dirname(path));
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const file = await handle.stat();
    const entry = await lstat(path);
    requireThat(file.isFile() && file.uid === process.getuid() && file.nlink === 1
      && (file.mode & 0o7777) === 0o600 && integer(file.size, 1, maximum)
      && entry.dev === file.dev && entry.ino === file.ino && !entry.isSymbolicLink(), 'private_file_required');
    return handle;
  } catch (error) {
    await handle.close();
    throw error;
  }
}
async function absent(path) {
  absolute(path);
  await directory(dirname(path));
  try { await lstat(path); } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  throw new StorageBridgeError('output_exists');
}
async function executable(path) {
  absolute(path);
  const file = await lstat(path);
  requireThat(file.isFile() && (file.uid === 0 || file.uid === process.getuid())
    && (file.mode & 0o022) === 0 && (file.mode & 0o111) !== 0
    && await realpath(path) === path, 'invalid_core_executable');
}
async function controlSocket(path) {
  absolute(path);
  const file = await lstat(path);
  requireThat(file.isSocket() && (file.mode & 0o007) === 0
    && await realpath(path) === path, 'invalid_control_socket');
}
function configuration(raw) {
  onlyKeys(raw, CONFIG_KEYS);
  requireThat(raw.version === 1 && Array.isArray(raw.providers)
    && integer(raw.providers.length, 3, 8));
  for (const key of ['coreBinary', 'controlSocket', 'identity', 'passphraseFile', 'stateDirectory']) absolute(raw[key]);
  const providers = raw.providers.map(provider => {
    onlyKeys(provider, ['key', 'grant']);
    requireThat(HASH.test(provider.key));
    return Object.freeze({ key: provider.key, grant: absolute(provider.grant) });
  });
  requireThat(new Set(providers.map(provider => provider.key)).size === providers.length
    && integer(raw.copies, 2, providers.length - 1)
    && integer(raw.fragmentBytes, 1, 1024 ** 3)
    && integer(raw.lifetimeSeconds, 1, 2678400)
    && integer(raw.deadlineMs ?? 1800000, 100, 1800000));
  return Object.freeze({ ...raw, providers: Object.freeze(providers), deadlineMs: raw.deadlineMs ?? 1800000 });
}

// Raw CLI output stays private. Validate the accounting structure before publishing a closed summary.
function summary(raw, operation) {
  const code = 'invalid_core_report';
  const check = value => requireThat(value, code);
  check(object(raw) && raw.operation === `private_storage_fragments_${operation}`);
  const logical = raw.logical_ciphertext_bytes;
  const count = raw.fragment_count;
  const copies = raw.copies_per_fragment;
  const providerCount = raw.distinct_provider_identities;
  check(integer(providerCount, 3, 8) && integer(copies, 2, providerCount - 1)
    && integer(logical, providerCount, ARCHIVE_MAX) && integer(count, providerCount, 256));
  check(FALSE_FLAGS.every(key => raw[key] === false)
    && raw.expired_copies_remain_charged === true && raw.owner_signature_verified === true);
  const amounts = ['reserved_payload_bytes', 'committed_payload_bytes', 'uncertain_payload_bytes'];
  check(amounts.every(key => integer(raw[key], 0, logical * copies)));
  const total = amounts.reduce((sum, key) => sum + raw[key], 0);
  check(total <= logical * copies && raw.physical_payload_charge_upper_bound === total);
  check(Array.isArray(raw.providers) && raw.providers.length === providerCount
    && Array.isArray(raw.fragments) && raw.fragments.length === count);
  const providers = new Map();
  for (const provider of raw.providers) {
    check(object(provider) && HASH.test(provider.provider_key) && !providers.has(provider.provider_key)
      && integer(provider.physical_payload_charge_upper_bound, 0, logical));
    providers.set(provider.provider_key, { declared: provider.physical_payload_charge_upper_bound, charge: 0 });
  }
  let offset = 0;
  let recoverable = 0;
  let redundant = 0;
  const charges = { reserved: 0, committed: 0, uncertain: 0 };
  raw.fragments.forEach((fragment, index) => {
    check(object(fragment) && fragment.index === index && fragment.offset === offset
      && integer(fragment.ciphertext_bytes, 1, 1024 ** 3)
      && integer(fragment.confirmed_unexpired_copies, 0, copies)
      && Array.isArray(fragment.copies) && fragment.copies.length === copies);
    offset += fragment.ciphertext_bytes;
    recoverable += Number(fragment.confirmed_unexpired_copies > 0);
    redundant += Number(fragment.confirmed_unexpired_copies === copies);
    const distinct = new Set();
    let committedCopies = 0;
    for (const copy of fragment.copies) {
      check(object(copy) && providers.has(copy.provider_key) && !distinct.has(copy.provider_key)
        && ['unattempted', 'reserved', 'committed', 'uncertain', 'deleted'].includes(copy.charge));
      distinct.add(copy.provider_key);
      if (Object.hasOwn(charges, copy.charge)) {
        charges[copy.charge] += fragment.ciphertext_bytes;
        providers.get(copy.provider_key).charge += fragment.ciphertext_bytes;
      }
      committedCopies += Number(copy.charge === 'committed');
    }
    check(fragment.confirmed_unexpired_copies <= committedCopies);
  });
  check(offset === logical && recoverable === raw.fragments_with_confirmed_unexpired_copy
    && raw.fully_redundant_from_retained_receipts === (redundant === count)
    && [...providers.values()].every(provider => provider.charge === provider.declared)
    && charges.reserved === raw.reserved_payload_bytes && charges.committed === raw.committed_payload_bytes
    && charges.uncertain === raw.uncertain_payload_bytes);
  const local = operation === 'create' || operation === 'status';
  check(local ? !Object.hasOwn(raw, 'operation_complete') : typeof raw.operation_complete === 'boolean');
  const complete = local || raw.operation_complete;
  if (operation === 'restore') check(typeof raw.restored === 'boolean'
    && raw.restored === complete && (!complete || raw.whole_archive_sha256_verified === true));
  const result = {
    operation_complete: complete, logical_ciphertext_bytes: logical, fragment_count: count,
    copies_per_fragment: copies, distinct_provider_identities: providerCount,
    reserved_payload_bytes: charges.reserved, committed_payload_bytes: charges.committed,
    uncertain_payload_bytes: charges.uncertain, physical_payload_charge_upper_bound: total,
    fragments_with_confirmed_unexpired_copy: recoverable,
    fully_redundant_from_retained_receipts: redundant === count,
    expired_copies_remain_charged: true, owner_signature_verified: true,
  };
  for (const key of FALSE_FLAGS) result[key] = false;
  return Object.freeze(result);
}

async function verifyRestored(path, expected, length, signal, deadline) {
  const handle = await privateFile(path, ARCHIVE_MAX);
  try {
    const before = await handle.stat();
    requireThat(before.size === length, 'restore_verification_failed');
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(256 * 1024);
    let offset = 0;
    while (offset < length) {
      requireThat(!signal?.aborted, 'cancelled');
      requireThat(Date.now() < deadline, 'timed_out');
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, length - offset), offset);
      requireThat(bytesRead > 0, 'restore_verification_failed');
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const after = await handle.stat();
    const entry = await lstat(path);
    requireThat(after.size === length && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs
      && entry.ino === after.ino && entry.dev === after.dev && !entry.isSymbolicLink()
      && hash.digest('hex') === expected, 'restore_verification_failed');
  } finally { await handle.close(); }
}

export class CoreStorage {
  #config;
  #spawn;
  #busy = false;
  constructor(config, spawnProcess, token) {
    requireThat(token === CONSTRUCT, 'use_core_storage_open');
    this.#config = config;
    this.#spawn = spawnProcess;
  }

  // spawnProcess is solely a process-contract test seam; never selected by configuration.
  static async open(configPath, { spawnProcess = spawn } = {}) {
    requireThat(process.platform === 'linux' && Number(process.versions.node.split('.')[0]) >= 24, 'linux_node24_required');
    const file = await privateFile(configPath, 65536);
    let config;
    try {
      const bytes = Buffer.alloc(65537);
      const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
      requireThat(bytesRead <= 65536, 'invalid_configuration');
      config = configuration(JSON.parse(bytes.subarray(0, bytesRead).toString('utf8')));
    } catch { throw new StorageBridgeError('invalid_configuration'); }
    finally { await file.close(); }
    return new CoreStorage(config, spawnProcess, CONSTRUCT);
  }

  create(request, options) { return this.#run('create', request, options); }
  deposit(request, options) { return this.#run('deposit', request, options); }
  status(options) { return this.#run('status', {}, options); }
  progress(options) { return this.#run('progress', {}, options); }
  restore(request, options) { return this.#run('restore', request, options); }
  renew(request, options) { return this.#run('renew', request, options); }
  delete(options) { return this.#run('delete', {}, options); }

  async #run(operation, request = {}, { signal } = {}) {
    requireThat(!this.#busy, 'operation_in_progress');
    requireThat(!signal || (typeof signal.addEventListener === 'function' && typeof signal.aborted === 'boolean'));
    requireThat(!signal?.aborted, 'cancelled');
    requireThat(OPERATIONS.has(operation));
    this.#busy = true;
    const retained = [];
    let launched = false;
    try {
      const config = this.#config;
      const deadline = Date.now() + config.deadlineMs;
      await executable(config.coreBinary);
      await directory(dirname(config.stateDirectory));
      if (operation === 'create') await absent(config.stateDirectory);
      else await directory(config.stateDirectory);
      const args = ['--control-socket', config.controlSocket, 'storage', 'fragments', operation, '--state', config.stateDirectory];
      if (!['create', 'status'].includes(operation)) await controlSocket(config.controlSocket);
      if (operation !== 'status') {
        retained.push(await privateFile(config.identity, 65536));
        retained.push(await privateFile(config.passphraseFile, 1025));
        args.push('--identity', config.identity, '--passphrase-file', config.passphraseFile);
      }
      if (operation === 'create' || operation === 'deposit') {
        onlyKeys(request, operation === 'create' ? ['input', 'sha256', 'alreadyEncrypted'] : ['input', 'alreadyEncrypted']);
        requireThat(request.alreadyEncrypted === true);
        const input = await privateFile(request.input, ARCHIVE_MAX);
        retained.push(input);
        args.push('--input', request.input, '--already-encrypted');
        if (operation === 'create') {
          requireThat(HASH.test(request.sha256));
          const length = (await input.stat()).size;
          const size = Math.min(config.fragmentBytes, Math.floor(length / config.providers.length));
          requireThat(size > 0 && Math.ceil(length / size) <= 256, 'invalid_fragment_plan');
          args.push('--sha256', request.sha256, '--copies', String(config.copies),
            '--fragment-bytes', String(config.fragmentBytes), '--lifetime-seconds', String(config.lifetimeSeconds));
          for (const provider of config.providers) {
            retained.push(await privateFile(provider.grant, 2048));
            args.push('--provider-key', provider.key, '--grant', provider.grant);
          }
        }
      } else if (operation === 'restore') {
        onlyKeys(request, ['output', 'sha256']);
        requireThat(HASH.test(request.sha256));
        absolute(request.output);
        requireThat(request.output !== config.stateDirectory && !request.output.startsWith(`${config.stateDirectory}${sep}`));
        await absent(request.output);
        args.push('--output', request.output);
      } else if (operation === 'renew') {
        onlyKeys(request, ['lifetimeSeconds']);
        requireThat(integer(request.lifetimeSeconds, 1, 2678400));
        args.push('--lifetime-seconds', String(request.lifetimeSeconds));
      } else onlyKeys(request, []);
      requireThat(!signal?.aborted, 'cancelled');
      const execution = await this.#execute(args, signal, deadline, () => { launched = true; });
      let report = null;
      let status = ['cancelled', 'timed_out'].includes(execution.stopped) ? execution.stopped : 'failed';
      let code = execution.stopped ?? 'core_failed';
      let restored = false;
      if (!execution.stopped && !execution.spawnError && execution.signal === null) {
        try {
          report = summary(JSON.parse(execution.output), operation);
          requireThat((execution.code === 0 && report.operation_complete)
            || (execution.code === 1 && !report.operation_complete), 'invalid_core_report');
          status = report.operation_complete ? 'complete' : 'incomplete';
          code = report.operation_complete ? 'ok' : 'retained_operation_incomplete';
        } catch { report = null; code = 'invalid_core_report'; }
        if (status === 'complete' && operation === 'restore') {
          try {
            await verifyRestored(request.output, request.sha256, report.logical_ciphertext_bytes, signal, deadline);
            restored = true;
          } catch (error) {
            const stopped = ['cancelled', 'timed_out'].includes(error.code);
            status = stopped ? error.code : 'failed';
            code = stopped ? error.code : 'restore_verification_failed';
          }
        }
      }
      return Object.freeze({ version: 1, operation, status, code, local_process_joined: true,
        remote_cleanup_confirmed: false, restore_verified: restored, storage: report });
    } catch (error) {
      if (error instanceof StorageBridgeError) throw error;
      throw new StorageBridgeError(launched ? 'local_verification_failed' : 'local_input_unavailable');
    } finally {
      await Promise.all(retained.map(handle => handle.close()));
      this.#busy = false;
    }
  }

  #execute(args, signal, deadline, launched) {
    const config = this.#config;
    return new Promise((resolve, reject) => {
      let child;
      try {
        child = this.#spawn(config.coreBinary, args, {
          cwd: dirname(config.stateDirectory), shell: false, detached: true,
          env: { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' }, stdio: ['ignore', 'pipe', 'ignore'],
        });
        launched();
      } catch { reject(new StorageBridgeError('core_spawn_failed')); return; }
      let chunks = [];
      let bytes = 0;
      let stopped = null;
      let spawnError = false;
      let closed = false;
      let killTimer;
      const kill = name => {
        if (!closed && Number.isSafeInteger(child.pid) && child.pid > 1) {
          try { process.kill(-child.pid, name); } catch { /* Wait for close; no guessed completion. */ }
        }
      };
      const stop = reason => {
        if (closed || stopped) return;
        stopped = reason;
        chunks = [];
        kill('SIGTERM');
        killTimer = setTimeout(() => kill('SIGKILL'), 5000);
      };
      const cancel = () => stop('cancelled');
      const timeout = setTimeout(() => stop('timed_out'), Math.max(0, deadline - Date.now()));
      signal?.addEventListener('abort', cancel, { once: true });
      if (signal?.aborted) cancel();
      child.stdout.on('data', chunk => {
        if (stopped) return;
        bytes += chunk.length;
        if (bytes > REPORT_MAX) stop('report_too_large');
        else chunks.push(chunk);
      });
      child.on('error', () => { spawnError = true; });
      child.on('close', (code, terminationSignal) => {
        closed = true;
        clearTimeout(timeout);
        clearTimeout(killTimer);
        signal?.removeEventListener('abort', cancel);
        resolve({ code, signal: terminationSignal, stopped, spawnError,
          output: stopped ? '' : Buffer.concat(chunks).toString('utf8') });
      });
    });
  }
}
