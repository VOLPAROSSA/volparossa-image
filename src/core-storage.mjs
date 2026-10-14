// SPDX-License-Identifier: GPL-3.0-only
// Linux development bridge; peer placement, signatures and accounting belong to the core.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, join, normalize, sep } from 'node:path';

const ARCHIVE_MAX = 64 * 1024 ** 3;
const REPORT_MAX = 2 * 1024 ** 2;
const MAINTENANCE_RECORD_MAX = 32768;
const MAINTENANCE_STAGES = new Set(['enrolled', 'owner_locked', 'waiting_for_core', 'core_unavailable',
  'working', 'paused', 'enrollment_expired', 'turn_completed', 'retry_pending', 'core_turn_revoked']);
const CORE_CREATE_COPIES = 2; // Core policy contract, not an application-selectable tier.
const COPY_HISTORY_MAX = 8;
const REPAIR_FIELDS = ['placement_authorizations', 'retained_copy_records', 'pending_retirements',
  'desired_copies_per_fragment', 'replacement_overhead_included'];
const HASH = /^[a-f0-9]{64}$/;
const OPERATIONS = new Set(['create', 'deposit', 'status', 'progress', 'restore', 'renew', 'delete']);
const DEPOSIT_OPERATIONS = new Set(['prepare', 'reserve', 'progress', 'append', 'finalize', 'renew', 'read_range', 'delete']);
const DEPOSIT_STAGES = new Set(['journal_open', 'authorization', 'agent_ready', 'challenge', 'signed_request',
  'wire_receipt', 'agent_terminal', 'accounting', 'local_input', 'receipt_validation', 'journal_save', 'deadline', 'unknown']);
const DEPOSIT_CATEGORIES = new Set(['io', 'timeout', 'protocol', 'agent_rejected', 'invalid', 'busy', 'store', 'unknown']);
const DEPOSIT_AGENT_CODES = new Set(['CONTENT_INVALID', 'CONTENT_UNAVAILABLE', 'CONTENT_BUSY', 'CONTENT_POLICY', 'unknown']);
const DEPOSIT_AGENT_STAGES = new Set(['unobserved', 'route_connect', 'control_selection', 'provider_lookup',
  'provider_cardinality', 'offer_validity', 'stream_open', 'tls_handshake', 'challenge']);
const DEPOSIT_EXCHANGE_STAGES = new Set(['stream_open', 'tls_handshake', 'challenge']);
const DEPOSIT_TLS_FAILURES = new Set(['offer', 'configuration', 'handshake_deadline', 'authentication', 'tls_other', 'io']);
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

async function privateJSON(path, maximum) {
  const handle = await privateFile(path, maximum);
  try {
    const before = await handle.stat({ bigint: true });
    requireThat(before.size > 0n && before.size <= BigInt(maximum), 'private_file_required');
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const entry = await lstat(path, { bigint: true });
    requireThat(offset === Number(before.size) && ['dev', 'ino', 'size', 'mode', 'uid', 'nlink', 'mtimeNs', 'ctimeNs']
      .every(key => before[key] === after[key] && after[key] === entry[key]), 'local_input_changed');
    const raw = bytes.subarray(0, offset);
    return { value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)),
      sha256: createHash('sha256').update(raw).digest('hex') };
  } finally { await handle.close(); }
}

function maintenanceCheckpoint(raw) {
  const valid = object(raw) && raw.version === 1 && raw.scope === 'owner-private-maintenance'
    && MAINTENANCE_STAGES.has(raw.stage) && integer(raw.turns, 0, Number.MAX_SAFE_INTEGER)
    && integer(raw.at, 1, Number.MAX_SAFE_INTEGER) && raw.core_coordinated === true
    && raw.new_network_node === false && raw.automatic_grant_refresh === false && raw.private_key_exported === false;
  requireThat(valid, 'invalid_maintenance_report');
  // Detail may contain operation-specific data; never forward arbitrary core output.
  return Object.freeze({ version: 1, scope: raw.scope, stage: raw.stage, turns: raw.turns, at: raw.at,
    core_coordinated: true, new_network_node: false, automatic_grant_refresh: false, private_key_exported: false });
}
function maintenanceResult(status, code, checkpoint = null, running = false) {
  return Object.freeze({ version: 1, operation: 'maintenance', status, code, checkpoint,
    owned_process_running: running, local_process_joined: !running, remote_cleanup_confirmed: false,
    automatic_grant_refresh: false, private_key_exported: false });
}
function maintenancePath(enrollment, state) {
  absolute(enrollment);
  requireThat(enrollment !== state && !enrollment.startsWith(`${state}${sep}`)
    && !state.startsWith(`${enrollment}${sep}`), 'overlapping_maintenance_state');
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
    && (!Object.hasOwn(raw, 'copies') || raw.copies === CORE_CREATE_COPIES)
    && integer(raw.fragmentBytes, 1, 1024 ** 3)
    && integer(raw.lifetimeSeconds, 1, 2678400)
    && integer(raw.deadlineMs ?? 1800000, 100, 1800000));
  return Object.freeze({ ...raw, providers: Object.freeze(providers), deadlineMs: raw.deadlineMs ?? 1800000 });
}

// Raw CLI output stays private. Validate the accounting structure before publishing a closed summary.
function depositDiagnostics(raw, fragments, complete) {
  const check = value => requireThat(value, 'invalid_core_report');
  const exactKeys = (value, keys) => object(value) && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
  const retainedCopies = fragments.reduce((sum, fragment) => sum + fragment.copies.length, 0);
  check(exactKeys(raw, ['version', 'failures', 'omitted_failures']) && [1, 2, 3].includes(raw.version)
    && Array.isArray(raw.failures) && raw.failures.length <= 8
    && integer(raw.omitted_failures, 0, 2048)
    && raw.failures.length + raw.omitted_failures <= retainedCopies
    && (raw.omitted_failures === 0 || raw.failures.length === 8)
    && (!complete || (raw.failures.length === 0 && raw.omitted_failures === 0)));
  const seen = new Set();
  const failures = raw.failures.map(failure => {
    const keys = ['fragment_index', 'copy_index', 'operation', 'stage', 'category', 'agent_code'];
    if (raw.version !== 1) keys.push('agent_detail');
    check(exactKeys(failure, keys));
    const { fragment_index, copy_index, operation, stage, category, agent_code } = failure;
    // This bridge consumes fragment reports, never the replica-only null index.
    check(integer(fragment_index, 0, fragments.length - 1)
      && integer(copy_index, 0, fragments[fragment_index].copies.length - 1)
      && DEPOSIT_OPERATIONS.has(operation) && DEPOSIT_STAGES.has(stage) && DEPOSIT_CATEGORIES.has(category)
      && (category === 'agent_rejected' ? DEPOSIT_AGENT_CODES.has(agent_code) : agent_code === null));
    const copy = `${fragment_index}:${copy_index}`;
    check(!seen.has(copy));
    seen.add(copy);
    const closed = { fragment_index, copy_index, operation, stage, category, agent_code };
    if (raw.version !== 1) {
      const detail = failure.agent_detail;
      if (detail !== null) {
        const detailKeys = ['stage', 'deadline_scope'];
        if (raw.version === 3) detailKeys.push('tls_failure');
        check(exactKeys(detail, detailKeys)
          && stage === 'agent_ready' && category === 'agent_rejected' && agent_code !== 'unknown'
          && DEPOSIT_AGENT_STAGES.has(detail.stage)
          && ['none', 'operation', 'exchange'].includes(detail.deadline_scope)
          && (detail.stage !== 'unobserved' || detail.deadline_scope === 'operation')
          && (detail.deadline_scope !== 'exchange' || DEPOSIT_EXCHANGE_STAGES.has(detail.stage))
          && (detail.deadline_scope === 'none' || agent_code === 'CONTENT_UNAVAILABLE'));
        if (raw.version === 3) {
          check(detail.tls_failure === null || (DEPOSIT_TLS_FAILURES.has(detail.tls_failure)
            && detail.stage === 'tls_handshake' && detail.deadline_scope === 'none'
            && agent_code === 'CONTENT_UNAVAILABLE'));
        }
      }
      closed.agent_detail = detail === null ? null
        : Object.freeze({ stage: detail.stage, deadline_scope: detail.deadline_scope,
          ...(raw.version === 3 ? { tls_failure: detail.tls_failure } : {}) });
    }
    return Object.freeze(closed);
  });
  // Diagnostic evidence does not alter completion, accounting, retry or cleanup.
  return Object.freeze({ version: raw.version, failures: Object.freeze(failures), omitted_failures: raw.omitted_failures });
}

function summary(raw, operation) {
  const code = 'invalid_core_report';
  const check = value => requireThat(value, code);
  check(object(raw) && raw.operation === `private_storage_fragments_${operation}`);
  const logical = raw.logical_ciphertext_bytes;
  const count = raw.fragment_count;
  const copies = raw.copies_per_fragment;
  const providerCount = raw.distinct_provider_identities;
  const repaired = raw.report_version === 2;
  check(!Object.hasOwn(raw, 'report_version') || repaired);
  check(repaired || REPAIR_FIELDS.every(key => !Object.hasOwn(raw, key)));
  check(integer(copies, 2, 7) && integer(count, 3, 256) && integer(logical, count, ARCHIVE_MAX));
  check(integer(providerCount, 3, repaired ? 8 + count * (COPY_HISTORY_MAX - copies) : 8));
  if (!repaired) check(count >= providerCount && copies < providerCount);
  // An old retained archive may have more copies; newly created archives may not.
  if (operation === 'create') check(!repaired && copies === CORE_CREATE_COPIES);
  check(FALSE_FLAGS.every(key => raw[key] === false)
    && raw.expired_copies_remain_charged === true && raw.owner_signature_verified === true);
  const amounts = ['reserved_payload_bytes', 'committed_payload_bytes', 'uncertain_payload_bytes'];
  const chargeLimit = logical * (repaired ? COPY_HISTORY_MAX : copies);
  check(amounts.every(key => integer(raw[key], 0, chargeLimit)));
  const total = amounts.reduce((sum, key) => sum + raw[key], 0);
  check(total <= chargeLimit && raw.physical_payload_charge_upper_bound === total);
  check(Array.isArray(raw.providers) && raw.providers.length === providerCount
    && Array.isArray(raw.fragments) && raw.fragments.length === count);
  const providers = new Map();
  for (const provider of raw.providers) {
    check(object(provider) && HASH.test(provider.provider_key) && !providers.has(provider.provider_key)
      && integer(provider.physical_payload_charge_upper_bound, 0, logical));
    providers.set(provider.provider_key, { declared: provider.physical_payload_charge_upper_bound, charge: 0, records: 0 });
  }
  let offset = 0;
  let recoverable = 0;
  let redundant = 0;
  let retainedCopies = 0;
  let extendedFragments = 0;
  const originalProviders = new Set();
  const charges = { reserved: 0, committed: 0, uncertain: 0 };
  raw.fragments.forEach((fragment, index) => {
    check(object(fragment) && fragment.index === index && fragment.offset === offset
      && integer(fragment.ciphertext_bytes, 1, 1024 ** 3)
      && Array.isArray(fragment.copies)
      && integer(fragment.copies.length, copies, repaired ? COPY_HISTORY_MAX : copies)
      && integer(fragment.confirmed_unexpired_copies, 0, fragment.copies.length));
    offset += fragment.ciphertext_bytes;
    retainedCopies += fragment.copies.length;
    extendedFragments += Number(fragment.copies.length > copies);
    recoverable += Number(fragment.confirmed_unexpired_copies > 0);
    redundant += Number(fragment.confirmed_unexpired_copies >= copies);
    const distinct = new Set();
    let committedCopies = 0;
    for (const copy of fragment.copies) {
      check(object(copy) && providers.has(copy.provider_key) && !distinct.has(copy.provider_key)
        && ['unattempted', 'reserved', 'committed', 'uncertain', 'deleted'].includes(copy.charge));
      distinct.add(copy.provider_key);
      providers.get(copy.provider_key).records++;
      if (Object.hasOwn(charges, copy.charge)) {
        charges[copy.charge] += fragment.ciphertext_bytes;
        providers.get(copy.provider_key).charge += fragment.ciphertext_bytes;
      }
      committedCopies += Number(copy.charge === 'committed');
    }
    for (const copy of fragment.copies.slice(0, copies)) originalProviders.add(copy.provider_key);
    check(fragment.confirmed_unexpired_copies <= committedCopies);
  });
  // The immutable original plan uses a 3..8-provider rotating pool. Later signed
  // placements append records/identities; they do not redefine that original root.
  const originalCount = originalProviders.size;
  check(integer(originalCount, 3, 8) && copies < originalCount && originalCount <= count
    && providerCount >= originalCount);
  check(raw.fragments.every((fragment, index) => fragment.copies.slice(0, copies).every((copy, position) =>
    copy.provider_key === raw.providers[(index + position) % originalCount].provider_key)));
  if (repaired) {
    const authorizations = retainedCopies - count * copies;
    check(integer(authorizations, 1, count * (COPY_HISTORY_MAX - copies))
      && raw.placement_authorizations === authorizations
      && raw.retained_copy_records === retainedCopies
      && raw.desired_copies_per_fragment === copies
      && integer(raw.pending_retirements, 0, extendedFragments)
      && raw.replacement_overhead_included === true
      && providerCount <= originalCount + authorizations);
  } else check(providerCount === originalCount);
  check(offset === logical && recoverable === raw.fragments_with_confirmed_unexpired_copy
    && raw.fully_redundant_from_retained_receipts === (redundant === count)
    && [...providers.values()].every(provider => provider.records > 0 && provider.charge === provider.declared)
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
  if (repaired) {
    result.report_version = 2;
    for (const key of REPAIR_FIELDS) result[key] = raw[key];
  }
  if (Object.hasOwn(raw, 'deposit_diagnostics')) {
    check(operation === 'deposit');
    result.deposit_diagnostics = depositDiagnostics(raw.deposit_diagnostics, raw.fragments, complete);
  }
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
  #operation = null;
  #maintenance = null;
  #closed = false;
  #closing = null;
  #cleanupFailure = null;
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

  async #exclusive(action, { signal } = {}) {
    requireThat(!this.#closed, 'storage_closed');
    requireThat(!this.#cleanupFailure, this.#cleanupFailure);
    requireThat(!this.#busy, 'operation_in_progress');
    requireThat(!signal || (typeof signal.addEventListener === 'function' && typeof signal.aborted === 'boolean'));
    requireThat(!signal?.aborted, 'cancelled');
    this.#busy = true;
    const controller = new AbortController();
    let joined;
    const done = new Promise(resolve => { joined = resolve; });
    this.#operation = { controller, done };
    const cancel = () => controller.abort();
    signal?.addEventListener('abort', cancel, { once: true });
    if (signal?.aborted) cancel();
    try { return await action(controller.signal); }
    catch (error) {
      if (error instanceof StorageBridgeError) throw error;
      throw new StorageBridgeError('local_input_unavailable');
    }
    finally {
      signal?.removeEventListener('abort', cancel);
      this.#busy = false;
      this.#operation = null;
      joined();
    }
  }

  enrollMaintenance(request, options) {
    return this.#exclusive(async signal => {
      requireThat(!this.#maintenance, 'maintenance_in_progress');
      onlyKeys(request, ['enrollment', 'fromProviderKey', 'providers', 'authorizationSeconds',
        'authorizationExpiresAt', 'lifetimeSeconds', 'renewBeforeSeconds', 'maximumChargedBytes', 'maximumTurnBytes']);
      const c = this.#config;
      maintenancePath(request.enrollment, c.stateDirectory);
      requireThat(HASH.test(request.fromProviderKey) && Array.isArray(request.providers)
        && integer(request.providers.length, 1, 8));
      for (const name of ['authorizationSeconds', 'lifetimeSeconds', 'renewBeforeSeconds']) {
        requireThat(integer(request[name], 1, 2678400));
      }
      const hasAbsoluteExpiry = Object.hasOwn(request, 'authorizationExpiresAt');
      if (hasAbsoluteExpiry) {
        requireThat(integer(request.authorizationExpiresAt, 1, Number.MAX_SAFE_INTEGER));
      }
      requireThat(integer(request.maximumChargedBytes, 1, ARCHIVE_MAX * COPY_HISTORY_MAX)
        && integer(request.maximumTurnBytes, 1, 134217728));
      const args = ['--control-socket', c.controlSocket, 'storage', 'fragments', 'maintenance', 'enroll',
        '--enrollment', request.enrollment, '--state', c.stateDirectory, '--from-provider-key', request.fromProviderKey,
        '--authorization-seconds', String(request.authorizationSeconds), '--lifetime-seconds', String(request.lifetimeSeconds),
        '--renew-before-seconds', String(request.renewBeforeSeconds), '--maximum-charged-bytes', String(request.maximumChargedBytes),
        '--maximum-turn-bytes', String(request.maximumTurnBytes), '--identity', c.identity, '--passphrase-file', c.passphraseFile];
      // Preserve the owner's exact absolute deadline. The core must enforce it
      // at signing; converting it to a new relative duration could extend it.
      if (hasAbsoluteExpiry) args.push('--authorization-expires-at', String(request.authorizationExpiresAt));
      const retained = [];
      try {
        await executable(c.coreBinary);
        await directory(c.stateDirectory);
        await absent(request.enrollment);
        const keys = new Set();
        for (const provider of request.providers) {
          onlyKeys(provider, ['key', 'grant']);
          requireThat(HASH.test(provider.key) && provider.key !== request.fromProviderKey && !keys.has(provider.key));
          keys.add(provider.key);
          retained.push(await privateFile(provider.grant, 2048));
          args.push('--provider-key', provider.key, '--grant', provider.grant);
        }
        retained.push(await privateFile(c.identity, 65536));
        retained.push(await privateFile(c.passphraseFile, 1025));
        requireThat(!signal.aborted, 'cancelled');
        const execution = await this.#execute(args, signal, Date.now() + c.deadlineMs, () => {});
        return this.#maintenanceOutcome(execution);
      } finally { await Promise.all(retained.map(handle => handle.close())); }
    }, options);
  }

  maintenanceStatus(request, options) {
    return this.#exclusive(signal => {
      onlyKeys(request, ['enrollment']);
      return this.#readMaintenanceStatus(request.enrollment, signal);
    }, options);
  }

  async #readMaintenanceStatus(enrollment, signal) {
    const c = this.#config;
    maintenancePath(enrollment, c.stateDirectory);
    await executable(c.coreBinary);
    await directory(enrollment);
    requireThat(!signal?.aborted, 'cancelled');
    const result = await this.#execute(['--control-socket', c.controlSocket, 'storage', 'fragments', 'maintenance',
      'status', '--enrollment', enrollment], signal, Date.now() + c.deadlineMs, () => {});
    const running = this.#maintenance?.request.enrollment === enrollment && !!this.#maintenance?.live;
    return this.#maintenanceOutcome(result, running);
  }

  #maintenanceOutcome(execution, running = false) {
    if (execution.stopped || execution.spawnError || execution.signal !== null || execution.code !== 0) {
      return maintenanceResult('failed', execution.stopped ?? 'core_failed', null, running);
    }
    try {
      requireThat(Buffer.byteLength(execution.output) <= MAINTENANCE_RECORD_MAX, 'invalid_maintenance_report');
      return maintenanceResult('complete', 'ok', maintenanceCheckpoint(JSON.parse(execution.output)), running);
    } catch { return maintenanceResult('failed', 'invalid_maintenance_report', null, running); }
  }

  startMaintenance(request, options = {}) {
    return this.#exclusive(async signal => {
      requireThat(!this.#maintenance, 'maintenance_in_progress');
      onlyKeys(request, ['enrollment', 'maximumTurns']);
      requireThat(!Object.hasOwn(request, 'maximumTurns') || integer(request.maximumTurns, 1, 4096));
      const selected = Object.freeze({ ...request });
      let resolveDone;
      const done = new Promise(resolve => { resolveDone = resolve; });
      const session = { request: selected, binding: null, desired: true, live: null, resolveDone, done,
        signal: options.signal, abort: null, finished: false };
      session.abort = () => { this.#endMaintenance(session, 'cancelled').catch(() => {}); };
      this.#maintenance = session;
      options.signal?.addEventListener('abort', session.abort, { once: true });
      try {
        requireThat(!signal.aborted && !options.signal?.aborted, 'cancelled');
        session.binding = await this.#maintenanceBinding(selected.enrollment, signal);
        await this.#launchMaintenance(session, signal);
        return Object.freeze({ done, stop: () => this.#endMaintenance(session, 'stopped'),
          status: () => this.maintenanceStatus({ enrollment: selected.enrollment }) });
      } catch (error) {
        await this.#endMaintenance(session, 'start_failed');
        throw error;
      }
    }, options);
  }

  async #maintenanceBinding(enrollment, signal) {
    maintenancePath(enrollment, this.#config.stateDirectory);
    const before = await privateJSON(join(enrollment, 'enrollment.json'), MAINTENANCE_RECORD_MAX);
    const status = await this.#readMaintenanceStatus(enrollment, signal);
    requireThat(status.status === 'complete', status.code);
    const after = await privateJSON(join(enrollment, 'enrollment.json'), MAINTENANCE_RECORD_MAX);
    requireThat(before.sha256 === after.sha256, 'enrollment_changed');
    const authority = after.value?.enrollment;
    requireThat(object(authority) && authority.version === 1 && authority.archive === this.#config.stateDirectory
      && integer(authority.created, 1, Number.MAX_SAFE_INTEGER) && integer(authority.expires, authority.created + 1, Number.MAX_SAFE_INTEGER)
      && authority.expires - authority.created <= 2678400, 'invalid_enrollment');
    requireThat(authority.created <= Math.floor(Date.now() / 1000) && authority.expires > Math.floor(Date.now() / 1000), 'enrollment_expired');
    return Object.freeze({ sha256: after.sha256, expires: authority.expires, turns: status.checkpoint.turns });
  }

  async #launchMaintenance(session, signal) {
    const c = this.#config;
    const binding = await this.#maintenanceBinding(session.request.enrollment, signal);
    requireThat(binding.sha256 === session.binding.sha256, 'enrollment_changed');
    requireThat(binding.turns >= session.binding.turns, 'maintenance_cursor_regressed');
    const remaining = session.request.maximumTurns === undefined ? undefined
      : session.request.maximumTurns - (binding.turns - session.binding.turns);
    if (remaining !== undefined && remaining <= 0) {
      this.#finishMaintenance(session, maintenanceResult('stopped', 'turn_limit'));
      return;
    }
    const retained = [];
    try {
      await executable(c.coreBinary);
      await directory(c.stateDirectory);
      retained.push(await privateFile(c.identity, 65536));
      retained.push(await privateFile(c.passphraseFile, 1025));
      requireThat(session.desired && !this.#closed && !signal?.aborted && !session.signal?.aborted, 'cancelled');
      const args = ['--control-socket', c.controlSocket, 'storage', 'fragments', 'maintenance', 'serve',
        '--enrollment', session.request.enrollment, '--identity', c.identity, '--passphrase-file', c.passphraseFile];
      if (remaining !== undefined) args.push('--maximum-turns', String(remaining));
      const child = this.#spawn(c.coreBinary, args, { cwd: dirname(c.stateDirectory), shell: false, detached: true,
        env: { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' }, stdio: ['ignore', 'pipe', 'ignore'] });
      let resolveDone, pending = Buffer.alloc(0), stopped = null, killTimer, checkpoint = null, spawned = false;
      const done = new Promise(resolve => { resolveDone = resolve; });
      const kill = name => {
        if (session.live?.child === child && Number.isSafeInteger(child.pid) && child.pid > 1) {
          try { process.kill(-child.pid, name); } catch { /* Completion still requires close. */ }
        }
      };
      const stop = reason => {
        if (stopped || session.live?.child !== child) return;
        stopped = reason; pending = Buffer.alloc(0);
        kill('SIGTERM');
        killTimer = setTimeout(() => kill('SIGKILL'), 5000);
      };
      session.live = { child, done, stop };
      let expiryTimer;
      const expire = () => {
        const delay = session.binding.expires * 1000 - Date.now();
        if (delay <= 0) stop('enrollment_expired');
        else expiryTimer = setTimeout(expire, Math.min(delay, 2147483647));
      };
      expire();
      child.stdout.on('data', chunk => {
        if (stopped) return; // The pipe remains drained after a stop request.
        let offset = 0;
        while (offset < chunk.length) {
          const newline = chunk.indexOf(10, offset);
          const end = newline === -1 ? chunk.length : newline;
          if (pending.length + end - offset > MAINTENANCE_RECORD_MAX) { stop('report_too_large'); return; }
          pending = Buffer.concat([pending, chunk.subarray(offset, end)]);
          offset = newline === -1 ? chunk.length : newline + 1;
          if (newline !== -1) {
            try { checkpoint = maintenanceCheckpoint(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(pending))); }
            catch { stop('invalid_maintenance_report'); return; }
            pending = Buffer.alloc(0);
          }
        }
      });
      child.on('error', () => { stopped ??= 'core_spawn_failed'; });
      child.on('close', (code, termination) => {
        clearTimeout(expiryTimer); clearTimeout(killTimer);
        if (session.live?.child === child) session.live = null;
        const clean = spawned && code === 0 && termination === null && pending.length === 0
          && (!stopped || ['foreground_pause', 'stopped', 'cancelled', 'closed', 'enrollment_expired'].includes(stopped));
        const result = maintenanceResult(clean ? 'stopped' : 'failed', clean ? stopped ?? checkpoint?.stage ?? 'core_exited' : stopped ?? 'core_failed', checkpoint);
        resolveDone(result);
        if (stopped !== 'foreground_pause') this.#finishMaintenance(session, result);
      });
      await new Promise((resolve, reject) => {
        child.once('spawn', () => { spawned = true; resolve(); });
        child.once('error', () => reject(new StorageBridgeError('core_spawn_failed')));
      });
      if (!session.desired || this.#closed || signal?.aborted || session.signal?.aborted) stop('cancelled');
    } finally { await Promise.all(retained.map(handle => handle.close())); }
  }

  #finishMaintenance(session, result) {
    if (session.finished) return;
    if (result.status === 'failed') this.#cleanupFailure ??= 'maintenance_cleanup_unconfirmed';
    session.finished = true; session.desired = false;
    session.signal?.removeEventListener('abort', session.abort);
    if (this.#maintenance === session) this.#maintenance = null;
    session.resolveDone(result);
  }

  async #endMaintenance(session, reason) {
    session.desired = false;
    const live = session.live;
    if (live) {
      live.stop(reason);
      const result = await live.done;
      this.#finishMaintenance(session, result);
    } else this.#finishMaintenance(session, maintenanceResult('stopped', reason));
    return session.done;
  }

  stopMaintenance() {
    return this.#maintenance ? this.#endMaintenance(this.#maintenance, 'stopped')
      : Promise.resolve(maintenanceResult(this.#cleanupFailure ? 'failed' : 'stopped', this.#cleanupFailure ?? 'not_running'));
  }

  close() {
    if (!this.#closing) {
      this.#closed = true;
      this.#operation?.controller.abort();
      const operation = this.#operation?.done;
      const maintenance = this.stopMaintenance();
      this.#closing = (async () => {
        await operation;
        const result = await maintenance;
        requireThat(!this.#cleanupFailure, this.#cleanupFailure);
        return result;
      })();
    }
    return this.#closing;
  }

  #run(operation, request = {}, options) {
    return this.#exclusive(async signal => {
      const session = this.#maintenance;
      if (session?.live) {
        const live = session.live;
        live.stop('foreground_pause');
        const stopped = await live.done;
        if (stopped.status === 'failed') {
          this.#finishMaintenance(session, stopped);
          throw new StorageBridgeError('maintenance_cleanup_unconfirmed');
        }
      }
      let result;
      try {
        requireThat(!signal.aborted && !this.#closed, 'cancelled');
        result = await this.#foreground(operation, request, { signal });
      } catch (error) {
        if (session) this.#finishMaintenance(session, maintenanceResult('stopped', 'foreground_failed'));
        throw error;
      }
      if (session && !session.finished) {
        if (session.desired && !this.#closed && !signal.aborted && !session.signal?.aborted
          && result.status === 'complete' && result.local_process_joined && operation !== 'delete') {
          try { await this.#launchMaintenance(session, signal); }
          catch {
            if (session.live) await this.#endMaintenance(session, 'resume_unavailable');
            else this.#finishMaintenance(session, maintenanceResult('stopped', 'resume_unavailable'));
          }
        } else this.#finishMaintenance(session, maintenanceResult('stopped', 'foreground_not_resumed'));
      }
      return result;
    }, options);
  }

  async #foreground(operation, request = {}, { signal } = {}) {
    requireThat(OPERATIONS.has(operation));
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
          args.push('--sha256', request.sha256,
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
        if (terminationSignal === 'SIGKILL') this.#cleanupFailure ??= 'foreground_cleanup_unconfirmed';
        clearTimeout(timeout);
        clearTimeout(killTimer);
        signal?.removeEventListener('abort', cancel);
        resolve({ code, signal: terminationSignal, stopped, spawnError,
          output: stopped ? '' : Buffer.concat(chunks).toString('utf8') });
      });
    });
  }
}
