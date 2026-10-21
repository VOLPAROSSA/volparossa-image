// SPDX-License-Identifier: GPL-3.0-only
// Linux development bridge; peer placement, signatures and accounting belong to the core.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, normalize, sep } from 'node:path';

const ARCHIVE_MAX = 64 * 1024 ** 3;
const REPORT_MAX = 2 * 1024 ** 2;
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
const DEPOSIT_STREAM_FAILURES = new Set(['policy', 'route_state', 'route_material', 'flow_acquire',
  'transport_certificate', 'transport_tls', 'initial_paths', 'open_tcp_write', 'subflow_readiness', 'stream_attachment']);
const FLOW_HELPER_REASONS = ['helper_kernel', 'helper_capacity', 'helper_unavailable', 'helper_not_found',
  'helper_cleanup_incomplete', 'helper_other_rejection', 'helper_timeout', 'helper_io',
  'helper_validation', 'helper_authority', 'helper_correlation', 'helper_runtime_changed'];
const FLOW_BOUNDARIES = new Map([
  ['source_port', new Set(['entropy'])],
  ['retirement_drain', new Set(['unconfirmed', 'io', ...FLOW_HELPER_REASONS.filter(reason => reason !== 'helper_not_found')])],
  ['material', new Set(['metadata', 'topology'])],
  ['slot_reservation', new Set(['unconfirmed', 'local_capacity', 'local_unavailable'])],
  ['helper_acquire', new Set(FLOW_HELPER_REASONS)],
  ['descriptor_clone', new Set(['io'])],
  ['descriptor_adoption', new Set(['metadata', 'io'])],
  ['flow_metadata', new Set(['metadata'])],
]);
const DEPOSIT_CHALLENGE_PHASES = new Set(['selector_write_flush', 'grant_write_flush', 'challenge_read_verify']);
const DEPOSIT_ELAPSED_BUCKETS = new Set(['under_1s', '1_to_5s', '5_to_15s', '15_to_30s',
  '30_to_60s', '60_to_90s', '90_to_120s', 'at_least_120s']);
const DEPOSIT_OUTCOME_STATUSES = new Set(['observed', 'missing', 'pending', 'expired', 'query_failed', 'query_timeout']);
// Ordered like the core's nonzero PrivateStorageOutcomePhase discriminants (1..21).
const DEPOSIT_OUTCOME_PHASES = ['ready_write', 'local_request_read', 'local_request_verify',
  'local_payload_read', 'local_payload_verify', 'admission', 'remote_request_verify', 'remote_request_write',
  'remote_payload_write', 'remote_receipt_read', 'remote_receipt_verify', 'remote_payload_read',
  'remote_payload_verify', 'local_receipt_write', 'local_payload_write', 'provider_tls_close',
  'transport_tls_close', 'final_route_check', 'final_grant_check', 'final_lifetime_check', 'terminal_write'];
const DEPOSIT_OUTCOME_CATEGORIES = new Set(['io', 'auth', 'invalid', 'busy', 'store', 'expired', 'entropy',
  'timeout', 'policy', 'unavailable', 'cancelled']);
const DEPOSIT_OUTCOME_STAGES = new Set(['wire_receipt', 'agent_terminal', 'deadline']);
const DEPOSIT_OUTCOME_DEADLINES = new Set(['none', 'operation', 'exchange', 'bridge', 'remote_wire']);
const DEPOSIT_TLS_CLOSE_FAILURES = new Set(['shutdown_io', 'read_io', 'trailing_data', 'internal_deadline']);
const DIAGNOSTIC_SELECTORS = [
  ['appendDiagnosticsV7', '--append-diagnostics-v7', 7],
  ['flowAcquireDiagnosticsV8', '--flow-acquire-diagnostics-v8', 8],
  ['tlsCloseDiagnosticsV9', '--tls-close-diagnostics-v9', 9],
  ['challengeReadDiagnosticsV10', '--challenge-read-diagnostics-v10', 10],
];
const FALSE_FLAGS = ['metadata_overhead_measured', 'current_remote_availability_proven',
  'independent_failure_domains_proven', 'network_contribution_credit', 'automatic_repair',
  'automatic_handoff', 'read_consumes_archive', 'erasure_coding'];
const CONFIG_KEYS = ['version', 'coreBinary', 'controlSocket', 'identity', 'passphraseFile',
  'stateDirectory', 'providers', 'copies', 'fragmentBytes', 'lifetimeSeconds', 'deadlineMs',
  ...DIAGNOSTIC_SELECTORS.map(([key]) => key)];
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
    && (!Object.hasOwn(raw, 'copies') || raw.copies === CORE_CREATE_COPIES)
    && integer(raw.fragmentBytes, 1, 1024 ** 3)
    && integer(raw.lifetimeSeconds, 1, 2678400)
    && integer(raw.deadlineMs ?? 1800000, 100, 1800000)
    && DIAGNOSTIC_SELECTORS.every(([key]) => !Object.hasOwn(raw, key) || typeof raw[key] === 'boolean')
    && DIAGNOSTIC_SELECTORS.filter(([key]) => raw[key] === true).length <= 1);
  return Object.freeze({ ...raw, providers: Object.freeze(providers), deadlineMs: raw.deadlineMs ?? 1800000 });
}

function challengeRead(value, phase, check) {
  if (value === null) return null;
  check(object(value) && Object.keys(value).length === 2
    && Object.hasOwn(value, 'step') && Object.hasOwn(value, 'returned_outcome')
    && phase === 'challenge_read_verify' && ['length_read', 'body_read', 'verification'].includes(value.step));
  const allowed = { length_read: ['io_eof', 'io_other', 'invalid', 'wire_timeout'],
    body_read: ['io_eof', 'io_other', 'wire_timeout'], verification: ['invalid', 'verification_rejected'] };
  check(value.returned_outcome === null || allowed[value.step].includes(value.returned_outcome));
  return Object.freeze({ step: value.step, returned_outcome: value.returned_outcome });
}

// Raw CLI output stays private. Validate the accounting structure before publishing a closed summary.
function depositDiagnostics(raw, fragments, complete, selectedVersion) {
  const check = value => requireThat(value, 'invalid_core_report');
  const exactKeys = (value, keys) => object(value) && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
  const retainedCopies = fragments.reduce((sum, fragment) => sum + fragment.copies.length, 0);
  check(exactKeys(raw, ['version', 'failures', 'omitted_failures'])
    && [7, 8, 9, 10].includes(selectedVersion) && raw.version === selectedVersion
    && Array.isArray(raw.failures) && raw.failures.length <= 8
    && integer(raw.omitted_failures, 0, 2048)
    && raw.failures.length + raw.omitted_failures <= retainedCopies
    && (raw.omitted_failures === 0 || raw.failures.length === 8)
    && (!complete || (raw.failures.length === 0 && raw.omitted_failures === 0)));
  const seen = new Set();
  const failures = raw.failures.map(failure => {
    const keys = ['fragment_index', 'copy_index', 'operation', 'stage', 'category', 'agent_code'];
    if (raw.version !== 1) keys.push('agent_detail');
    if (raw.version >= 4) keys.push('agent_outcome');
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
      let flowAcquire = null, challengeReadDetail = null;
      if (detail !== null) {
        const detailKeys = ['stage', 'deadline_scope'];
        if (raw.version >= 3) detailKeys.push('tls_failure');
        if (raw.version >= 5) detailKeys.push('stream_failure');
        if (raw.version >= 6) detailKeys.push('challenge');
        if (raw.version >= 8) detailKeys.push('flow_acquire');
        check(exactKeys(detail, detailKeys)
          && stage === 'agent_ready' && category === 'agent_rejected' && agent_code !== 'unknown'
          && DEPOSIT_AGENT_STAGES.has(detail.stage)
          && ['none', 'operation', 'exchange'].includes(detail.deadline_scope)
          && (detail.stage !== 'unobserved' || detail.deadline_scope === 'operation')
          && (detail.deadline_scope !== 'exchange' || DEPOSIT_EXCHANGE_STAGES.has(detail.stage))
          && (detail.deadline_scope === 'none' || agent_code === 'CONTENT_UNAVAILABLE'));
        if (raw.version >= 3) {
          check(detail.tls_failure === null || (DEPOSIT_TLS_FAILURES.has(detail.tls_failure)
            && detail.stage === 'tls_handshake' && detail.deadline_scope === 'none'
            && agent_code === 'CONTENT_UNAVAILABLE'));
        }
        if (raw.version >= 5) {
          check(detail.stream_failure === null || (DEPOSIT_STREAM_FAILURES.has(detail.stream_failure)
            && detail.stage === 'stream_open' && detail.deadline_scope === 'none'
            && detail.tls_failure === null && agent_code === 'CONTENT_UNAVAILABLE'));
        }
        if (raw.version >= 6) {
          const challenge = detail.challenge;
          check(challenge === null || (exactKeys(challenge, ['phase', 'before_challenge', 'in_challenge', ...(raw.version === 10 ? ['read'] : [])])
            && DEPOSIT_CHALLENGE_PHASES.has(challenge.phase)
            && DEPOSIT_ELAPSED_BUCKETS.has(challenge.before_challenge)
            && DEPOSIT_ELAPSED_BUCKETS.has(challenge.in_challenge)
            && detail.stage === 'challenge' && detail.tls_failure === null && detail.stream_failure === null
            && agent_code === 'CONTENT_UNAVAILABLE'));
          if (raw.version === 10 && challenge !== null) challengeReadDetail = challengeRead(challenge.read, challenge.phase, check);
        }
        if (raw.version >= 8 && detail.flow_acquire !== null) {
          const flow = detail.flow_acquire;
          check(exactKeys(flow, ['rounds', 'first', 'last']) && integer(flow.rounds, 1, 8)
            && detail.stage === 'stream_open' && detail.deadline_scope === 'none'
            && detail.stream_failure === 'flow_acquire' && detail.tls_failure === null
            && detail.challenge === null && agent_code === 'CONTENT_UNAVAILABLE');
          for (const endpoint of [flow.first, flow.last]) {
            check(exactKeys(endpoint, ['stage', 'reason'])
              && FLOW_BOUNDARIES.get(endpoint.stage)?.has(endpoint.reason) === true);
          }
          check(flow.rounds !== 1 || (flow.first.stage === flow.last.stage && flow.first.reason === flow.last.reason));
          // Original local loop observations only; no remote capacity or cleanup claim.
          flowAcquire = Object.freeze({ rounds: flow.rounds,
            first: Object.freeze({ stage: flow.first.stage, reason: flow.first.reason }),
            last: Object.freeze({ stage: flow.last.stage, reason: flow.last.reason }) });
        }
      }
      closed.agent_detail = detail === null ? null
        : Object.freeze({ stage: detail.stage, deadline_scope: detail.deadline_scope,
          ...(raw.version >= 3 ? { tls_failure: detail.tls_failure } : {}),
          ...(raw.version >= 5 ? { stream_failure: detail.stream_failure } : {}),
          ...(raw.version >= 6 ? { challenge: detail.challenge === null ? null
            : Object.freeze({ phase: detail.challenge.phase, before_challenge: detail.challenge.before_challenge,
              in_challenge: detail.challenge.in_challenge,
              ...(raw.version === 10 ? { read: challengeReadDetail } : {}) }) } : {}),
          ...(raw.version >= 8 ? { flow_acquire: flowAcquire } : {}) });
    }
    if (raw.version >= 4) {
      const outcome = failure.agent_outcome;
      if (outcome !== null) {
        check(exactKeys(outcome, raw.version >= 9 ? ['status', 'detail', 'append_timing', 'tls_close_failure']
          : raw.version >= 7 ? ['status', 'detail', 'append_timing'] : ['status', 'detail'])
          && DEPOSIT_OUTCOME_STATUSES.has(outcome.status)
          && DEPOSIT_OUTCOME_STAGES.has(stage));
        const detail = outcome.detail;
        if (outcome.status === 'observed') {
          check(exactKeys(detail, ['phase', 'category', 'deadline_scope'])
            && DEPOSIT_OUTCOME_PHASES.includes(detail.phase) && DEPOSIT_OUTCOME_CATEGORIES.has(detail.category)
            && DEPOSIT_OUTCOME_DEADLINES.has(detail.deadline_scope)
            && (detail.category === 'timeout') === (detail.deadline_scope !== 'none')
            && (detail.deadline_scope !== 'bridge' || DEPOSIT_OUTCOME_PHASES.slice(1, 15).includes(detail.phase))
            && (detail.deadline_scope !== 'remote_wire' || DEPOSIT_OUTCOME_PHASES.slice(6, 13).includes(detail.phase)));
        } else check(detail === null);
        if (raw.version >= 7) {
          const timing = outcome.append_timing;
          check(timing === null || (exactKeys(timing, ['before_payload', 'in_payload_write_flush', 'in_receipt_read'])
            && operation === 'append' && outcome.status === 'observed'
            && DEPOSIT_ELAPSED_BUCKETS.has(timing.before_payload)
            && DEPOSIT_ELAPSED_BUCKETS.has(timing.in_payload_write_flush)
            && ((detail.phase === 'remote_payload_write' && timing.in_receipt_read === null)
              || (detail.phase === 'remote_receipt_read' && DEPOSIT_ELAPSED_BUCKETS.has(timing.in_receipt_read)))));
        }
        if (raw.version >= 9) {
          check(outcome.tls_close_failure === null || (DEPOSIT_TLS_CLOSE_FAILURES.has(outcome.tls_close_failure)
            && outcome.status === 'observed' && detail.phase === 'transport_tls_close'
            && detail.category === 'unavailable' && detail.deadline_scope === 'none'
            && outcome.append_timing === null));
        }
      }
      closed.agent_outcome = outcome === null ? null : Object.freeze({ status: outcome.status,
        detail: outcome.detail === null ? null : Object.freeze({ phase: outcome.detail.phase,
          category: outcome.detail.category, deadline_scope: outcome.detail.deadline_scope }),
        ...(raw.version >= 7 ? { append_timing: outcome.append_timing === null ? null
          : Object.freeze({ before_payload: outcome.append_timing.before_payload,
            in_payload_write_flush: outcome.append_timing.in_payload_write_flush,
            in_receipt_read: outcome.append_timing.in_receipt_read }) } : {}),
        ...(raw.version >= 9 ? { tls_close_failure: outcome.tls_close_failure } : {}) });
    }
    return Object.freeze(closed);
  });
  // Diagnostic evidence does not alter completion, accounting, retry or cleanup.
  return Object.freeze({ version: raw.version, failures: Object.freeze(failures), omitted_failures: raw.omitted_failures });
}

// Raw CLI output stays private. Validate accounting before the explicitly selected diagnostic extension.
function summary(raw, operation, diagnosticVersion = null) {
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
  // Unsolicited diagnostics are deliberately ignored, including malformed/future
  // values. Only the configuration-selected deposit version authorizes parsing.
  if (operation === 'deposit' && diagnosticVersion !== null) {
    check(Object.hasOwn(raw, 'deposit_diagnostics'));
    result.deposit_diagnostics = depositDiagnostics(raw.deposit_diagnostics, raw.fragments, complete, diagnosticVersion);
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
      const diagnostics = operation === 'deposit'
        ? DIAGNOSTIC_SELECTORS.find(([key]) => config[key] === true) : null;
      if (diagnostics) args.push(diagnostics[1]);
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
          report = summary(JSON.parse(execution.output), operation, diagnostics?.[2] ?? null);
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
