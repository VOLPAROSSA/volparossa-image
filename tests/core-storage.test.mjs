// SPDX-License-Identifier: GPL-3.0-only
// These are filesystem/process/CLI-contract tests, NOT a core or peer storage proof.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { chmod, lstat, mkdir, mkdtemp, open, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { CoreStorage } from '../src/core-storage.mjs';
import { runSnapshotStorage } from '../scripts/snapshot-storage.mjs';

const KEYS = ['11'.repeat(32), '22'.repeat(32), '33'.repeat(32)];
const CONTENT = Buffer.from('synthetic already-encrypted fixture bytes: opaque to this bridge');
const SHA = createHash('sha256').update(CONTENT).digest('hex');

function coreReport(operation, charge = 'committed', complete = true, { keys = KEYS, copiesPerFragment = 2 } = {}) {
  const fragments = [];
  const amounts = keys.map(() => 0);
  const charged = ['reserved', 'committed', 'uncertain'].includes(charge);
  let offset = 0;
  for (let index = 0; index < keys.length; index++) {
    const bytes = index === keys.length - 1 ? CONTENT.length - offset : Math.floor(CONTENT.length / keys.length);
    const copies = Array.from({ length: copiesPerFragment }, (_, copy) => {
      const provider = (index + copy) % keys.length;
      if (charged) amounts[provider] += bytes;
      return { provider_key: keys[provider], charge, last_confirmed_stored_bytes: bytes,
        last_confirmed_expiry: 3000000000, last_confirmed_state: charge === 'committed' ? 'Committed' : null };
    });
    fragments.push({ index, offset, ciphertext_bytes: bytes, confirmed_unexpired_copies: charge === 'committed' ? copiesPerFragment : 0, copies });
    offset += bytes;
  }
  const raw = {
    operation: `private_storage_fragments_${operation}`, logical_ciphertext_bytes: CONTENT.length,
    fragment_count: keys.length, copies_per_fragment: copiesPerFragment, distinct_provider_identities: keys.length,
    reserved_payload_bytes: charge === 'reserved' ? CONTENT.length * copiesPerFragment : 0,
    committed_payload_bytes: charge === 'committed' ? CONTENT.length * copiesPerFragment : 0,
    uncertain_payload_bytes: charge === 'uncertain' ? CONTENT.length * copiesPerFragment : 0,
    physical_payload_charge_upper_bound: charged ? CONTENT.length * copiesPerFragment : 0,
    metadata_overhead_measured: false, expired_copies_remain_charged: true,
    fragments_with_confirmed_unexpired_copy: charge === 'committed' ? keys.length : 0,
    fully_redundant_from_retained_receipts: charge === 'committed',
    current_remote_availability_proven: false, independent_failure_domains_proven: false,
    network_contribution_credit: false, automatic_repair: false, automatic_handoff: false,
    read_consumes_archive: false, erasure_coding: false, owner_signature_verified: true,
    providers: keys.map((key, index) => ({ provider_key: key, physical_payload_charge_upper_bound: amounts[index] })), fragments,
  };
  if (!['create', 'status'].includes(operation)) {
    raw.operation_complete = complete;
    raw.fragment_outcomes = [];
  }
  if (operation === 'restore') {
    raw.restored = complete;
    if (complete) raw.whole_archive_sha256_verified = true;
  }
  return raw;
}

// Matches the core's additive report v2, not a new app-side placement/accounting format.
function repairedReport(operation, stage = 'pending', replacements = 1) {
  const raw = coreReport(operation, 'committed', stage !== 'pending');
  const fragment = raw.fragments[0];
  for (let index = 0; index < replacements; index++) {
    const key = (index + 4).toString(16).padStart(2, '0').repeat(32);
    fragment.copies.push({ ...fragment.copies[0], provider_key: key });
    raw.providers.push({ provider_key: key, physical_payload_charge_upper_bound: 0 });
  }
  // Previous completed replacements retain deleted history. Only the last retires now.
  for (let index = 0; index < fragment.copies.length - 1; index++) {
    if (index !== 1) fragment.copies[index].charge = 'deleted';
  }
  const source = fragment.copies[replacements === 1 ? 0 : fragment.copies.length - 2];
  source.charge = stage === 'complete' || stage === 'deleted' ? 'deleted'
    : stage === 'pending' ? 'uncertain' : 'committed';
  fragment.copies.at(-1).charge = stage === 'planned' ? 'unattempted' : stage === 'reserved' ? 'reserved' : 'committed';
  raw.reserved_payload_bytes = 0;
  raw.committed_payload_bytes = 0;
  raw.uncertain_payload_bytes = 0;
  for (const provider of raw.providers) provider.physical_payload_charge_upper_bound = 0;
  for (const part of raw.fragments) {
    for (const copy of part.copies) {
      if (stage === 'deleted') copy.charge = 'deleted';
      copy.last_confirmed_state = copy.charge === 'committed' ? 'Committed' : copy.charge === 'deleted' ? 'Deleted' : null;
      if (['reserved', 'committed', 'uncertain'].includes(copy.charge)) {
        raw[`${copy.charge}_payload_bytes`] += part.ciphertext_bytes;
        raw.providers.find(provider => provider.provider_key === copy.provider_key).physical_payload_charge_upper_bound += part.ciphertext_bytes;
      }
    }
    part.confirmed_unexpired_copies = part.copies.filter(copy => copy.charge === 'committed').length;
  }
  raw.physical_payload_charge_upper_bound = raw.reserved_payload_bytes + raw.committed_payload_bytes + raw.uncertain_payload_bytes;
  raw.distinct_provider_identities = raw.providers.length;
  raw.fragments_with_confirmed_unexpired_copy = raw.fragments.filter(part => part.confirmed_unexpired_copies > 0).length;
  raw.fully_redundant_from_retained_receipts = raw.fragments.every(part => part.confirmed_unexpired_copies >= raw.copies_per_fragment);
  Object.assign(raw, { report_version: 2, placement_authorizations: replacements,
    retained_copy_records: raw.fragments.reduce((total, part) => total + part.copies.length, 0),
    pending_retirements: stage === 'complete' || stage === 'deleted' ? 0 : 1,
    desired_copies_per_fragment: raw.copies_per_fragment, replacement_overhead_included: true });
  return raw;
}

function fakeProcess(reply) {
  const calls = [];
  const spawnProcess = (binary, args, options) => {
    calls.push({ binary, args, options });
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    setImmediate(async () => {
      try {
        const operation = args[4];
        const response = await reply(operation, args, options);
        child.stdout.end(response.text ?? JSON.stringify(response.raw ?? coreReport(operation)));
        child.emit('close', response.code ?? 0, response.signal ?? null);
      } catch (error) { child.emit('error', error); child.emit('close', 1, null); }
    });
    return child;
  };
  return { calls, spawnProcess };
}

async function setup(t, { existing = true, configChanges = {}, process: selectedProcess } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'volparossa-image-contract-'));
  await chmod(root, 0o700);
  const socket = join(root, 'control.sock');
  const server = createServer(connection => connection.destroy());
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve); });
  await chmod(socket, 0o600);
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    await rm(root, { recursive: true });
  });
  for (const name of ['identity', 'passphrase', 'grant0', 'grant1', 'grant2']) {
    await writeFile(join(root, name), 'synthetic-private-fixture-only', { mode: 0o600 });
  }
  const input = join(root, 'snapshot.pgp');
  await writeFile(input, CONTENT, { mode: 0o600 });
  const config = { version: 1, coreBinary: process.execPath, controlSocket: socket,
    identity: join(root, 'identity'), passphraseFile: join(root, 'passphrase'), stateDirectory: join(root, 'journal'),
    providers: KEYS.map((key, index) => ({ key, grant: join(root, `grant${index}`) })),
    fragmentBytes: 16777216, lifetimeSeconds: 604800, deadlineMs: 30000, ...configChanges };
  if (existing) await mkdir(config.stateDirectory, { mode: 0o700 });
  const configPath = join(root, 'storage.json');
  await writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
  const fake = selectedProcess ?? fakeProcess(async operation => ({ raw: coreReport(operation) }));
  const adapter = await CoreStorage.open(configPath, { spawnProcess: fake.spawnProcess });
  return { root, config, configPath, input, adapter, ...fake };
}

test('create is explicit encrypted input, exact argv, no inherited environment or raw report', async t => {
  const fixture = await setup(t, { existing: false, process: fakeProcess(async operation => ({
    raw: { ...coreReport(operation, 'unattempted'), arbitrary_private_text: 'NEVER-PUBLISH' },
  })) });
  const result = await fixture.adapter.create({ input: fixture.input, sha256: SHA, alreadyEncrypted: true });
  assert.equal(result.status, 'complete');
  assert.equal(result.storage.committed_payload_bytes, 0);
  assert.equal(result.remote_cleanup_confirmed, false);
  assert.equal(result.restore_verified, false);
  assert.deepEqual(fixture.calls[0].args, ['--control-socket', fixture.config.controlSocket,
    'storage', 'fragments', 'create', '--state', fixture.config.stateDirectory,
    '--identity', fixture.config.identity, '--passphrase-file', fixture.config.passphraseFile,
    '--input', fixture.input, '--already-encrypted', '--sha256', SHA,
    '--fragment-bytes', '16777216', '--lifetime-seconds', '604800',
    ...fixture.config.providers.flatMap(({ key, grant }) => ['--provider-key', key, '--grant', grant])]);
  assert.deepEqual(fixture.calls[0].options.env, { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' });
  assert.equal(fixture.calls[0].options.shell, false);
  assert.equal(fixture.calls[0].options.detached, true);
  assert.deepEqual(fixture.calls[0].options.stdio, ['ignore', 'pipe', 'ignore']);
  const encoded = JSON.stringify(result);
  for (const secret of [fixture.root, KEYS[0], 'NEVER-PUBLISH', 'synthetic-private-fixture-only']) assert.ok(!encoded.includes(secret));
});

test('incomplete deposit keeps exact state/charged bytes; retry uses no new placement or identity', async t => {
  let attempt = 0;
  const fixture = await setup(t, { process: fakeProcess(async operation => {
    attempt++;
    return { raw: coreReport(operation, attempt === 1 ? 'uncertain' : 'committed', attempt !== 1), code: attempt === 1 ? 1 : 0 };
  }) });
  const request = { input: fixture.input, alreadyEncrypted: true };
  const incomplete = await fixture.adapter.deposit(request);
  assert.equal(incomplete.status, 'incomplete');
  assert.equal(incomplete.storage.uncertain_payload_bytes, CONTENT.length * 2);
  const complete = await fixture.adapter.deposit(request);
  assert.equal(complete.status, 'complete');
  assert.deepEqual(fixture.calls[0].args, fixture.calls[1].args);
  assert.ok(!fixture.calls[0].args.includes('--provider-key'));
  assert.equal((await readFile(fixture.input)).equals(CONTENT), true);
});

test('optional copies=2 is only compatibility and never an application-selected CLI target', async t => {
  const fixture = await setup(t, { existing: false, configChanges: { copies: 2 } });
  assert.equal((await fixture.adapter.create({ input: fixture.input, sha256: SHA, alreadyEncrypted: true })).status, 'complete');
  assert.ok(!fixture.calls[0].args.includes('--copies'));
  for (const copies of [1, 3, 7, '2', null]) {
    await writeFile(fixture.configPath, JSON.stringify({ ...fixture.config, copies,
      providers: [...fixture.config.providers, { key: '44'.repeat(32), grant: join(fixture.root, 'grant3') }] }));
    await assert.rejects(CoreStorage.open(fixture.configPath), { code: 'invalid_configuration' });
  }
});

test('v2 status preserves exact charged history, extra confirmed copies and pending retirement', async t => {
  for (const stage of ['planned', 'reserved', 'verified', 'pending', 'complete', 'deleted']) {
    const raw = repairedReport('status', stage);
    const fixture = await setup(t, { process: fakeProcess(async () => ({ raw })) });
    const result = await fixture.adapter.status();
    assert.equal(result.status, 'complete', stage);
    for (const key of ['report_version', 'placement_authorizations', 'retained_copy_records', 'pending_retirements',
      'desired_copies_per_fragment', 'replacement_overhead_included', 'physical_payload_charge_upper_bound',
      'reserved_payload_bytes', 'committed_payload_bytes', 'uncertain_payload_bytes']) assert.equal(result.storage[key], raw[key], key);
    assert.equal(result.storage.copies_per_fragment, 2);
    assert.equal(result.storage.automatic_repair, false);
    for (const key of raw.providers.map(provider => provider.provider_key)) assert.ok(!JSON.stringify(result).includes(key));
  }
});

test('v2 provider history can exceed both original pool and fragment count', async t => {
  const raw = repairedReport('status', 'pending', 6);
  assert.equal(raw.distinct_provider_identities, 9);
  const fixture = await setup(t, { process: fakeProcess(async () => ({ raw })) });
  const result = await fixture.adapter.status();
  assert.equal(result.status, 'complete');
  assert.equal(result.storage.distinct_provider_identities, 9);
  assert.equal(result.storage.retained_copy_records, 12);
  assert.equal(result.storage.physical_payload_charge_upper_bound, CONTENT.length * 2 + raw.fragments[0].ciphertext_bytes);
});

test('v2 pending retirement remains usable for existing lifecycle operations without re-placement', async t => {
  const fixture = await setup(t, { process: fakeProcess(async (operation, args) => {
    const raw = repairedReport(operation, operation === 'delete' ? 'deleted' : 'pending');
    raw.operation_complete = operation !== 'deposit';
    if (operation === 'restore') {
      raw.restored = true;
      raw.whole_archive_sha256_verified = true;
      await writeFile(args[args.indexOf('--output') + 1], CONTENT, { mode: 0o600, flag: 'wx' });
    }
    return { raw, code: raw.operation_complete ? 0 : 1 };
  }) });
  assert.equal((await fixture.adapter.deposit({ input: fixture.input, alreadyEncrypted: true })).status, 'incomplete');
  assert.equal((await fixture.adapter.progress()).storage.pending_retirements, 1);
  assert.equal((await fixture.adapter.renew({ lifetimeSeconds: 1200 })).status, 'complete');
  for (const name of ['restore-one', 'restore-two']) {
    const result = await fixture.adapter.restore({ output: join(fixture.root, name), sha256: SHA });
    assert.equal(result.restore_verified, true);
    assert.equal(result.storage.pending_retirements, 1);
  }
  assert.equal((await fixture.adapter.delete()).storage.physical_payload_charge_upper_bound, 0);
  for (const call of fixture.calls) {
    assert.ok(!call.args.includes('--copies') && !call.args.includes('--provider-key'));
    assert.equal(call.args[call.args.indexOf('--state') + 1], fixture.config.stateDirectory);
  }
  assert.ok((await lstat(fixture.config.stateDirectory)).isDirectory());
});

test('legacy three-copy archives remain readable and restorable without redefining their target', async t => {
  const keys = [...KEYS, '44'.repeat(32)];
  const fixture = await setup(t, { process: fakeProcess(async (operation, args) => {
    if (operation === 'restore') await writeFile(args[args.indexOf('--output') + 1], CONTENT, { mode: 0o600, flag: 'wx' });
    return { raw: coreReport(operation, operation === 'delete' ? 'deleted' : 'committed', true, { keys, copiesPerFragment: 3 }) };
  }) });
  assert.equal((await fixture.adapter.status()).storage.copies_per_fragment, 3);
  assert.equal((await fixture.adapter.progress()).storage.physical_payload_charge_upper_bound, CONTENT.length * 3);
  assert.equal((await fixture.adapter.renew({ lifetimeSeconds: 1200 })).storage.copies_per_fragment, 3);
  const restored = await fixture.adapter.restore({ output: join(fixture.root, 'legacy.pgp'), sha256: SHA });
  assert.equal(restored.restore_verified, true);
  assert.equal(restored.storage.copies_per_fragment, 3);
  assert.equal((await fixture.adapter.delete()).storage.physical_payload_charge_upper_bound, 0);
  assert.deepEqual(await readFile(fixture.input), CONTENT);
  const newArchive = await setup(t, { existing: false, process: fakeProcess(async operation => ({
    raw: coreReport(operation, 'unattempted', true, { keys, copiesPerFragment: 3 }),
  })) });
  assert.equal((await newArchive.adapter.create({ input: newArchive.input, sha256: SHA, alreadyEncrypted: true })).code, 'invalid_core_report');
});

test('v2 contradictions, downgrade, invented history or hidden charges fail closed', async t => {
  const mutations = [raw => { raw.report_version = 3; }, raw => { delete raw.report_version; },
    raw => { delete raw.placement_authorizations; }, raw => { raw.placement_authorizations++; },
    raw => { raw.retained_copy_records++; }, raw => { raw.desired_copies_per_fragment = 3; },
    raw => { raw.pending_retirements = 2; }, raw => { raw.replacement_overhead_included = false; },
    raw => { raw.uncertain_payload_bytes = 0; raw.physical_payload_charge_upper_bound -= raw.fragments[0].ciphertext_bytes; },
    raw => { raw.providers.at(-1).physical_payload_charge_upper_bound = 0; },
    raw => { raw.fragments[0].copies[0].provider_key = raw.fragments[0].copies.at(-1).provider_key; },
    raw => { raw.fragments[0].confirmed_unexpired_copies = 3; },
    raw => { raw.owner_signature_verified = false; }, raw => { raw.automatic_repair = true; },
    raw => { raw.providers.push({ provider_key: 'ee'.repeat(32), physical_payload_charge_upper_bound: 0 }); raw.distinct_provider_identities++; },
    raw => { raw.fragments[1].copies.reverse(); }];
  for (const mutate of mutations) {
    const fixture = await setup(t, { process: fakeProcess(async operation => {
      const raw = repairedReport(operation); mutate(raw); return { raw };
    }) });
    const result = await fixture.adapter.status();
    assert.equal(result.status, 'failed');
    assert.equal(result.code, 'invalid_core_report');
    assert.equal(result.storage, null);
  }
});

test('status, progress, renew, delete retain operation-specific arguments', async t => {
  const fixture = await setup(t);
  await fixture.adapter.status();
  await fixture.adapter.progress();
  await fixture.adapter.renew({ lifetimeSeconds: 3600 });
  await fixture.adapter.delete();
  assert.deepEqual(fixture.calls.map(call => call.args[4]), ['status', 'progress', 'renew', 'delete']);
  assert.ok(!fixture.calls[0].args.includes('--identity'));
  assert.ok(!fixture.calls[0].args.includes('--passphrase-file'));
  assert.deepEqual(fixture.calls[2].args.slice(-2), ['--lifetime-seconds', '3600']);
  assert.ok((await lstat(fixture.config.stateDirectory)).isDirectory());
});

test('explicitly incomplete deletion retains conservative charge, not an erasure claim', async t => {
  const fixture = await setup(t, { process: fakeProcess(async operation => ({ raw: coreReport(operation, 'uncertain', false), code: 1 })) });
  const result = await fixture.adapter.delete();
  assert.equal(result.status, 'incomplete');
  assert.equal(result.storage.physical_payload_charge_upper_bound, CONTENT.length * 2);
  assert.equal(result.remote_cleanup_confirmed, false);
});

test('restore requires a new output and independently hashes retained ciphertext without consuming it', async t => {
  const fixture = await setup(t, { process: fakeProcess(async (operation, args) => {
    await writeFile(args[args.indexOf('--output') + 1], CONTENT, { mode: 0o600, flag: 'wx' });
    return { raw: coreReport(operation) };
  }) });
  const output = join(fixture.root, 'restored.pgp');
  const result = await fixture.adapter.restore({ output, sha256: SHA });
  assert.equal(result.status, 'complete');
  assert.equal(result.restore_verified, true);
  assert.equal(result.storage.read_consumes_archive, false);
  assert.deepEqual(await readFile(output), CONTENT);
  await assert.rejects(fixture.adapter.restore({ output, sha256: SHA }), { code: 'output_exists' });
  assert.equal(fixture.calls.length, 1);
  const second = await fixture.adapter.restore({ output: join(fixture.root, 'second.pgp'), sha256: SHA });
  assert.equal(second.restore_verified, true);
});

test('a lying restore report or wrong independently retained hash never verifies; file is preserved', async t => {
  const fixture = await setup(t, { process: fakeProcess(async (operation, args) => {
    await writeFile(args[args.indexOf('--output') + 1], CONTENT, { mode: 0o600 });
    return { raw: coreReport(operation) };
  }) });
  const output = join(fixture.root, 'restored.pgp');
  const result = await fixture.adapter.restore({ output, sha256: 'ab'.repeat(32) });
  assert.equal(result.status, 'failed');
  assert.equal(result.code, 'restore_verification_failed');
  assert.equal(result.restore_verified, false);
  assert.deepEqual(await readFile(output), CONTENT);
});

test('rejects plaintext acknowledgement, malformed hash, free-form args and existing state before spawn', async t => {
  const fixture = await setup(t, { existing: false });
  await assert.rejects(fixture.adapter.create({ input: fixture.input, sha256: SHA, alreadyEncrypted: false }));
  await assert.rejects(fixture.adapter.create({ input: fixture.input, sha256: 'bad', alreadyEncrypted: true }));
  await assert.rejects(fixture.adapter.create({ input: fixture.input, sha256: SHA, alreadyEncrypted: true, args: ['--evil'] }));
  await mkdir(fixture.config.stateDirectory, { mode: 0o700 });
  await assert.rejects(fixture.adapter.create({ input: fixture.input, sha256: SHA, alreadyEncrypted: true }), { code: 'output_exists' });
  assert.equal(fixture.calls.length, 0);
});

test('rejects exposed private inputs and symlink inputs without disclosing paths', async t => {
  const fixture = await setup(t);
  await chmod(fixture.input, 0o644);
  await assert.rejects(fixture.adapter.deposit({ input: fixture.input, alreadyEncrypted: true }), { code: 'private_file_required' });
  await chmod(fixture.input, 0o600);
  const link = join(fixture.root, 'alias');
  await symlink(fixture.input, link);
  await assert.rejects(fixture.adapter.deposit({ input: link, alreadyEncrypted: true }), error => {
    assert.ok(!error.message.includes(fixture.root));
    return true;
  });
  assert.equal(fixture.calls.length, 0);
});

test('invalid provider plan/config and non-private config are rejected', async t => {
  const fixture = await setup(t);
  await writeFile(fixture.configPath, JSON.stringify({ ...fixture.config, copies: 3 }));
  await assert.rejects(CoreStorage.open(fixture.configPath), { code: 'invalid_configuration' });
  await writeFile(fixture.configPath, JSON.stringify({ ...fixture.config, additionalCommand: 'sh' }));
  await assert.rejects(CoreStorage.open(fixture.configPath), { code: 'invalid_configuration' });
  await chmod(fixture.configPath, 0o644);
  await assert.rejects(CoreStorage.open(fixture.configPath), { code: 'private_file_required' });
});

test('rejects more than 256 planned fragments before signing/spawning', async t => {
  const fixture = await setup(t, { existing: false, configChanges: { fragmentBytes: 1 } });
  await writeFile(fixture.input, Buffer.alloc(257));
  await assert.rejects(fixture.adapter.create({ input: fixture.input, sha256: SHA, alreadyEncrypted: true }), { code: 'invalid_fragment_plan' });
  assert.equal(fixture.calls.length, 0);
});

test('report contradictions, mismatched operation and invented accounting fail closed', async t => {
  const mutations = [raw => { raw.operation = 'wrong'; }, raw => { raw.physical_payload_charge_upper_bound++; },
    raw => { raw.fragments[1].offset++; }, raw => { raw.providers[0].physical_payload_charge_upper_bound++; },
    raw => { raw.current_remote_availability_proven = true; }, raw => { raw.fragments[0].copies[1].provider_key = KEYS[0]; },
    raw => { raw.owner_signature_verified = false; }];
  for (const mutate of mutations) {
    const fixture = await setup(t, { process: fakeProcess(async operation => {
      const raw = coreReport(operation); mutate(raw); return { raw };
    }) });
    const result = await fixture.adapter.status();
    assert.equal(result.status, 'failed');
    assert.equal(result.code, 'invalid_core_report');
    assert.equal(result.storage, null);
  }
});

test('exit status must agree with completion; raw stderr/invalid JSON are not exposed', async t => {
  for (const response of [{ raw: coreReport('progress'), code: 1 },
    { raw: coreReport('progress', 'uncertain', false), code: 0 },
    { text: 'PATH-AND-SECRET-NOT-JSON', code: 1 }]) {
    const fixture = await setup(t, { process: fakeProcess(async () => response) });
    const result = await fixture.adapter.progress();
    assert.equal(result.status, 'failed');
    assert.equal(result.storage, null);
    assert.ok(!JSON.stringify(result).includes('PATH-AND-SECRET'));
  }
});

test('oversized report is discarded and only reports joined failure', async t => {
  const fixture = await setup(t, { process: fakeProcess(async () => ({ text: 'x'.repeat(2 * 1024 ** 2 + 1) })) });
  const result = await fixture.adapter.status();
  assert.equal(result.status, 'failed');
  assert.equal(result.code, 'report_too_large');
  assert.equal(result.local_process_joined, true);
  assert.equal(result.storage, null);
});

test('pre-cancelled request never spawns', async t => {
  const fixture = await setup(t);
  await assert.rejects(fixture.adapter.status({ signal: AbortSignal.abort() }), { code: 'cancelled' });
  assert.equal(fixture.calls.length, 0);
});

test('real synthetic child cancellation joins its owned process group and keeps the journal', async t => {
  let ready;
  const started = new Promise(resolve => { ready = resolve; });
  let child;
  const fixture = await setup(t, { process: { spawnProcess: (_binary, _args, options) => {
    child = spawn(process.execPath, ['-e', 'process.stdout.write("ready"); setInterval(() => {}, 1000)'], options);
    child.stdout.once('data', ready);
    return child;
  } } });
  const controller = new AbortController();
  const running = fixture.adapter.progress({ signal: controller.signal });
  await started;
  await assert.rejects(fixture.adapter.status(), { code: 'operation_in_progress' });
  controller.abort();
  const result = await running;
  assert.equal(result.status, 'cancelled');
  assert.equal(result.local_process_joined, true);
  assert.equal(result.remote_cleanup_confirmed, false);
  assert.equal(child.signalCode, 'SIGTERM');
  assert.ok((await lstat(fixture.config.stateDirectory)).isDirectory());
});

test('real synthetic child deadline requests termination and waits for close', async t => {
  const fixture = await setup(t, { configChanges: { deadlineMs: 100 }, process: {
    spawnProcess: (_binary, _args, options) => spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], options),
  } });
  const result = await fixture.adapter.progress();
  assert.equal(result.status, 'timed_out');
  assert.equal(result.local_process_joined, true);
  assert.equal(result.storage, null);
});

function checkpoint(stage = 'waiting_for_core', turns = 0) {
  return { version: 1, scope: 'owner-private-maintenance', stage, turns, at: Math.floor(Date.now() / 1000),
    detail: { private_path: 'DO-NOT-EXPORT' }, core_coordinated: true, new_network_node: false,
    automatic_grant_refresh: false, private_key_exported: false };
}

// Actual inert Node children exercise process ownership; the simulated core responses
// below do NOT establish Rust signatures, protected storage or repair functionality.
async function maintenanceFixture(t, { worker = '', foreground, maximumTurns, failedClose = false, foregroundWorker, terminationCode = 0 } = {}) {
  let fixture;
  t.after(async () => {
    if (failedClose) await assert.rejects(fixture.adapter.close(), { code: 'maintenance_cleanup_unconfirmed' });
    else await fixture?.adapter.close();
  });
  const calls = [], children = [], order = [];
  let latest = checkpoint();
  const oneShot = fakeProcess(async (operation, args) => {
    if (operation === 'maintenance') {
      if (args[5] === 'enroll') {
        await mkdir(fixture.enrollment, { mode: 0o700 });
        await fixture.writeEnrollment();
        latest = checkpoint('enrolled');
      }
      return { raw: latest };
    }
    order.push(operation);
    if (foreground) return foreground(operation, args, fixture);
    if (operation === 'restore') await writeFile(args[args.indexOf('--output') + 1], CONTENT, { mode: 0o600, flag: 'wx' });
    return { raw: coreReport(operation) };
  });
  const spawnProcess = (binary, args, options) => {
    calls.push({ binary, args, options });
    if (args[4] !== 'maintenance' && foregroundWorker) return foregroundWorker(binary, args, options, fixture);
    if (args[4] !== 'maintenance' || args[5] !== 'serve') return oneShot.spawnProcess(binary, args, options);
    order.push('serve');
    const source = `process.on('SIGTERM',()=>process.exit(${terminationCode}));
      process.stdout.write(process.argv[1]+'\\n');
      setInterval(()=>{},1000); ${worker}`;
    const child = spawn(process.execPath, ['-e', source, JSON.stringify(checkpoint())], options);
    child.receivedBytes = 0;
    child.stdout.on('data', chunk => { child.receivedBytes += chunk.length; });
    child.ready = new Promise(resolve => child.stdout.once('data', resolve));
    child.once('close', () => order.push('joined'));
    children.push(child);
    return child;
  };
  fixture = await setup(t, { process: { spawnProcess, calls } });
  fixture.enrollment = join(fixture.root, 'maintenance');
  fixture.writeEnrollment = async changes => {
    const now = Math.floor(Date.now() / 1000);
    await writeFile(join(fixture.enrollment, 'enrollment.json'), JSON.stringify({
      enrollment: { version: 1, created: now - 10, expires: now + 600, archive: fixture.config.stateDirectory,
        ...changes }, signature: 'synthetic-only-not-a-core-signature',
    }), { mode: 0o600 });
  };
  await mkdir(fixture.enrollment, { mode: 0o700 });
  await fixture.writeEnrollment();
  await writeFile(join(fixture.config.stateDirectory, 'retained'), 'same-private-journal', { mode: 0o600 });
  fixture.request = { enrollment: fixture.enrollment, ...(maximumTurns === undefined ? {} : { maximumTurns }) };
  return Object.assign(fixture, { children, order, latest: value => { latest = value; },
    async start(options) { const handle = await fixture.adapter.startMaintenance(fixture.request, options); await children.at(-1).ready; return handle; } });
}

test('finite maintenance enrollment forwards only explicit owner scope; no network/socket precondition', async t => {
  const f = await maintenanceFixture(t);
  await rm(f.enrollment, { recursive: true });
  const request = { enrollment: f.enrollment, fromProviderKey: KEYS[0], providers: f.config.providers.slice(1),
    authorizationSeconds: 600, lifetimeSeconds: 300, renewBeforeSeconds: 60,
    maximumChargedBytes: 4096, maximumTurnBytes: 1048576 };
  const result = await f.adapter.enrollMaintenance(request);
  assert.equal(result.status, 'complete');
  assert.equal(result.checkpoint.stage, 'enrolled');
  const args = f.calls[0].args;
  assert.deepEqual(args.slice(2, 6), ['storage', 'fragments', 'maintenance', 'enroll']);
  for (const [flag, expected] of [['--authorization-seconds', '600'], ['--maximum-charged-bytes', '4096'],
    ['--maximum-turn-bytes', '1048576'], ['--from-provider-key', KEYS[0]], ['--state', f.config.stateDirectory]]) {
    assert.equal(args[args.indexOf(flag) + 1], expected);
  }
  assert.equal(args.filter(value => value === '--provider-key').length, 2);
  assert.ok(!args.includes('--authorization-expires-at'));
  assert.ok(!JSON.stringify(result).includes(f.root));
  assert.ok(!JSON.stringify(result).includes('DO-NOT-EXPORT'));
  assert.ok(!args.includes('recovery.key'));
  for (const changes of [{ authorizationSeconds: 0 }, { maximumTurnBytes: 134217729 },
    { providers: [f.config.providers[0]] }, { providers: [f.config.providers[1], f.config.providers[1]] },
    { enrollment: join(f.config.stateDirectory, 'nested') }, { automaticRenewal: true }]) {
    await assert.rejects(f.adapter.enrollMaintenance({ ...request, ...changes }));
  }
});

test('maintenance forwards the exact optional absolute expiry without replacing its relative limit', async t => {
  const f = await maintenanceFixture(t);
  await rm(f.enrollment, { recursive: true });
  // A historical deadline deliberately proves that this bridge does not turn
  // an elapsed service window into a fresh one. Actual expiry rejection belongs
  // to the core signing boundary, not this synthetic CLI-argument fixture.
  const authorizationExpiresAt = 1700000000;
  const request = { enrollment: f.enrollment, fromProviderKey: KEYS[0], providers: f.config.providers.slice(1),
    authorizationSeconds: 600, authorizationExpiresAt, lifetimeSeconds: 300, renewBeforeSeconds: 60,
    maximumChargedBytes: 4096, maximumTurnBytes: 1048576 };
  await f.adapter.enrollMaintenance(request);
  assert.equal(f.calls.length, 1);
  const { args } = f.calls[0];
  assert.equal(args.filter(value => value === '--authorization-expires-at').length, 1);
  assert.equal(args[args.indexOf('--authorization-expires-at') + 1], String(authorizationExpiresAt));
  assert.equal(args[args.indexOf('--authorization-seconds') + 1], '600');
  assert.equal(request.authorizationExpiresAt, authorizationExpiresAt);
});

test('invalid absolute maintenance expiries are rejected before any core process starts', async t => {
  const f = await maintenanceFixture(t);
  await rm(f.enrollment, { recursive: true });
  const request = { enrollment: f.enrollment, fromProviderKey: KEYS[0], providers: f.config.providers.slice(1),
    authorizationSeconds: 600, lifetimeSeconds: 300, renewBeforeSeconds: 60,
    maximumChargedBytes: 4096, maximumTurnBytes: 1048576 };
  for (const authorizationExpiresAt of [undefined, null, false, true, '1700000000', 0, -1, 1.5,
    NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(f.adapter.enrollMaintenance({ ...request, authorizationExpiresAt }), { code: 'invalid_request' });
  }
  assert.equal(f.calls.length, 0);
});

test('maintenance owns a real child while status stays distinct from stale checkpoint; stop joins without deleting state', async t => {
  const f = await maintenanceFixture(t);
  // No contact with a missing core is attempted by the app-side preflight.
  await rm(f.config.controlSocket);
  const original = await readFile(join(f.enrollment, 'enrollment.json'));
  const handle = await f.start();
  const status = await handle.status();
  assert.equal(status.owned_process_running, true);
  assert.equal(status.local_process_joined, false);
  assert.equal(status.checkpoint.stage, 'waiting_for_core');
  assert.ok(!JSON.stringify(status).includes('DO-NOT-EXPORT'));
  await assert.rejects(f.adapter.startMaintenance(f.request), { code: 'maintenance_in_progress' });
  const stopped = await handle.stop();
  assert.equal(stopped.local_process_joined, true);
  assert.equal(stopped.remote_cleanup_confirmed, false);
  assert.equal(f.children[0].exitCode, 0);
  assert.equal(await handle.done, stopped);
  assert.equal((await f.adapter.maintenanceStatus(f.request)).owned_process_running, false);
  assert.deepEqual(await readFile(join(f.enrollment, 'enrollment.json')), original);
  assert.equal(await readFile(join(f.config.stateDirectory, 'retained'), 'utf8'), 'same-private-journal');
});

test('same-fd enrollment growth is rejected before allocating beyond the bounded JSON record', async t => {
  const f = await maintenanceFixture(t);
  const enrollmentFile = join(f.enrollment, 'enrollment.json');
  const inode = (await lstat(enrollmentFile)).ino;
  const handle = await open(enrollmentFile, 'r');
  const prototype = Object.getPrototypeOf(handle);
  await handle.close();
  const originalStat = prototype.stat;
  let grew = false, oversizedAllocation = false;
  t.mock.method(prototype, 'stat', async function (options) {
    const value = await originalStat.call(this, options);
    if (!grew && !options?.bigint && value.ino === inode) {
      // Real bytes grow after privateFile's first same-fd stat, before privateJSON's second.
      grew = true;
      await writeFile(enrollmentFile, Buffer.alloc(32769, 120));
    }
    return value;
  });
  const allocate = Buffer.alloc;
  t.mock.method(Buffer, 'alloc', (size, ...args) => {
    if (size === 32770) oversizedAllocation = true;
    return allocate(size, ...args);
  });
  await assert.rejects(f.adapter.startMaintenance(f.request), { code: 'private_file_required' });
  assert.equal(grew, true);
  assert.equal(oversizedAllocation, false);
  assert.equal(f.children.length, 0);
});

test('Image snapshot restore joins maintenance before archive use then resumes the identical finite session', async t => {
  const f = await maintenanceFixture(t, { maximumTurns: 8 });
  const handle = await f.start();
  f.latest(checkpoint('paused', 3));
  const receipt = { version: 1, kind: 'volparossa-immich-snapshot', cipher_file: 'snapshot.pgp',
    cipher_sha256: SHA, cipher_bytes: CONTENT.length, encryption: 'OpenPGP-AES256',
    source_consistency: 'operator-asserted-quiesced-copy' };
  const receiptPath = join(f.root, 'original-receipt.json');
  await writeFile(receiptPath, JSON.stringify(receipt), { mode: 0o600 });
  const output = join(f.root, 'restored');
  const result = await runSnapshotStorage({ operation: 'restore', config: f.configPath, receipt: receiptPath, output },
    { storageFactory: async () => f.adapter });
  await f.children[1].ready;
  assert.equal(result.restore_verified, true);
  assert.deepEqual(await readFile(join(output, 'snapshot.pgp')), CONTENT);
  assert.deepEqual(JSON.parse(await readFile(join(output, 'receipt.json'), 'utf8')), receipt);
  assert.equal(result.snapshot_decrypted, false);
  assert.equal(result.immich_restore_proven, false);
  assert.deepEqual(f.order, ['serve', 'joined', 'restore', 'serve']);
  const serves = f.calls.filter(call => call.args[5] === 'serve');
  assert.equal(serves.length, 2);
  assert.equal(serves[0].args[serves[0].args.indexOf('--maximum-turns') + 1], '8');
  assert.equal(serves[1].args[serves[1].args.indexOf('--maximum-turns') + 1], '5');
  assert.equal(serves[0].args[7], serves[1].args[7]);
  assert.ok(f.calls.every(call => call.args[5] !== 'enroll'));
  await handle.stop();
});

test('unsuccessful foreground or delete never restarts maintenance or clears journals', async t => {
  for (const operation of ['progress', 'delete']) {
    const f = await maintenanceFixture(t, { foreground: async name => ({
      raw: coreReport(name, name === 'delete' ? 'deleted' : 'uncertain', name === 'delete'),
      code: name === 'delete' ? 0 : 1,
    }) });
    const handle = await f.start();
    const result = await f.adapter[operation]();
    assert.equal(result.status, operation === 'delete' ? 'complete' : 'incomplete');
    assert.equal(f.children.length, 1);
    assert.equal((await handle.done).code, 'foreground_not_resumed');
    assert.equal(await readFile(join(f.config.stateDirectory, 'retained'), 'utf8'), 'same-private-journal');
  }
});

test('changed or expired enrollment prevents foreground resume without granting new authority', async t => {
  for (const changes of [{ changed: true }, { expires: Math.floor(Date.now() / 1000) - 1 }]) {
    const f = await maintenanceFixture(t, { foreground: async (operation, _args, fixture) => {
      await fixture.writeEnrollment(changes);
      return { raw: coreReport(operation) };
    } });
    const handle = await f.start();
    assert.equal((await f.adapter.status()).status, 'complete');
    assert.equal(f.children.length, 1);
    assert.equal((await handle.done).code, 'resume_unavailable');
  }
});

test('a session exhausts its original turn allowance across foreground work without creating another process', async t => {
  const f = await maintenanceFixture(t, { maximumTurns: 3 });
  const handle = await f.start();
  f.latest(checkpoint('paused', 3));
  assert.equal((await f.adapter.status()).status, 'complete');
  assert.equal((await handle.done).code, 'turn_limit');
  assert.equal(f.children.length, 1);
});

test('finite enrollment expiration stops and joins the owned background process', async t => {
  const f = await maintenanceFixture(t);
  await f.writeEnrollment({ expires: Math.floor(Date.now() / 1000) + 2 });
  const handle = await f.start();
  const result = await handle.done;
  assert.equal(result.code, 'enrollment_expired');
  assert.equal(result.status, 'stopped');
  assert.equal(f.children[0].exitCode, 0);
  assert.equal(f.children.length, 1);
});

test('session cancellation and adapter close join their own process, no implicit reopen', async t => {
  const f = await maintenanceFixture(t);
  const owner = new AbortController();
  const handle = await f.start({ signal: owner.signal });
  owner.abort();
  assert.equal((await handle.done).code, 'cancelled');
  assert.equal(f.children[0].exitCode, 0);
  const closing = f.adapter.close();
  assert.equal(f.adapter.close(), closing);
  await closing;
  await assert.rejects(f.adapter.status(), { code: 'storage_closed' });
  await assert.rejects(f.adapter.startMaintenance(f.request), { code: 'storage_closed' });
});

test('failed maintenance stop prevents foreground and remains a rejected close even after the session ended', async t => {
  const f = await maintenanceFixture(t, { failedClose: true, terminationCode: 7 });
  const handle = await f.start();
  await assert.rejects(f.adapter.progress(), { code: 'maintenance_cleanup_unconfirmed' });
  assert.equal((await handle.done).status, 'failed');
  assert.equal(f.children[0].exitCode, 7);
  assert.deepEqual(f.order, ['serve', 'joined']);
  await assert.rejects(f.adapter.progress(), { code: 'maintenance_cleanup_unconfirmed' });
  const closing = f.adapter.close();
  assert.equal(f.adapter.close(), closing);
  await assert.rejects(closing, { code: 'maintenance_cleanup_unconfirmed' });
});

test('close during foreground cancels and joins that owned child without resuming maintenance', async t => {
  let ready, foregroundChild;
  const started = new Promise(resolve => { ready = resolve; });
  const f = await maintenanceFixture(t, { foregroundWorker: (_binary, _args, options) => {
    foregroundChild = spawn(process.execPath, ['-e', `process.stdout.write('ready'); setInterval(()=>{},1000);`], options);
    foregroundChild.stdout.once('data', ready);
    return foregroundChild;
  } });
  const handle = await f.start();
  const pending = f.adapter.progress();
  await started;
  const closing = f.adapter.close();
  assert.equal((await pending).status, 'cancelled');
  await closing;
  assert.equal(foregroundChild.signalCode, 'SIGTERM');
  assert.equal(f.children[0].exitCode, 0);
  assert.equal(f.children.length, 1);
  assert.equal((await handle.done).status, 'stopped');
});

test('a forced foreground termination remains a rejected idempotent close', async t => {
  const f = await setup(t, { process: fakeProcess(async () => ({ signal: 'SIGKILL' })) });
  assert.equal((await f.adapter.progress()).status, 'failed');
  const closing = f.adapter.close();
  assert.equal(f.adapter.close(), closing);
  await assert.rejects(closing, { code: 'foreground_cleanup_unconfirmed' });
});

test('maintenance drains many valid records without a lifetime output limit or retained history', async t => {
  const f = await maintenanceFixture(t, { worker: `for(let i=0;i<12000;i++)process.stdout.write(process.argv[1]+'\\n');` });
  const handle = await f.start();
  // Count actual pipe bytes without retaining them; wait for all 12,001 records.
  const child = f.children[0];
  const expectedBytes = (Buffer.byteLength(JSON.stringify(checkpoint())) + 1) * 12001;
  await new Promise((resolve, reject) => {
    const deadline = setTimeout(() => { child.stdout.off('data', check); reject(new Error('bounded pipe drain deadline')); }, 2000);
    const check = () => {
      if (child.receivedBytes >= expectedBytes) { clearTimeout(deadline); child.stdout.off('data', check); resolve(); }
    };
    child.stdout.on('data', check); check();
  });
  assert.ok(child.receivedBytes > 2 * 1024 ** 2);
  assert.equal((await handle.status()).owned_process_running, true);
  assert.equal((await handle.stop()).status, 'stopped');
});

test('malformed and oversized background records fail closed without exporting raw output', async t => {
  for (const [body, code] of [[`process.stdout.write('PRIVATE-INVALID\\n');`, 'invalid_maintenance_report'],
    [`process.stdout.write('x'.repeat(32769));`, 'report_too_large']]) {
    const f = await maintenanceFixture(t, { worker: `setTimeout(()=>{${body}},20);`, failedClose: true });
    const handle = await f.start();
    const result = await handle.done;
    assert.equal(result.status, 'failed');
    assert.equal(result.code, code);
    assert.equal(result.local_process_joined, true);
    assert.ok(!JSON.stringify(result).includes('PRIVATE-INVALID'));
    assert.equal(f.children[0].exitCode, 0);
  }
});
