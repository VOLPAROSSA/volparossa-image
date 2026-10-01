// SPDX-License-Identifier: GPL-3.0-only
// These are filesystem/process/CLI-contract tests, NOT a core or peer storage proof.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { CoreStorage } from '../src/core-storage.mjs';

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
