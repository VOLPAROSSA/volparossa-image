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

// Diagnostic fixtures originate from the retained f51b8ace0352377c7068a93fc8f4544f18e52978
// contract suite. Only explicit v7-v10 selectors authorize their projection here.
function diagnostic(overrides = {}) {
  return { version: 1, failures: [{ fragment_index: 0, copy_index: 1, operation: 'append',
    stage: 'wire_receipt', category: 'io', agent_code: null }], omitted_failures: 0, ...overrides };
}

function diagnosticV2(detail = null, changes = {}) {
  return { ...diagnostic(), version: 2, failures: [{ ...diagnostic().failures[0],
    operation: 'reserve', stage: 'agent_ready', category: 'agent_rejected',
    agent_code: 'CONTENT_UNAVAILABLE', agent_detail: detail, ...changes }] };
}

function diagnosticV3(detail = null, changes = {}) {
  return { ...diagnosticV2(detail, changes), version: 3 };
}

function diagnosticV4(outcome = null, changes = {}) {
  return { ...diagnostic(), version: 4, failures: [{ ...diagnostic().failures[0],
    agent_detail: null, agent_outcome: outcome, ...changes }] };
}

function diagnosticV5(detail = null, changes = {}) {
  return { ...diagnosticV4(null, { ...diagnosticV2(detail).failures[0], ...changes }), version: 5 };
}

function diagnosticV6(detail = null, changes = {}) {
  return { ...diagnosticV5(detail, changes), version: 6 };
}

const CHALLENGE_PHASES = ['selector_write_flush', 'grant_write_flush', 'challenge_read_verify'];
const ELAPSED_BUCKETS = ['under_1s', '1_to_5s', '5_to_15s', '15_to_30s',
  '30_to_60s', '60_to_90s', '90_to_120s', 'at_least_120s'];

function diagnosticV7(append_timing = null, phase = 'remote_receipt_read', changes = {}) {
  return { ...diagnosticV4({ status: 'observed', detail: { phase, category: 'io', deadline_scope: 'none' },
    append_timing }, changes), version: 7 };
}

const FLOW_PAIRS = {
  source_port: ['entropy'],
  retirement_drain: ['unconfirmed', 'io', 'helper_kernel', 'helper_capacity', 'helper_unavailable',
    'helper_cleanup_incomplete', 'helper_other_rejection', 'helper_timeout', 'helper_io',
    'helper_validation', 'helper_authority', 'helper_correlation', 'helper_runtime_changed'],
  material: ['metadata', 'topology'],
  slot_reservation: ['unconfirmed', 'local_capacity', 'local_unavailable'],
  helper_acquire: ['helper_kernel', 'helper_capacity', 'helper_unavailable', 'helper_not_found',
    'helper_cleanup_incomplete', 'helper_other_rejection', 'helper_timeout', 'helper_io',
    'helper_validation', 'helper_authority', 'helper_correlation', 'helper_runtime_changed'],
  descriptor_clone: ['io'], descriptor_adoption: ['metadata', 'io'], flow_metadata: ['metadata'],
};
function flowDetail(stage = 'helper_acquire', reason = 'helper_capacity', rounds = 1) {
  return { rounds, first: { stage, reason }, last: { stage, reason } };
}
function diagnosticV8(flow_acquire = null, changes = {}) {
  return { ...diagnosticV6({ stage: 'stream_open', deadline_scope: 'none', tls_failure: null,
    stream_failure: 'flow_acquire', challenge: null, flow_acquire }, changes), version: 8 };
}

function diagnosticV9(tls_close_failure = null) {
  return { ...diagnosticV4({ status: 'observed', detail: { phase: 'transport_tls_close',
    category: 'unavailable', deadline_scope: 'none' }, append_timing: null, tls_close_failure },
  { operation: 'reserve' }), version: 9 };
}

const OUTCOME_PHASES = ['ready_write', 'local_request_read', 'local_request_verify', 'local_payload_read',
  'local_payload_verify', 'admission', 'remote_request_verify', 'remote_request_write', 'remote_payload_write',
  'remote_receipt_read', 'remote_receipt_verify', 'remote_payload_read', 'remote_payload_verify',
  'local_receipt_write', 'local_payload_write', 'provider_tls_close', 'transport_tls_close', 'final_route_check',
  'final_grant_check', 'final_lifetime_check', 'terminal_write'];

function diagnosticV10(read = { step: 'body_read', returned_outcome: null }) {
  return { ...diagnosticV6({ stage: 'challenge', deadline_scope: 'operation', tls_failure: null,
    stream_failure: null, flow_acquire: null, challenge: { phase: 'challenge_read_verify',
      before_challenge: '1_to_5s', in_challenge: '90_to_120s', read } },
  { fragment_index: 2, copy_index: 1, operation: 'append', stage: 'agent_ready',
    category: 'agent_rejected', agent_code: 'CONTENT_UNAVAILABLE' }), version: 10 };
}

test('v9 strict opt-in selects exactly one deposit flag and leaves other operations unchanged', async t => {
  const fixture = await setup(t, { configChanges: { tlsCloseDiagnosticsV9: true },
    process: fakeProcess(async operation => ({ raw: { ...coreReport(operation),
      ...(operation === 'deposit' ? { deposit_diagnostics: { version: 9, failures: [], omitted_failures: 0 } } : {}) } })) });
  assert.equal((await fixture.adapter.deposit({ input: fixture.input, alreadyEncrypted: true })).status, 'complete');
  assert.deepEqual(fixture.calls[0].args.slice(0, 8), ['--control-socket', fixture.config.controlSocket,
    'storage', 'fragments', 'deposit', '--state', fixture.config.stateDirectory, '--tls-close-diagnostics-v9']);
  assert.equal(fixture.calls[0].args.filter(value => value === '--tls-close-diagnostics-v9').length, 1);
  for (const flag of ['--append-diagnostics-v7', '--flow-acquire-diagnostics-v8']) {
    assert.equal(fixture.calls[0].args.includes(flag), false);
  }
  for (const method of ['status', 'progress', 'delete']) {
    await fixture.adapter[method]();
    assert.equal(fixture.calls.at(-1).args.some(value => value.endsWith('-diagnostics-v9')), false);
  }
  for (const value of [null, 'true', 1, 0, [], {}]) {
    await writeFile(fixture.configPath, JSON.stringify({ ...fixture.config, tlsCloseDiagnosticsV9: value }));
    await assert.rejects(CoreStorage.open(fixture.configPath), { code: 'invalid_configuration' });
  }
  for (const other of ['appendDiagnosticsV7', 'flowAcquireDiagnosticsV8']) {
    await writeFile(fixture.configPath, JSON.stringify({ ...fixture.config, [other]: true }));
    await assert.rejects(CoreStorage.open(fixture.configPath), { code: 'invalid_configuration' });
  }
});

test('v9 keeps all four closed TLS-close reasons without changing result, accounting or custody', async t => {
  let current = diagnosticV9();
  const fixture = await setup(t, { configChanges: { tlsCloseDiagnosticsV9: true }, process: fakeProcess(async () => ({
    raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: current }, code: 1,
  })) });
  const request = { input: fixture.input, alreadyEncrypted: true };
  const baseline = await fixture.adapter.deposit(request);
  for (const reason of [null, 'shutdown_io', 'read_io', 'trailing_data', 'internal_deadline']) {
    current = diagnosticV9(reason);
    const result = await fixture.adapter.deposit(request);
    assert.equal(result.status, 'incomplete');
    assert.equal(result.code, 'retained_operation_incomplete');
    assert.deepEqual(result.storage.deposit_diagnostics, current);
    assert.equal(JSON.stringify(result.storage.deposit_diagnostics), JSON.stringify(current));
    assert.ok(Object.isFrozen(result.storage.deposit_diagnostics.failures[0].agent_outcome));
    assert.deepEqual({ ...result, storage: baseline.storage }, baseline);
    const { deposit_diagnostics, ...accounting } = result.storage;
    const { deposit_diagnostics: ignored, ...expectedAccounting } = baseline.storage;
    assert.deepEqual(accounting, expectedAccounting);
    assert.equal(result.local_process_joined, true);
    assert.equal(result.remote_cleanup_confirmed, false);
    assert.deepEqual(await readFile(fixture.input), CONTENT);
    for (const secret of [fixture.root, ...KEYS]) assert.ok(!JSON.stringify(result).includes(secret));
  }
});

test('v9 nullable outcomes remain unknown and do not invent a TLS-close failure', async t => {
  let current;
  const fixture = await setup(t, { configChanges: { tlsCloseDiagnosticsV9: true }, process: fakeProcess(async () => ({
    raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: current }, code: 1,
  })) });
  const outcomes = [null, ...['missing', 'pending', 'expired', 'query_failed', 'query_timeout'].map(status => ({
    status, detail: null, append_timing: null, tls_close_failure: null,
  })), { status: 'observed', detail: { phase: 'provider_tls_close', category: 'io', deadline_scope: 'none' },
    append_timing: null, tls_close_failure: null }];
  for (const outcome of outcomes) {
    current = diagnosticV9(); current.failures[0].agent_outcome = outcome;
    const result = await fixture.adapter.deposit({ input: fixture.input, alreadyEncrypted: true });
    assert.deepEqual(result.storage.deposit_diagnostics, current);
  }
});

test('v9 rejects missing, private, unknown and wrongly scoped close outcomes and schema downgrade', async t => {
  let current;
  const fixture = await setup(t, { configChanges: { tlsCloseDiagnosticsV9: true }, process: fakeProcess(async () => ({
    raw: { ...coreReport('deposit', 'uncertain', false), ...(current === undefined ? {} : { deposit_diagnostics: current }) }, code: 1,
  })) });
  const invalid = [undefined, diagnostic(), diagnosticV7(), diagnosticV8()];
  for (const reason of ['PRIVATE-CLOSE-CANARY', 'unspecified', '', true, 1, {}, []]) invalid.push(diagnosticV9(reason));
  for (const field of ['tls_close_failure', 'append_timing']) {
    const value = diagnosticV9(); delete value.failures[0].agent_outcome[field]; invalid.push(value);
  }
  for (const [field, value] of [['phase', 'provider_tls_close'], ['phase', 'remote_receipt_read'],
    ['category', 'io'], ['category', 'cancelled'], ['category', 'timeout'], ['deadline_scope', 'operation']]) {
    const bad = diagnosticV9('shutdown_io'); bad.failures[0].agent_outcome.detail[field] = value; invalid.push(bad);
  }
  for (const status of ['missing', 'pending', 'expired', 'query_failed', 'query_timeout']) {
    const bad = diagnosticV9('shutdown_io'); Object.assign(bad.failures[0].agent_outcome, { status, detail: null }); invalid.push(bad);
  }
  const raw = diagnosticV9(); raw.failures[0].agent_outcome.raw = 'PRIVATE-CLOSE-CANARY'; invalid.push(raw);
  const timing = diagnosticV9('read_io'); timing.failures[0].agent_outcome.append_timing = {
    before_payload: 'under_1s', in_payload_write_flush: 'under_1s', in_receipt_read: 'under_1s',
  }; invalid.push(timing);
  for (const version of [0, 8, 10, '9', true]) invalid.push({ ...diagnosticV9(), version });
  for (current of invalid) {
    const result = await fixture.adapter.deposit({ input: fixture.input, alreadyEncrypted: true });
    assert.equal(result.code, 'invalid_core_report', JSON.stringify(current));
    assert.equal(result.storage, null);
    assert.equal(result.local_process_joined, true);
    assert.equal(result.remote_cleanup_confirmed, false);
    assert.ok(!JSON.stringify(result).includes('PRIVATE-CLOSE-CANARY'));
  }
});

test('v9 preserves all 35 flow pairs and APPEND timing constraints', async t => {
  let current;
  const fixture = await setup(t, { configChanges: { tlsCloseDiagnosticsV9: true }, process: fakeProcess(async () => ({
    raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: current }, code: 1,
  })) });
  const request = { input: fixture.input, alreadyEncrypted: true };
  let count = 0;
  for (const [stage, reasons] of Object.entries(FLOW_PAIRS)) for (const reason of reasons) {
    count++;
    current = { ...diagnosticV8(flowDetail(stage, reason, 8)), version: 9 };
    assert.deepEqual((await fixture.adapter.deposit(request)).storage.deposit_diagnostics, current);
  }
  assert.equal(count, 35);
  const timing = { before_payload: 'under_1s', in_payload_write_flush: '1_to_5s', in_receipt_read: '90_to_120s' };
  current = { ...diagnosticV7(timing), version: 9 };
  current.failures[0].agent_outcome.tls_close_failure = null;
  assert.deepEqual((await fixture.adapter.deposit(request)).storage.deposit_diagnostics, current);
  const invalidTiming = structuredClone(current); invalidTiming.failures[0].agent_outcome.append_timing.in_receipt_read = 'PRIVATE-CLOSE-CANARY';
  const invalid = [invalidTiming, { ...diagnosticV8(flowDetail('retirement_drain', 'helper_not_found')), version: 9 },
    { ...diagnosticV8({ ...flowDetail(), last: { stage: 'source_port', reason: 'entropy' } }), version: 9 }];
  for (const rounds of [0, 9, true, '1']) invalid.push({ ...diagnosticV8({ ...flowDetail(), rounds }), version: 9 });
  const missingFlow = { ...diagnosticV8(), version: 9 }; delete missingFlow.failures[0].agent_detail.flow_acquire; invalid.push(missingFlow);
  for (current of invalid) assert.equal((await fixture.adapter.deposit(request)).code, 'invalid_core_report');
});

test('v8 is a mutually exclusive boolean opt-in on the actual deposit argv only', async t => {
  const fixture = await setup(t, { configChanges: { flowAcquireDiagnosticsV8: true },
    process: fakeProcess(async operation => ({ raw: { ...coreReport(operation),
      ...(operation === 'deposit' ? { deposit_diagnostics: { version: 8, failures: [], omitted_failures: 0 } } : {}) } })) });
  assert.equal((await fixture.adapter.deposit({ input: fixture.input, alreadyEncrypted: true })).status, 'complete');
  assert.deepEqual(fixture.calls[0].args.slice(0, 8), ['--control-socket', fixture.config.controlSocket,
    'storage', 'fragments', 'deposit', '--state', fixture.config.stateDirectory, '--flow-acquire-diagnostics-v8']);
  assert.equal(fixture.calls[0].args.filter(value => value === '--flow-acquire-diagnostics-v8').length, 1);
  assert.equal(fixture.calls[0].args.includes('--append-diagnostics-v7'), false);
  for (const method of ['status', 'progress', 'delete']) {
    await fixture.adapter[method]();
    for (const flag of ['--append-diagnostics-v7', '--flow-acquire-diagnostics-v8']) {
      assert.equal(fixture.calls.at(-1).args.includes(flag), false);
    }
  }
  for (const value of [null, 'true', 1, 0, [], {}]) {
    await writeFile(fixture.configPath, JSON.stringify({ ...fixture.config, flowAcquireDiagnosticsV8: value }));
    await assert.rejects(CoreStorage.open(fixture.configPath), { code: 'invalid_configuration' });
  }
  await writeFile(fixture.configPath, JSON.stringify({ ...fixture.config, appendDiagnosticsV7: true }));
  await assert.rejects(CoreStorage.open(fixture.configPath), { code: 'invalid_configuration' });
});

test('v8 retains exactly 35 local flow pairs and bounded rounds without changing custody or input', async t => {
  let current = diagnosticV8();
  const fixture = await setup(t, { configChanges: { flowAcquireDiagnosticsV8: true }, process: fakeProcess(async () => ({
    raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: current }, code: 1,
  })) });
  const request = { input: fixture.input, alreadyEncrypted: true };
  const baseline = await fixture.adapter.deposit(request);
  const journal = join(fixture.config.stateDirectory, 'owner-state');
  await writeFile(journal, 'PRIVATE-FLOW-CANARY', { mode: 0o600 });
  const cases = [null, { rounds: 8, first: { stage: 'helper_acquire', reason: 'helper_capacity' },
    last: { stage: 'slot_reservation', reason: 'local_capacity' } }];
  let pairs = 0;
  for (const [stage, reasons] of Object.entries(FLOW_PAIRS)) for (const reason of reasons) {
    pairs++;
    for (let rounds = 1; rounds <= 8; rounds++) cases.push(flowDetail(stage, reason, rounds));
  }
  assert.equal(pairs, 35);
  for (const flow of cases) {
    current = diagnosticV8(flow);
    const before = JSON.stringify(current);
    const result = await fixture.adapter.deposit(request);
    assert.equal(JSON.stringify(result.storage.deposit_diagnostics), before);
    assert.equal(JSON.stringify(current), before);
    assert.deepEqual({ ...result, storage: baseline.storage }, baseline);
    const { deposit_diagnostics, ...accounting } = result.storage;
    const { deposit_diagnostics: ignored, ...oldAccounting } = baseline.storage;
    assert.deepEqual(accounting, oldAccounting);
    const observed = deposit_diagnostics.failures[0].agent_detail.flow_acquire;
    if (observed) assert.ok(Object.isFrozen(observed) && Object.isFrozen(observed.first) && Object.isFrozen(observed.last));
    for (const canary of [fixture.root, ...KEYS, 'PRIVATE-FLOW-CANARY']) assert.ok(!JSON.stringify(result).includes(canary));
    assert.equal(result.remote_cleanup_confirmed, false);
    assert.deepEqual(fixture.calls.at(-1).args, fixture.calls[0].args);
  }
  assert.equal(await readFile(journal, 'utf8'), 'PRIVATE-FLOW-CANARY');
  assert.deepEqual(await readFile(fixture.input), CONTENT);
});

test('v8 rejects every unreachable flow pair and malformed or private observation', async t => {
  let current;
  const fixture = await setup(t, { configChanges: { flowAcquireDiagnosticsV8: true }, process: fakeProcess(async () => ({
    raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: current }, code: 1,
  })) });
  const reasons = [...new Set(Object.values(FLOW_PAIRS).flat()), 'unobserved', 'PRIVATE-FLOW-CANARY'];
  const invalid = [];
  for (const stage of [...Object.keys(FLOW_PAIRS), 'unobserved', 'PRIVATE-FLOW-CANARY']) for (const reason of reasons) {
    if (FLOW_PAIRS[stage]?.includes(reason)) continue;
    for (const endpoint of ['first', 'last']) {
      const flow = flowDetail('helper_acquire', 'helper_capacity', 2);
      flow[endpoint] = { stage, reason }; invalid.push(diagnosticV8(flow));
    }
  }
  for (const rounds of [0, 9, -1, true, 1.5, null, '1', Number.MAX_SAFE_INTEGER + 1]) {
    invalid.push(diagnosticV8({ ...flowDetail(), rounds }));
  }
  invalid.push(diagnosticV8({ ...flowDetail(), last: { stage: 'source_port', reason: 'entropy' } }));
  for (const value of ['PRIVATE-FLOW-CANARY', false, 1, [], {}]) invalid.push(diagnosticV8(value));
  for (const field of ['rounds', 'first', 'last']) {
    const flow = flowDetail(); delete flow[field]; invalid.push(diagnosticV8(flow));
  }
  for (const endpoint of ['first', 'last']) {
    for (const value of [null, 'PRIVATE-FLOW-CANARY', false, 1, [], {}]) {
      invalid.push(diagnosticV8({ ...flowDetail(), [endpoint]: value }));
    }
    for (const field of ['stage', 'reason']) {
      const flow = flowDetail(); delete flow[endpoint][field]; invalid.push(diagnosticV8(flow));
    }
    const flow = flowDetail(); flow[endpoint].raw = 'PRIVATE-FLOW-CANARY'; invalid.push(diagnosticV8(flow));
  }
  invalid.push(diagnosticV8({ ...flowDetail(), elapsed_ms: 10 }));
  const missing = diagnosticV8(); delete missing.failures[0].agent_detail.flow_acquire; invalid.push(missing);
  for (current of invalid) {
    const result = await fixture.adapter.deposit({ input: fixture.input, alreadyEncrypted: true });
    assert.equal(result.code, 'invalid_core_report', JSON.stringify(current));
    assert.equal(result.storage, null);
    assert.equal(result.local_process_joined, true);
    assert.equal(result.remote_cleanup_confirmed, false);
    assert.ok(!JSON.stringify(result).includes('PRIVATE-FLOW-CANARY'));
  }
});

test('v8 flow detail belongs only to the original unavailable pre-READY flow failure', async t => {
  let current;
  const fixture = await setup(t, { configChanges: { flowAcquireDiagnosticsV8: true }, process: fakeProcess(async () => ({
    raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: current }, code: 1,
  })) });
  const invalid = [];
  for (const [field, values] of Object.entries({ stage: ['wire_receipt', 'agent_terminal', 'unknown'],
    category: ['io', 'timeout', 'unknown'], agent_code: [null, 'unknown', 'CONTENT_BUSY', 'CONTENT_INVALID', 'CONTENT_POLICY'] })) {
    for (const value of values) invalid.push(diagnosticV8(flowDetail(), { [field]: value }));
  }
  for (const [field, values] of Object.entries({ stage: ['provider_lookup', 'tls_handshake', 'challenge'],
    deadline_scope: ['operation', 'exchange'], stream_failure: [null, 'policy', 'transport_tls'],
    tls_failure: ['io'], challenge: [{ phase: 'challenge_read_verify', before_challenge: 'under_1s', in_challenge: '1_to_5s' }] })) {
    for (const value of values) {
      const raw = diagnosticV8(flowDetail()); raw.failures[0].agent_detail[field] = value; invalid.push(raw);
    }
  }
  for (current of invalid) {
    const result = await fixture.adapter.deposit({ input: fixture.input, alreadyEncrypted: true });
    assert.equal(result.code, 'invalid_core_report', JSON.stringify(current));
    assert.equal(result.storage, null);
  }
});

test('v8 preserves the eight-failure and charged-copy bounds', async t => {
  let current;
  const fixture = await setup(t, { configChanges: { flowAcquireDiagnosticsV8: true }, process: fakeProcess(async () => ({
    raw: { ...repairedReport('deposit', 'pending', 6), deposit_diagnostics: current }, code: 1,
  })) });
  const failure = diagnosticV8(flowDetail()).failures[0];
  const valid = { version: 8, failures: Array.from({ length: 8 }, (_, copy_index) => ({ ...failure, copy_index })), omitted_failures: 4 };
  current = valid;
  assert.deepEqual((await fixture.adapter.deposit({ input: fixture.input, alreadyEncrypted: true })).storage.deposit_diagnostics, valid);
  for (current of [{ ...valid, omitted_failures: 5 }, { ...valid, omitted_failures: 2049 },
    { ...valid, failures: [...valid.failures, valid.failures[0]] },
    { ...valid, failures: valid.failures.slice(1) }, { ...valid, failures: [failure, failure], omitted_failures: 0 }]) {
    assert.equal((await fixture.adapter.deposit({ input: fixture.input, alreadyEncrypted: true })).code, 'invalid_core_report');
  }
});

test('v7 is a strict boolean opt-in and selects only the actual fragment deposit command', async t => {
  const fixture = await setup(t, { configChanges: { appendDiagnosticsV7: true },
    process: fakeProcess(async operation => ({ raw: { ...coreReport(operation),
      ...(operation === 'deposit' ? { deposit_diagnostics: { version: 7, failures: [], omitted_failures: 0 } } : {}) } })) });
  assert.equal((await fixture.adapter.deposit({ input: fixture.input, alreadyEncrypted: true })).status, 'complete');
  const args = fixture.calls[0].args;
  assert.deepEqual(args.slice(0, 8), ['--control-socket', fixture.config.controlSocket,
    'storage', 'fragments', 'deposit', '--state', fixture.config.stateDirectory, '--append-diagnostics-v7']);
  assert.equal(args.filter(value => value === '--append-diagnostics-v7').length, 1);
  for (const method of ['status', 'progress', 'delete']) {
    await fixture.adapter[method]();
    assert.equal(fixture.calls.at(-1).args.includes('--append-diagnostics-v7'), false);
  }
  for (const value of [null, 'true', 1, 0, [], {}]) {
    await writeFile(fixture.configPath, JSON.stringify({ ...fixture.config, appendDiagnosticsV7: value }));
    await assert.rejects(CoreStorage.open(fixture.configPath), { code: 'invalid_configuration' });
  }
});

test('v7 preserves finite APPEND timing, all nullable outcomes, custody and immutable input', async t => {
  let current = diagnosticV7();
  const fixture = await setup(t, { configChanges: { appendDiagnosticsV7: true }, process: fakeProcess(async () => ({
    raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: current }, code: 1,
  })) });
  const request = { input: fixture.input, alreadyEncrypted: true };
  const journal = join(fixture.config.stateDirectory, 'owner-state');
  await writeFile(journal, 'PRIVATE-APPEND-CANARY', { mode: 0o600 });
  const baseline = await fixture.adapter.deposit(request);
  const cases = [diagnosticV7(null, 'remote_receipt_read', { agent_outcome: null }),
    ...['missing', 'pending', 'expired', 'query_failed', 'query_timeout'].map(status =>
      diagnosticV7(null, 'remote_receipt_read', { agent_outcome: { status, detail: null, append_timing: null } })),
    ...OUTCOME_PHASES.map(phase => diagnosticV7(null, phase)),
    diagnosticV7(null, 'remote_receipt_read', { operation: 'finalize' })];
  for (const before_payload of ELAPSED_BUCKETS) for (const in_payload_write_flush of ELAPSED_BUCKETS) {
    const timing = { before_payload, in_payload_write_flush, in_receipt_read: null };
    cases.push(diagnosticV7(timing, 'remote_payload_write'));
    for (const in_receipt_read of ELAPSED_BUCKETS) cases.push(diagnosticV7({ ...timing, in_receipt_read }));
  }
  for (current of cases) {
    const result = await fixture.adapter.deposit(request);
    assert.equal(JSON.stringify(result.storage.deposit_diagnostics), JSON.stringify(current));
    assert.deepEqual({ ...result, storage: baseline.storage }, baseline);
    const { deposit_diagnostics, ...accounting } = result.storage;
    const { deposit_diagnostics: ignored, ...expectedAccounting } = baseline.storage;
    assert.deepEqual(accounting, expectedAccounting);
    const timing = deposit_diagnostics.failures[0].agent_outcome?.append_timing;
    if (timing) assert.ok(Object.isFrozen(timing));
    assert.deepEqual(fixture.calls.at(-1).args, fixture.calls[0].args);
    for (const secret of [fixture.root, ...KEYS, 'PRIVATE-APPEND-CANARY']) assert.ok(!JSON.stringify(result).includes(secret));
  }
  assert.equal(await readFile(journal, 'utf8'), 'PRIVATE-APPEND-CANARY');
  assert.deepEqual(await readFile(fixture.input), CONTENT);
});

test('v7 rejects missing keys, invented timing, wrong phase or operation and nonobserved timing', async t => {
  let current;
  const fixture = await setup(t, { configChanges: { appendDiagnosticsV7: true }, process: fakeProcess(async () => ({
    raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: current }, code: 1,
  })) });
  const timing = { before_payload: 'under_1s', in_payload_write_flush: '1_to_5s', in_receipt_read: '90_to_120s' };
  const invalid = [diagnosticV7({ ...timing, phase: 'remote_receipt_read' }),
    diagnosticV7({ ...timing, elapsed_ms: 120000 }), diagnosticV7(timing, 'remote_payload_write'),
    diagnosticV7({ ...timing, in_receipt_read: null }),
    ...['reserve', 'finalize'].map(operation => diagnosticV7(timing, 'remote_receipt_read', { operation })),
    ...OUTCOME_PHASES.filter(phase => !['remote_payload_write', 'remote_receipt_read'].includes(phase))
      .map(phase => diagnosticV7(timing, phase)),
    ...['missing', 'pending', 'expired', 'query_failed', 'query_timeout'].map(status =>
      diagnosticV7(null, 'remote_receipt_read', { agent_outcome: { status, detail: null, append_timing: timing } }))];
  for (const field of Object.keys(timing)) {
    const missing = { ...timing }; delete missing[field]; invalid.push(diagnosticV7(missing));
    for (const value of [null, 'PRIVATE-APPEND-CANARY', '', false, 1, [], {}]) {
      invalid.push(diagnosticV7({ ...timing, [field]: value }));
    }
  }
  for (const value of ['PRIVATE-APPEND-CANARY', false, 1, [], {}]) invalid.push(diagnosticV7(value));
  for (const field of ['status', 'detail', 'append_timing']) {
    const missing = diagnosticV7(); delete missing.failures[0].agent_outcome[field]; invalid.push(missing);
  }
  const leaking = diagnosticV7(); leaking.failures[0].agent_outcome.raw = 'PRIVATE-APPEND-CANARY'; invalid.push(leaking);
  for (current of invalid) {
    const result = await fixture.adapter.deposit({ input: fixture.input, alreadyEncrypted: true });
    assert.equal(result.code, 'invalid_core_report', JSON.stringify(current));
    assert.equal(result.storage, null);
    assert.equal(result.local_process_joined, true);
    assert.equal(result.remote_cleanup_confirmed, false);
    assert.ok(!JSON.stringify(result).includes('PRIVATE-APPEND-CANARY'));
  }
});

test('v10 explicitly selects one deposit flag and preserves other operations and explicit v9', async t => {
  const f = await setup(t, { configChanges: { challengeReadDiagnosticsV10: true }, process: fakeProcess(async operation => ({
    raw: { ...coreReport(operation), ...(operation === 'deposit' ? { deposit_diagnostics: { version: 10, failures: [], omitted_failures: 0 } } : {}) },
  })) });
  assert.equal((await f.adapter.deposit({ input: f.input, alreadyEncrypted: true })).status, 'complete');
  assert.equal(f.calls[0].args.filter(value => value === '--challenge-read-diagnostics-v10').length, 1);
  assert.equal(f.calls[0].args[7], '--challenge-read-diagnostics-v10');
  await f.adapter.status(); await f.adapter.progress(); await f.adapter.delete();
  for (const call of f.calls.slice(1)) assert.ok(!call.args.includes('--challenge-read-diagnostics-v10'));
  for (const configChanges of [{ tlsCloseDiagnosticsV9: true }, { tlsCloseDiagnosticsV9: true, challengeReadDiagnosticsV10: false }]) {
    const old = await setup(t, { configChanges, process: fakeProcess(async () => ({
      raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: diagnosticV9() }, code: 1,
    })) });
    assert.equal((await old.adapter.deposit({ input: old.input, alreadyEncrypted: true })).storage.deposit_diagnostics.version, 9);
    assert.ok(!old.calls[0].args.includes('--challenge-read-diagnostics-v10'));
  }
});

test('v10 finite challenge reads retain exact attempt, buckets, null meaning and closed privacy projection', async t => {
  let current = diagnosticV10();
  const f = await setup(t, { configChanges: { challengeReadDiagnosticsV10: true }, process: fakeProcess(async () => ({
    raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: current }, code: 1,
  })) });
  const allowed = { length_read: [null, 'io_eof', 'io_other', 'invalid', 'wire_timeout'],
    body_read: [null, 'io_eof', 'io_other', 'wire_timeout'], verification: [null, 'invalid', 'verification_rejected'] };
  for (const step of Object.keys(allowed)) for (const returned_outcome of [null, 'io_eof', 'io_other', 'invalid', 'verification_rejected', 'wire_timeout']) {
    current = diagnosticV10({ step, returned_outcome });
    const result = await f.adapter.deposit({ input: f.input, alreadyEncrypted: true });
    if (allowed[step].includes(returned_outcome)) {
      assert.deepEqual(result.storage.deposit_diagnostics, current);
      assert.equal(result.status, 'incomplete'); assert.equal(result.local_process_joined, true);
      assert.equal(result.remote_cleanup_confirmed, false);
      assert.ok(Object.isFrozen(result.storage.deposit_diagnostics.failures[0].agent_detail.challenge.read));
    } else { assert.equal(result.code, 'invalid_core_report'); assert.equal(result.storage, null); }
    assert.deepEqual(await readFile(f.input), CONTENT);
    for (const canary of [f.root, ...KEYS]) assert.ok(!JSON.stringify(result).includes(canary));
  }
  for (const diagnostics of [diagnosticV10(null), { ...diagnosticV9('read_io'), version: 10 }]) {
    current = diagnostics;
    assert.deepEqual((await f.adapter.deposit({ input: f.input, alreadyEncrypted: true })).storage.deposit_diagnostics, diagnostics);
  }
});

test('v10 rejects mixed selectors, malformed read fields, wrong phase, unsolicited and downgraded reports', async t => {
  for (const value of [null, 0, 1, 'true', {}, []]) {
    await assert.rejects(setup(t, { configChanges: { challengeReadDiagnosticsV10: value } }), { code: 'invalid_configuration' });
  }
  for (const other of ['appendDiagnosticsV7', 'flowAcquireDiagnosticsV8', 'tlsCloseDiagnosticsV9']) {
    await assert.rejects(setup(t, { configChanges: { challengeReadDiagnosticsV10: true, [other]: true } }), { code: 'invalid_configuration' });
  }
  const invalid = [diagnosticV9(), diagnosticV10({ step: 'PRIVATE-READ-CANARY', returned_outcome: null }),
    diagnosticV10({ step: 'body_read' }), diagnosticV10({ step: 'body_read', returned_outcome: false }),
    diagnosticV10({ step: 'body_read', returned_outcome: null, raw: 'PRIVATE-READ-CANARY' })];
  const phase = diagnosticV10(); phase.failures[0].agent_detail.challenge.phase = 'grant_write_flush'; invalid.push(phase);
  const missing = diagnosticV10(); delete missing.failures[0].agent_detail.challenge.read; invalid.push(missing);
  for (const current of invalid) {
    const f = await setup(t, { configChanges: { challengeReadDiagnosticsV10: true }, process: fakeProcess(async () => ({
      raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: current }, code: 1,
    })) });
    const result = await f.adapter.deposit({ input: f.input, alreadyEncrypted: true });
    assert.equal(result.code, 'invalid_core_report'); assert.equal(result.storage, null);
    assert.ok(!JSON.stringify(result).includes('PRIVATE-READ-CANARY'));
  }
  const unsolicited = await setup(t, { configChanges: { tlsCloseDiagnosticsV9: true }, process: fakeProcess(async () => ({
    raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: diagnosticV10() }, code: 1,
  })) });
  assert.equal((await unsolicited.adapter.deposit({ input: unsolicited.input, alreadyEncrypted: true })).code, 'invalid_core_report');
});

const SELECTORS = [
  ['appendDiagnosticsV7', '--append-diagnostics-v7', 7],
  ['flowAcquireDiagnosticsV8', '--flow-acquire-diagnostics-v8', 8],
  ['tlsCloseDiagnosticsV9', '--tls-close-diagnostics-v9', 9],
  ['challengeReadDiagnosticsV10', '--challenge-read-diagnostics-v10', 10],
];

async function originalMainAdapter(fixture) {
  // Exact readable e817b48067108e0faaab7e2067a258bc07a4b045 source, not a
  // reconstructed expectation or a network/history dependency of the test.
  const path = new URL('./fixtures/core-storage-default-e817b480.mjs', import.meta.url);
  const bytes = await readFile(path);
  assert.equal(bytes.length, 20915);
  assert.equal(createHash('sha256').update(bytes).digest('hex'),
    'd274c294a4f7c500aac552629997487c79e67faaa89dddd1383309d7e58273b0');
  const { CoreStorage: OriginalCoreStorage } = await import(path.href);
  const originalConfig = { ...fixture.config };
  for (const [key] of SELECTORS) delete originalConfig[key];
  await writeFile(fixture.configPath, JSON.stringify(originalConfig));
  try { return await OriginalCoreStorage.open(fixture.configPath, { spawnProcess: fixture.spawnProcess }); }
  finally { await writeFile(fixture.configPath, JSON.stringify(fixture.config)); }
}
function operationRequest(operation, fixture) {
  if (operation === 'create') return { input: fixture.input, sha256: SHA, alreadyEncrypted: true };
  if (operation === 'deposit') return { input: fixture.input, alreadyEncrypted: true };
  if (operation === 'restore') return { output: join(fixture.root, 'new-restored.pgp'), sha256: SHA };
  if (operation === 'renew') return { lifetimeSeconds: 604800 };
  return {};
}

// This compares the complete result and every process argument/option against
// unchanged main. Neither adapter receives a real core, peer or private payload.
test('absent and all-false selectors exactly preserve main for every operation and unsolicited diagnostic shape', async t => {
  const modes = [{}, Object.fromEntries(SELECTORS.map(([key]) => [key, false]))];
  const diagnostics = [undefined, null, {}, 'PRIVATE-UNSOLICITED-CANARY', diagnostic(), diagnosticV7(),
    diagnosticV8(flowDetail()), diagnosticV9('read_io'), diagnosticV10(), { version: 999, failures: [] }];
  for (const configChanges of modes) for (const operation of ['create', 'deposit', 'status', 'progress', 'restore', 'renew', 'delete']) {
    let current, fault = 'valid';
    const fixture = await setup(t, { existing: operation !== 'create', configChanges,
      process: fakeProcess(async () => {
        const raw = coreReport(operation, 'uncertain', false);
        if (current !== undefined) raw.deposit_diagnostics = current;
        if (fault === 'accounting') raw.physical_payload_charge_upper_bound++;
        if (fault === 'json') return { text: 'PRIVATE-INVALID-JSON', code: 1 };
        const code = ['create', 'status'].includes(operation) ? 0 : 1;
        return { raw, code: fault === 'exit' ? 2 : code };
      }) });
    const original = await originalMainAdapter(fixture);
    const request = operationRequest(operation, fixture);
    for (current of diagnostics) for (fault of ['valid', 'accounting', 'json', 'exit']) {
      const result = await fixture.adapter[operation](request);
      const baseline = await original[operation](request);
      assert.deepEqual(result, baseline, `${operation}:${fault}`);
      assert.equal(JSON.stringify(result), JSON.stringify(baseline));
      assert.deepEqual(fixture.calls.at(-2), fixture.calls.at(-1));
      assert.ok(!fixture.calls.at(-1).args.some(value => /--.*diagnostics-v/.test(value)));
      for (const canary of [fixture.root, ...KEYS, 'PRIVATE-UNSOLICITED-CANARY', 'PRIVATE-INVALID-JSON']) {
        assert.ok(!JSON.stringify(result).includes(canary));
      }
    }
  }
});

test('each true selector is inactive for all other operations, including malformed unsolicited diagnostics', async t => {
  for (const [key] of SELECTORS) for (const operation of ['create', 'status', 'progress', 'restore', 'renew', 'delete']) {
    let current;
    const fixture = await setup(t, { existing: operation !== 'create', configChanges: { [key]: true },
      process: fakeProcess(async () => ({ raw: { ...coreReport(operation, 'uncertain', false), deposit_diagnostics: current },
        code: ['create', 'status'].includes(operation) ? 0 : 1 })) });
    const original = await originalMainAdapter(fixture);
    for (current of [undefined, diagnosticV10(), null, { raw: 'PRIVATE-NONDEPOSIT-CANARY' }]) {
      const request = operationRequest(operation, fixture);
      const result = await fixture.adapter[operation](request);
      assert.deepEqual(result, await original[operation](request));
      assert.deepEqual(fixture.calls.at(-2), fixture.calls.at(-1));
      assert.ok(!fixture.calls.at(-1).args.some(value => /--.*diagnostics-v/.test(value)));
      assert.ok(!JSON.stringify(result).includes('PRIVATE-NONDEPOSIT-CANARY'));
    }
  }
});

test('all four selectors are strict booleans, pairwise exclusive and exact-version without implicit legacy parsing', async t => {
  for (let bits = 0; bits < 16; bits++) {
    const configChanges = Object.fromEntries(SELECTORS.map(([key], index) => [key, Boolean(bits & (1 << index))]));
    if (SELECTORS.filter(([key]) => configChanges[key]).length > 1) {
      await assert.rejects(setup(t, { configChanges }), { code: 'invalid_configuration' });
    }
  }
  for (const [key, flag, version] of SELECTORS) {
    for (const value of [null, 0, 1, 'false', 'true', [], {}]) {
      await assert.rejects(setup(t, { configChanges: { [key]: value } }), { code: 'invalid_configuration' });
    }
    let current;
    const fixture = await setup(t, { configChanges: { [key]: true }, process: fakeProcess(async () => ({
      raw: { ...coreReport('deposit', 'uncertain', false), ...(current === undefined ? {} : { deposit_diagnostics: current }) }, code: 1,
    })) });
    for (const candidate of [undefined, null, ...Array.from({ length: 12 }, (_, version) => ({ version, failures: [], omitted_failures: 0 })),
      { version: String(version), failures: [], omitted_failures: 0 }, { failures: [], omitted_failures: 0 }]) {
      current = candidate;
      const result = await fixture.adapter.deposit(operationRequest('deposit', fixture));
      const accepted = candidate?.version === version;
      assert.equal(result.status, accepted ? 'incomplete' : 'failed');
      assert.equal(result.code, accepted ? 'retained_operation_incomplete' : 'invalid_core_report');
      assert.equal(fixture.calls.at(-1).args[7], flag);
      assert.equal(fixture.calls.at(-1).args.filter(value => SELECTORS.some(([, name]) => name === value)).length, 1);
      if (accepted) assert.deepEqual(result.storage.deposit_diagnostics, candidate);
      else assert.equal(result.storage, null);
    }
  }
});

function assertFrozenTree(value) {
  if (value !== null && typeof value === 'object') {
    assert.ok(Object.isFrozen(value));
    for (const child of Object.values(value)) assertFrozenTree(child);
  }
}

function inheritedDiagnostic(version, changes = {}) {
  return { version, failures: [{ ...diagnosticV7().failures[0], agent_outcome: null, ...changes }], omitted_failures: 0 };
}
function inheritedAgent(version, detail, changes = {}) {
  return inheritedDiagnostic(version, { operation: 'reserve', stage: 'agent_ready', category: 'agent_rejected',
    agent_code: 'CONTENT_UNAVAILABLE', agent_detail: detail, ...changes });
}
function agentFields(version, changes = {}) {
  return { stage: 'provider_lookup', deadline_scope: 'none', tls_failure: null, stream_failure: null,
    challenge: null, ...(version >= 8 ? { flow_acquire: null } : {}), ...changes };
}

const BASE_ENUMS = {
  operation: ['prepare', 'reserve', 'progress', 'append', 'finalize', 'renew', 'read_range', 'delete'],
  stage: ['journal_open', 'authorization', 'agent_ready', 'challenge', 'signed_request', 'wire_receipt',
    'agent_terminal', 'accounting', 'local_input', 'receipt_validation', 'journal_save', 'deadline', 'unknown'],
  category: ['io', 'timeout', 'protocol', 'agent_rejected', 'invalid', 'busy', 'store', 'unknown'],
};
const AGENT_STAGES = ['unobserved', 'route_connect', 'control_selection', 'provider_lookup', 'provider_cardinality',
  'offer_validity', 'stream_open', 'tls_handshake', 'challenge'];
const TLS_FAILURES = ['offer', 'configuration', 'handshake_deadline', 'authentication', 'tls_other', 'io'];
const STREAM_FAILURES = ['policy', 'route_state', 'route_material', 'flow_acquire', 'transport_certificate',
  'transport_tls', 'initial_paths', 'open_tcp_write', 'subflow_readiness', 'stream_attachment'];

test('selected v7-v10 inherit all closed v1-v6 enums, nullable agent details and independent challenge buckets', async t => {
  for (const [key, , version] of SELECTORS) {
    let current;
    const fixture = await setup(t, { configChanges: { [key]: true }, process: fakeProcess(async () => ({
      raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: current }, code: 1,
    })) });
    const cases = [inheritedDiagnostic(version), inheritedAgent(version, null)];
    for (const [field, values] of Object.entries(BASE_ENUMS)) for (const value of values) {
      cases.push(inheritedDiagnostic(version, { [field]: value, ...(value === 'agent_rejected' ? { agent_code: 'unknown' } : {}) }));
    }
    for (const agent_code of ['CONTENT_INVALID', 'CONTENT_UNAVAILABLE', 'CONTENT_BUSY', 'CONTENT_POLICY', 'unknown']) {
      cases.push(inheritedDiagnostic(version, { category: 'agent_rejected', agent_code }));
    }
    for (const stage of AGENT_STAGES) for (const deadline_scope of ['none', 'operation', 'exchange']) {
      if (stage === 'unobserved' && deadline_scope !== 'operation') continue;
      if (deadline_scope === 'exchange' && !['stream_open', 'tls_handshake', 'challenge'].includes(stage)) continue;
      cases.push(inheritedAgent(version, agentFields(version, { stage, deadline_scope })));
    }
    for (const tls_failure of TLS_FAILURES) cases.push(inheritedAgent(version,
      agentFields(version, { stage: 'tls_handshake', tls_failure })));
    for (const stream_failure of STREAM_FAILURES) cases.push(inheritedAgent(version,
      agentFields(version, { stage: 'stream_open', stream_failure })));
    for (const phase of CHALLENGE_PHASES) for (const before_challenge of ELAPSED_BUCKETS) for (const in_challenge of ELAPSED_BUCKETS) {
      const challenge = { phase, before_challenge, in_challenge, ...(version === 10 ? { read: null } : {}) };
      cases.push(inheritedAgent(version, agentFields(version, { stage: 'challenge', challenge })));
    }
    for (current of cases) {
      const result = await fixture.adapter.deposit(operationRequest('deposit', fixture));
      assert.equal(result.status, 'incomplete', JSON.stringify(current));
      assert.deepEqual(result.storage.deposit_diagnostics, current);
      assertFrozenTree(result.storage.deposit_diagnostics);
      assert.ok(Object.isFrozen(result.storage.deposit_diagnostics.failures[0]));
      const detail = result.storage.deposit_diagnostics.failures[0].agent_detail;
      if (detail) { assert.ok(Object.isFrozen(detail)); if (detail.challenge) assert.ok(Object.isFrozen(detail.challenge)); }
      assert.equal(result.remote_cleanup_confirmed, false);
    }
  }
});

test('selected inherited fields reject missing keys, private enums and impossible pre-READY bindings', async t => {
  for (const [key, , version] of SELECTORS) {
    let current;
    const fixture = await setup(t, { configChanges: { [key]: true }, process: fakeProcess(async () => ({
      raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: current }, code: 1,
    })) });
    const detail = agentFields(version, { stage: 'challenge', challenge: { phase: 'challenge_read_verify',
      before_challenge: 'under_1s', in_challenge: '90_to_120s', ...(version === 10 ? { read: null } : {}) } });
    const valid = inheritedAgent(version, detail);
    const invalid = [null, [], {}, { ...valid, raw: 'PRIVATE-INHERITED-CANARY' }];
    for (const source of ['root', 'failure', 'detail', 'challenge']) {
      const original = source === 'root' ? valid : source === 'failure' ? valid.failures[0]
        : source === 'detail' ? detail : detail.challenge;
      const extra = structuredClone(valid);
      const extraTarget = source === 'root' ? extra : source === 'failure' ? extra.failures[0]
        : source === 'detail' ? extra.failures[0].agent_detail : extra.failures[0].agent_detail.challenge;
      extraTarget.raw = 'PRIVATE-INHERITED-CANARY'; invalid.push(extra);
      for (const field of Object.keys(original)) {
        const bad = structuredClone(valid);
        const target = source === 'root' ? bad : source === 'failure' ? bad.failures[0]
          : source === 'detail' ? bad.failures[0].agent_detail : bad.failures[0].agent_detail.challenge;
        delete target[field]; invalid.push(bad);
      }
    }
    for (const [field, value] of [['stage', 'wire_receipt'], ['category', 'io'], ['agent_code', 'unknown']]) {
      invalid.push(inheritedAgent(version, detail, { [field]: value }));
    }
    for (const [field, value] of [['stage', 'provider_lookup'], ['tls_failure', 'io'], ['stream_failure', 'flow_acquire']]) {
      invalid.push(inheritedAgent(version, { ...detail, [field]: value }));
    }
    for (const [field, values] of Object.entries({ stage: ['PRIVATE-INHERITED-CANARY', false, 1],
      deadline_scope: ['bridge', 'remote_wire', 'PRIVATE-INHERITED-CANARY'], tls_failure: ['PRIVATE-INHERITED-CANARY'],
      stream_failure: ['PRIVATE-INHERITED-CANARY'] })) {
      for (const value of values) invalid.push(inheritedAgent(version, agentFields(version, { [field]: value })));
    }
    for (const field of ['phase', 'before_challenge', 'in_challenge']) for (const value of [null, false, 1, 'PRIVATE-INHERITED-CANARY']) {
      invalid.push(inheritedAgent(version, { ...detail, challenge: { ...detail.challenge, [field]: value } }));
    }
    for (const field of Object.keys(BASE_ENUMS)) invalid.push(inheritedDiagnostic(version, { [field]: 'PRIVATE-INHERITED-CANARY' }));
    for (const agent_code of ['PRIVATE-INHERITED-CANARY', null, false]) invalid.push(inheritedDiagnostic(version,
      { category: 'agent_rejected', agent_code }));
    invalid.push(inheritedAgent(version, agentFields(version, { stage: 'unobserved', deadline_scope: 'none' })),
      inheritedAgent(version, agentFields(version, { deadline_scope: 'exchange' })),
      inheritedAgent(version, agentFields(version, { deadline_scope: 'operation' }), { agent_code: 'CONTENT_BUSY' }),
      inheritedAgent(version, agentFields(version, { stage: 'tls_handshake', deadline_scope: 'operation', tls_failure: 'io' })),
      inheritedAgent(version, agentFields(version, { stage: 'provider_lookup', stream_failure: 'policy' })));
    for (current of invalid) {
      const result = await fixture.adapter.deposit(operationRequest('deposit', fixture));
      assert.equal(result.code, 'invalid_core_report', JSON.stringify(current));
      assert.equal(result.storage, null);
      assert.equal(result.local_process_joined, true);
      assert.equal(result.remote_cleanup_confirmed, false);
      assert.ok(!JSON.stringify(result).includes('PRIVATE-INHERITED-CANARY'));
    }
    assert.deepEqual(await readFile(fixture.input), CONTENT);
  }
});

// Closed bridge/remote-wire phase contracts, listed independently of the SDK's
// ordered discriminant slices so moving a boundary in the parser is detectable.
const BRIDGE_OUTCOME_PHASES = ['local_request_read', 'local_request_verify', 'local_payload_read',
  'local_payload_verify', 'admission', 'remote_request_verify', 'remote_request_write', 'remote_payload_write',
  'remote_receipt_read', 'remote_receipt_verify', 'remote_payload_read', 'remote_payload_verify',
  'local_receipt_write', 'local_payload_write'];
const REMOTE_WIRE_OUTCOME_PHASES = ['remote_request_verify', 'remote_request_write', 'remote_payload_write',
  'remote_receipt_read', 'remote_receipt_verify', 'remote_payload_read', 'remote_payload_verify'];

test('selected inherited outcomes preserve all finite phases and enforce exact category deadline scope', async t => {
  for (const [key, , version] of SELECTORS) {
    let current;
    const fixture = await setup(t, { configChanges: { [key]: true }, process: fakeProcess(async () => ({
      raw: { ...coreReport('deposit', 'uncertain', false), deposit_diagnostics: current }, code: 1,
    })) });
    function outcome(status, detail) { return { status, detail, append_timing: null, ...(version >= 9 ? { tls_close_failure: null } : {}) }; }
    for (const phase of OUTCOME_PHASES) for (const category of ['io', 'auth', 'invalid', 'busy', 'store', 'expired',
      'entropy', 'timeout', 'policy', 'unavailable', 'cancelled']) for (const deadline_scope of ['none', 'operation', 'exchange', 'bridge', 'remote_wire']) {
      current = inheritedDiagnostic(version, { agent_outcome: outcome('observed', { phase, category, deadline_scope }) });
      const scopes = category === 'timeout' ? ['operation', 'exchange',
        ...(BRIDGE_OUTCOME_PHASES.includes(phase) ? ['bridge'] : []),
        ...(REMOTE_WIRE_OUTCOME_PHASES.includes(phase) ? ['remote_wire'] : [])] : ['none'];
      const valid = scopes.includes(deadline_scope);
      const result = await fixture.adapter.deposit(operationRequest('deposit', fixture));
      assert.equal(result.code, valid ? 'retained_operation_incomplete' : 'invalid_core_report', JSON.stringify(current));
      if (valid) {
        assert.deepEqual(result.storage.deposit_diagnostics, current);
        assert.ok(Object.isFrozen(result.storage.deposit_diagnostics.failures[0].agent_outcome.detail));
      } else assert.equal(result.storage, null);
    }
    for (const status of ['missing', 'pending', 'expired', 'query_failed', 'query_timeout']) {
      for (const stage of ['wire_receipt', 'agent_terminal', 'deadline']) {
        current = inheritedDiagnostic(version, { stage, agent_outcome: outcome(status, null) });
        assert.deepEqual((await fixture.adapter.deposit(operationRequest('deposit', fixture))).storage.deposit_diagnostics, current);
      }
      current.failures[0].agent_outcome.detail = { phase: 'ready_write', category: 'io', deadline_scope: 'none' };
      assert.equal((await fixture.adapter.deposit(operationRequest('deposit', fixture))).code, 'invalid_core_report');
    }
    const finite = inheritedDiagnostic(version, { agent_outcome: outcome('observed',
      { phase: 'remote_receipt_read', category: 'io', deadline_scope: 'none' }) });
    const invalid = [];
    for (const stage of BASE_ENUMS.stage.filter(stage => !['wire_receipt', 'agent_terminal', 'deadline'].includes(stage))) {
      invalid.push({ ...finite, failures: [{ ...finite.failures[0], stage }] });
    }
    for (const source of ['outcome', 'detail']) {
      const original = source === 'outcome' ? finite.failures[0].agent_outcome : finite.failures[0].agent_outcome.detail;
      for (const field of [...Object.keys(original), 'raw']) {
        const bad = structuredClone(finite);
        const target = source === 'outcome' ? bad.failures[0].agent_outcome : bad.failures[0].agent_outcome.detail;
        if (field === 'raw') target.raw = 'PRIVATE-OUTCOME-CANARY'; else delete target[field];
        invalid.push(bad);
      }
    }
    for (const status of ['PRIVATE-OUTCOME-CANARY', false, 1, null]) {
      invalid.push(inheritedDiagnostic(version, { agent_outcome: outcome(status, null) }));
    }
    for (current of invalid) {
      const result = await fixture.adapter.deposit(operationRequest('deposit', fixture));
      assert.equal(result.code, 'invalid_core_report', JSON.stringify(current));
      assert.equal(result.storage, null); assert.ok(!JSON.stringify(result).includes('PRIVATE-OUTCOME-CANARY'));
    }
    for (const [field, value] of [['phase', 'PRIVATE-OUTCOME-CANARY'], ['category', 'PRIVATE-OUTCOME-CANARY'],
      ['deadline_scope', 'PRIVATE-OUTCOME-CANARY']]) {
      current = inheritedDiagnostic(version, { agent_outcome: outcome('observed',
        { phase: 'ready_write', category: 'io', deadline_scope: 'none', [field]: value }) });
      const result = await fixture.adapter.deposit(operationRequest('deposit', fixture));
      assert.equal(result.code, 'invalid_core_report'); assert.ok(!JSON.stringify(result).includes('PRIVATE-OUTCOME-CANARY'));
    }
  }
});

test('all selected versions bind uniqueness, omissions and completion to exact retained-copy geometry', async t => {
  for (const [key, , version] of SELECTORS) {
    let raw = repairedReport('deposit', 'pending', 6);
    const failure = inheritedDiagnostic(version).failures[0];
    const valid = { version, failures: Array.from({ length: 8 }, (_, copy_index) => ({ ...failure, copy_index })), omitted_failures: 4 };
    raw.deposit_diagnostics = valid;
    const fixture = await setup(t, { configChanges: { [key]: true }, process: fakeProcess(async () => ({
      raw, code: raw.operation_complete ? 0 : 1,
    })) });
    const request = operationRequest('deposit', fixture);
    assert.deepEqual((await fixture.adapter.deposit(request)).storage.deposit_diagnostics, valid);
    const duplicate = structuredClone(valid); duplicate.failures[1].copy_index = 0;
    const otherStageDuplicate = structuredClone(duplicate); otherStageDuplicate.failures[1].stage = 'agent_terminal';
    for (const invalid of [{ ...valid, omitted_failures: 5 }, { ...valid, omitted_failures: 2048 },
      { ...valid, failures: valid.failures.slice(0, 7) }, { ...valid, failures: [...valid.failures, failure] },
      { ...valid, failures: [], omitted_failures: 1 }, duplicate, otherStageDuplicate]) {
      raw.deposit_diagnostics = invalid;
      assert.equal((await fixture.adapter.deposit(request)).code, 'invalid_core_report');
    }
    for (const [field, values] of Object.entries({ fragment_index: [-1, 3, null, true, '0'], copy_index: [-1, 8, null, true, '0'] })) {
      for (const value of values) {
        raw.deposit_diagnostics = inheritedDiagnostic(version, { [field]: value });
        assert.equal((await fixture.adapter.deposit(request)).code, 'invalid_core_report');
      }
    }
    raw = { ...coreReport('deposit'), deposit_diagnostics: { version, failures: [], omitted_failures: 0 } };
    assert.equal((await fixture.adapter.deposit(request)).status, 'complete');
    raw.deposit_diagnostics = inheritedDiagnostic(version);
    assert.equal((await fixture.adapter.deposit(request)).code, 'invalid_core_report');
    raw.deposit_diagnostics = { version, failures: [], omitted_failures: 1 };
    assert.equal((await fixture.adapter.deposit(request)).code, 'invalid_core_report');
  }
});
