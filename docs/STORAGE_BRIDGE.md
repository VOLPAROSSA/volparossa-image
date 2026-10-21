# Private snapshot storage bridge

`src/core-storage.mjs` is a dependency-free **Linux / Node 24 development adapter**
to the existing VOLPAROSSA `storage fragments` CLI. It places no objects itself:
the core owns provider authentication, signed reconstruction manifests, reservations,
fragment placement, protected transport, receipts and conservative accounting.

This is not yet an Android, iOS or web application binding, nor a working
server-independent Immich library. An encrypted snapshot is a recovery unit;
it is not live database access, photo browsing, device synchronization or background
thumbnail processing.

## Boundary: encrypted bytes only

The caller supplies one explicitly **already-encrypted**, owner-private regular file.
For the snapshot tooling, this is `snapshot.pgp`, never the entire bundle.
Do not upload `recovery.key`, readable database dumps, photos, thumbnails, filenames,
EXIF/GPS, face embeddings or the recovery metadata alongside it. The adapter neither
encrypts files nor infers from an extension that their contents are encrypted:
`alreadyEncrypted: true` is an explicit caller assertion, not encryption verification.

The core identity passphrase is distinct from the snapshot decryption key. Neither is
passed as an argument value, environment value or public report. The adapter never
reads the passphrase bytes; the core opens the configured private passphrase file.
It never deletes an original snapshot, decryption key, journal or restored file.

## Configuration and API

Create a JSON configuration file with mode `0600` in a canonical, same-owner `0700`
directory. All paths are absolute, without symlinks. Fields are required unless
marked optional:

| Field | Meaning |
| --- | --- |
| `version` | `1` |
| `coreBinary` | Explicit existing core executable; no installation or daemon startup |
| `controlSocket` | Existing protected local core socket for network operations |
| `identity` | Existing encrypted core identity file |
| `passphraseFile` | Existing private core identity passphrase file |
| `stateDirectory` | Stable per-snapshot reconstruction journal path; absent on create |
| `providers` | 3–8 distinct explicit `{ "key": "64 lowercase hex digits", "grant": "/absolute/private/grant" }` entries |
| `copies` | Optional deprecated compatibility field; only `2` is accepted. Prefer omitting it: new-archive redundancy belongs to the core, not the application. |
| `fragmentBytes` | Maximum fragment size, 1 byte to 1 GiB |
| `lifetimeSeconds` | Requested lease duration, 1–2,678,400 seconds, also constrained by grants |
| `deadlineMs` | Optional operation budget, 100–1,800,000 ms; default 30 minutes |
| `appendDiagnosticsV7` | Optional boolean, default false; select exact deposit diagnostic v7 with APPEND timing |
| `flowAcquireDiagnosticsV8` | Optional boolean, default false; select exact v8 including local flow-acquisition observations |
| `tlsCloseDiagnosticsV9` | Optional boolean, default false; select exact v9 including finite TLS-close reasons |
| `challengeReadDiagnosticsV10` | Optional boolean, default false; select exact v10 including request-local challenge-read detail |

Identity, passphrase, grant, ciphertext and restored files must be same-owner,
single-link regular files with mode `0600`, directly within same-owner `0700`
canonical directories. The journal parent must already exist and be private.
The bridge does not create a missing parent, discover providers or change permissions.
Core grant and owner verification remain authoritative; explicit provider keys do not
prove independent people or failure domains.

```js
import { CoreStorage } from './src/core-storage.mjs';

const storage = await CoreStorage.open('/private/image/storage.json');
const ciphertext = '/private/snapshot-bundle/snapshot.pgp';
const sha256 = '...'; // Actual independently retained 64-character ciphertext SHA-256.

// Explicit first-time creation. Do not repeat create as an automatic retry.
const created = await storage.create({ input: ciphertext, sha256, alreadyEncrypted: true });
if (created.status !== 'complete') throw new Error(created.code);

// Retry this same operation and journal after an interrupted/incomplete deposit.
const deposited = await storage.deposit({ input: ciphertext, alreadyEncrypted: true });
const retained = await storage.status(); // Local receipts only; can work without a live socket.
const reconciled = await storage.progress();
const renewed = await storage.renew({ lifetimeSeconds: 604800 });

// Always a NEW output; the adapter additionally reads and checks its entire SHA-256.
const restored = await storage.restore({ output: '/private/recovery/snapshot.pgp', sha256 });
if (!restored.restore_verified) throw new Error(restored.code);

// Only after the owner explicitly decides to delete their remote copies:
// const deleted = await storage.delete();
```

All methods accept a final `{ signal: AbortSignal }` option; `status`, `progress`
and `delete` take that option as their only argument. A bridge instance admits one
operation at a time. Separate instances still rely on the core's journal lock;
there is no second application-side placement journal or accounting authority.

`create` and `deposit` map exactly to the supported `--input PATH` /
`--already-encrypted` CLI. The current core does **not** accept inherited input or
passphrase FDs. The bridge validates and holds open `O_NOFOLLOW` descriptors through
child completion, but the core independently reopens the private paths; holding an FD
does not bind that later path lookup to the original inode. Private owned parents and
the core's immutable signed hashes provide the supported boundary. No fictitious
`--input-fd` or `/proc/self/fd` workaround is used. Paths, but not secret contents,
are necessarily present in the local command line.

## Explicit deposit diagnostics

At most one of the four diagnostic selectors may be `true`. Every supplied selector
must be a boolean. A selected deposit sends exactly its corresponding
`--append-diagnostics-v7`, `--flow-acquire-diagnostics-v8`, `--tls-close-diagnostics-v9`
or `--challenge-read-diagnostics-v10` flag and requires the exact selected report
version. Missing, downgraded, future, malformed or extra diagnostic fields fail closed
as `invalid_core_report`. There is no generic opt-in for diagnostic v1–v6; their
closed observations are inherited fields of the explicitly selected v7–v10 versions.

With all selectors absent or false, the bridge preserves its original argv and
result behavior: unsolicited `deposit_diagnostics` are ignored, including malformed
or future values. A payload's version marker never authorizes projection. Selectors
are inactive on create, status, progress, restore, renew and delete; unsolicited
diagnostics on those operations are ignored even when a selector is configured.

A valid selected deposit adds only a frozen `storage.deposit_diagnostics` summary.
It binds failures to the already validated fragment/copy geometry, limits displayed
failures to eight, and checks omissions, uniqueness, exact nested fields and finite
enums. Nullable outcomes remain unknown. Diagnostics do not replace the original
error, accounting, completion, retry decision or cleanup evidence and never expose
provider keys, paths, free-form stderr or payload bytes.

In v10, a non-null challenge-read detail belongs only to `challenge_read_verify`
and distinguishes length read, body read and synchronous verification. Its returned
outcome is closed and step-specific; `null` means no returned wire outcome was
observed. It alone establishes neither cancellation nor timeout nor a remote cause.
The existing `before_challenge` and `in_challenge` buckets still describe the whole
challenge boundary. No deadline, retry, frame, authorization or sandbox policy changes.

The retained maintenance implementation on the separate diagnostic branch is pending
integration. This composition adds no background session, maintenance method or
snapshot-CLI behavior.

## Resume, restore and contribution accounting

The core binds the original ciphertext length/hash, fragment offsets/hashes, owner,
provider/grant identities and reservation IDs in its signed reconstruction manifest.
Keep `stateDirectory` and the owner's recovery credentials independently recoverable.
Changing the configuration's provider list does not replace an existing journal's
immutable placement. `deposit`, `progress`, `restore`, `renew` and `delete` use that
original state and its core-authorized replacement history, not a newly generated
placement plan. If interrupted during creation,
inspect the original state with `status` before deciding the next action; the bridge
does not overwrite or automatically recreate it.

New archives use the core's uniform two-copy target; the adapter sends no `--copies`
argument and rejects a create report with another target. Existing signed archives
with a higher target remain readable, restorable, renewable and deletable without
pruning copies or rewriting that target. For an old configuration containing
`copies` greater than two, remove **only that obsolete configuration field** before
opening the adapter; do not change the retained archive journal.

Archives are bounded by the core to 64 GiB and at most 256 fragments. The core may
split smaller than `fragmentBytes` to spread fragments across all chosen providers;
the adapter rejects plans that would exceed the fragment count. This is redundant
fragmentation, **not erasure coding**, automatic repair or automatic contribution resizing.

The adapter accepts both original reports and additive **fragment report v2** from
the core's explicit replacement primitive. V2 separates the desired copy target from
retained history (up to eight records per fragment), including deleted records and
replacements on providers outside the original pool. The adapter checks the original
placement, authorization/history counts and per-copy/per-provider charge totals;
the core remains responsible for verifying signed authorization. Pending retirement
does not prevent ordinary lifecycle operations or independently verified restores.
Image does not initiate replacements or run automatic maintenance.

Interrupted or unconfirmed copies remain charged. The reported physical payload upper
bound includes reserved, committed and uncertain copies, including temporary replacement
overlap and expired copies until reconciled/deleted. It can therefore exceed the desired
target multiplied by the archive size. It excludes unmeasured metadata overhead and is **not** measured network
contribution credit or proof of currently available storage. Equal contribution and
safe resizing are core responsibilities, not independent balances created by this adapter.

Restore checks all fragments and the complete ciphertext in the core, publishes without
overwriting an existing output, then the bridge independently checks the restored private
file against the caller's expected hash. Retain that hash from a trusted original or
authenticated recovery record; a peer-supplied unsigned receipt is not an identity proof.
Repeated restores do not consume remote copies. A failed/cancelled readback preserves
any already-published output for inspection; it never silently overwrites it on retry.

## Closed results and cancellation

Results contain only bounded fields:

```text
version, operation, status, code, local_process_joined,
remote_cleanup_confirmed, restore_verified, storage
```

`status` is `complete`, `incomplete`, `failed`, `cancelled` or `timed_out`. `storage`
is either a validated closed accounting summary or `null`; raw stderr, input paths,
provider keys, fragment IDs and arbitrary CLI text are not returned. Raw stdout is
limited to 2 MiB before JSON parsing. Core exit status must agree with its completion
flag: a useful incomplete report with exit code 1 remains `incomplete`, not success.
Local validation errors throw `StorageBridgeError` with a closed code and no file paths.
For v2, the summary also retains `report_version`, `placement_authorizations`,
`retained_copy_records`, `pending_retirements`, `desired_copies_per_fragment` and
`replacement_overhead_included`; those fields are not silently downgraded to v1.

`complete` describes the requested operation, not universal availability. In particular,
`status` only reads retained receipts and `progress` reconciles existing leases;
neither promises full redundancy or current remote availability. Inspect the explicit
summary flags. No filtering or legal-safety claim follows from ciphertext custody.

The explicit child receives no inherited environment, stdin or shell. Cancellation,
deadline or oversized output requests `SIGTERM` for its newly owned process group, then
`SIGKILL` after five seconds if needed. The promise waits for the actual child `close`
event before reporting `local_process_joined: true`; an unkillable process is not
invented away as cleanly joined. Restore readback also observes cancellation/deadline
between bounded reads. Filesystem/kernel stalls cannot be given an absolute completion
guarantee. A cancelled CLI is **not proof of cancellation or erasure at storage peers**:
`remote_cleanup_confirmed` remains false, journals stay intact and the next deliberate
`progress` call reconciles retained state.

## Verification scope

```sh
node --test tests/core-storage.test.mjs
```

The focused tests validate exact CLI arguments, private filesystem requirements,
same-journal retries, bounded v1/v2 reports, replacement overlap/history accounting,
uniform new-archive policy, legacy higher-copy lifecycle, no-overwrite/readback checks
and cancellation. Their storage responses are fabricated **test fixtures**.
Two tests use a real synthetic Node child solely to verify process termination/join.
They do not run the Rust core, storage peers, protected network paths or Immich.
Diagnostic tests reuse the fabricated CLI fixture and include direct full-result and
argv comparisons against the exact original main SDK at
`e817b48067108e0faaab7e2067a258bc07a4b045`. The readable test-only copy
`tests/fixtures/core-storage-default-e817b480.mjs` is unchanged: 20,915 bytes,
SHA-256 `d274c294a4f7c500aac552629997487c79e67faaa89dddd1383309d7e58273b0`.
The test verifies that identity before use. The diagnostic validators and selected
contract cases derive from retained Image
`f51b8ace0352377c7068a93fc8f4544f18e52978`, with its implicit v1–v6 acceptance
replaced by explicit configuration gating. Source checks do not prove actual peer
behavior or resolution of any historical trial failure.
The separate [peer-backed snapshot trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/36905847039)
passes with older Image `e177afebabd99ac0773de2a73d60275346a5de52` and core
`cf4de524ce885af95d0f75fcb53d80254486c27f`: eight fragment copies, provider A offline,
two B/C restores and actual GPG decryption, followed by complete deletion/cleanup.
That evidence does not cover this newer Node/report-v2 adapter or a running Immich
library. Joined proof for the current adapter and application/mobile integration
remain required before those paths are called working.
