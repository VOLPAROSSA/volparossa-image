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
directory. All paths are absolute, without symlinks. The required fields are:

| Field | Meaning |
| --- | --- |
| `version` | `1` |
| `coreBinary` | Explicit existing core executable; no installation or daemon startup |
| `controlSocket` | Existing protected local core socket for network operations |
| `identity` | Existing encrypted core identity file |
| `passphraseFile` | Existing private core identity passphrase file |
| `stateDirectory` | Stable per-snapshot reconstruction journal path; absent on create |
| `providers` | 3–8 distinct explicit `{ "key": "64 lowercase hex digits", "grant": "/absolute/private/grant" }` entries |
| `copies` | 2–7 copies per fragment, strictly fewer than provider count |
| `fragmentBytes` | Maximum fragment size, 1 byte to 1 GiB |
| `lifetimeSeconds` | Requested lease duration, 1–2,678,400 seconds, also constrained by grants |
| `deadlineMs` | Optional operation budget, 100–1,800,000 ms; default 30 minutes |

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

## Resume, restore and contribution accounting

The core binds the original ciphertext length/hash, fragment offsets/hashes, owner,
provider/grant identities and reservation IDs in its signed reconstruction manifest.
Keep `stateDirectory` and the owner's recovery credentials independently recoverable.
Changing the configuration's provider list does not replace an existing journal's
immutable placement. `deposit`, `progress`, `restore`, `renew` and `delete` use that
original state, not a newly generated placement plan. If interrupted during creation,
inspect the original state with `status` before deciding the next action; the bridge
does not overwrite or automatically recreate it.

Archives are bounded by the core to 64 GiB and at most 256 fragments. The core may
split smaller than `fragmentBytes` to spread fragments across all chosen providers;
the adapter rejects plans that would exceed the fragment count. This is redundant
fragmentation, **not erasure coding**, automatic repair or automatic contribution resizing.

Interrupted or unconfirmed copies remain charged. The reported physical payload upper
bound includes reserved, committed and uncertain copies, including expired copies until
reconciled/deleted. It excludes unmeasured metadata overhead and is **not** measured network
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
same-journal retries, bounded reports, accounting consistency, no-overwrite/readback
checks and cancellation. Their storage responses are fabricated **test fixtures**.
Two tests use a real synthetic Node child solely to verify process termination/join.
They do not run the Rust core, storage peers, protected network paths or Immich.
Actual peer-backed snapshot deposit, source-independent restore and application/mobile
integration require separate functional evidence before being called working.
