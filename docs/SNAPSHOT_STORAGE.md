# From a private snapshot to core storage

`scripts/snapshot-storage.mjs` connects the existing
[snapshot producer](SNAPSHOT.md) to the real
[`CoreStorage` adapter](STORAGE_BRIDGE.md). It is an explicit Linux / Node 24 CLI,
not a new daemon, peer scheduler or application-side storage ledger. No package
installation, provider discovery or background participation is performed.

## Prepare once

1. Produce a new bundle with `immich_snapshot.py create`, using a completed,
   explicitly quiesced database/media copy. Preserve the original data.
2. Independently retain the owner-generated `receipt.json`, `recovery.key`, core
   identity credentials and reconstruction journal. Storage peers never receive
   any of these through this CLI.
3. Prepare a private [storage configuration](STORAGE_BRIDGE.md#configuration-and-api)
   with explicit providers/grants and one stable `stateDirectory` for this
   snapshot. That directory must not exist before the first `create`.

All paths are absolute and canonical. Configuration, receipt and ciphertext must
be same-owner, single-link regular files with mode `0600`, directly within owned
`0700` directories. The owner receipt must have the exact snapshot-producer schema,
including `OpenPGP-AES256`, `snapshot.pgp`, expected ciphertext length and SHA-256.
It is a local trust anchor, **not a peer-signed certificate or encryption proof**.
Use the receipt actually produced by the owner-side GnuPG workflow, not an unsigned
replacement supplied by a storage peer.

## Explicit operations

```sh
# Local reconstruction-plan creation; does not deposit to peers yet.
node scripts/snapshot-storage.mjs create \
  --config /owner/private/storage.json --bundle /owner/private/snapshot

# Only snapshot.pgp is an input to the core. The key is not even opened.
node scripts/snapshot-storage.mjs deposit \
  --config /owner/private/storage.json --bundle /owner/private/snapshot

# Retained local receipts, then deliberate remote reconciliation.
node scripts/snapshot-storage.mjs status --config /owner/private/storage.json
node scripts/snapshot-storage.mjs progress --config /owner/private/storage.json

node scripts/snapshot-storage.mjs renew \
  --config /owner/private/storage.json --lifetime-seconds 604800
```

Before creation/deposit the CLI streams the entire ciphertext through SHA-256 and
checks its size against the original receipt. It reads neither media nor the key.
The core independently checks its signed reconstruction binding when reopening
the input; no filename-only encryption inference or invented FD interface is used.
Creation rejects ciphertext above 64 GiB and plans above 256 fragments before the
core operation. Set `fragmentBytes` large enough for the actual archive; there is
no truncation or automatic second archive.

After interruption or incomplete deposition, run `progress` and retry `deposit`
with the **same configuration, state directory and ciphertext**. Never use a new
`create` as a retry. Existing state is refused, not replaced; creation interrupted
after producing state requires inspection of that original state. The core's
journal lock, owner signature and immutable placement remain authoritative.

`complete` refers to the requested operation, not universal availability or full
redundancy. Retained/uncertain physical charges and the bridge's explicit
availability/cleanup limitations remain unchanged. Cancellation propagates to the
bridge; it does not imply remote erasure. Preflight hashing has a bounded budget
from `deadlineMs`; the subsequent core operation has its own bridge budget.

## Retrieve first; supply the key and decrypt separately

```sh
node scripts/snapshot-storage.mjs restore \
  --config /owner/private/storage.json \
  --receipt /owner/private/snapshot/receipt.json \
  --output /owner/private/new-recovered-bundle
```

The output must be new, in an existing owned `0700` parent, and outside the core
journal. The core retrieves the ciphertext; `CoreStorage` independently checks its
complete hash against the retained receipt. Only successful verified retrieval
adds `receipt.json` beside `snapshot.pgp`. The original local ciphertext may be
absent. No `recovery.key` is copied and no decryption happens.

The owner then supplies their independently retained `recovery.key` to this new
private bundle, without overwriting an existing file, and invokes the separate
snapshot decoder with the original receipt's expected hash:

```sh
python3 scripts/immich_snapshot.py restore \
  --bundle /owner/private/new-recovered-bundle \
  --expected-sha256 'OWNER_RETAINED_64_HEX_CIPHERTEXT_SHA256' \
  --output /owner/private/new-restored-copy
```

Failed/incomplete retrieval leaves its new output directory and any core-published
ciphertext intact for inspection; no success receipt is added. A retry uses a new
output directory but the **same core journal**. Neither reads nor this wrapper's
cleanup consume remote copies or remove originals.

Only an explicit owner decision to request deletion should invoke:

```sh
node scripts/snapshot-storage.mjs delete --config /owner/private/storage.json
```

This asks the core to delete its retained remote copies; it does not delete the
local journal, archive, receipt, key or source library. Unconfirmed remote copies
remain conservatively charged. No global secure-erasure promise follows.

## Results and evidence

The CLI emits the adapter's closed JSON result plus `snapshot_operation`,
`snapshot_ciphertext_checked`, `recovery_bundle_ready`, `snapshot_decrypted: false`
and `immich_restore_proven: false`. Exit status is zero only for a complete
operation. It does not print local paths, keys, raw subprocess logs or receipt
hashes. Validation failures use closed codes. `--help` performs no core operation.

```sh
node --test tests/snapshot-storage.test.mjs tests/core-storage.test.mjs
```

The orchestration tests use real private local files and **fabricated storage
contract responses**, not actual peer storage or GnuPG encryption of those dummy bytes.
They cover receipt/cipher binding, fragment bounds, unchanged retry state,
operation dispatch, non-overwriting source-independent retrieval, separate key
supply and failure/cancellation semantics. The actual synthetic GnuPG tests are
documented separately in [SNAPSHOT.md](SNAPSHOT.md). A combined real core/peer
deposit–retrieve–decrypt proof is still required, followed by a running restored
Immich instance. This CLI proves neither mobile integration nor operation without
an always-on personal server.
