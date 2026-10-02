# Project VOLPAROSSA Image

**Immich connected to the VOLPAROSSA Decentralized Intelligent Cooperative Network.**

The goal: manage, back up and share your photos and videos without maintaining a personal
server that must stay online. Your devices retain control of keys and private data;
VOLPAROSSA supplies cooperative storage, connectivity and eligible background work.

> Development integration, not yet a working server-independent Immich application.
> A scoped encrypted-snapshot/peer-recovery trial passes; live library operation and
> mobile integration remain unfinished.

**Target clients: Android, iPhone/iPad and the web browser.** The shared core/data
contract comes first; a working web-only version would not complete the mobile scope.

## What connects to VOLPAROSSA

- **Private storage:** encrypted originals, recovery metadata and selected derived files,
  distributed redundantly across peers. Contribution follows actual remotely retained bytes,
  including redundant copies and counted overhead; shrinking usage must not discard others' data.
- **Library and device sync:** albums, edits, favorites and deletion state need a recoverable,
  authenticated library model, not just a collection of uploaded files. Offline devices must
  catch up without losing changes or reviving deleted objects.
- **Network and sharing:** authenticated device connections and recipient-authorized albums;
  no public port forwarding or dependence on one always-on home machine as the final design.
- **Compute:** thumbnails, video processing and image search are integration candidates.
  Private photos and face/location data must not be sent to arbitrary workers. Local or
  explicitly trusted execution remains the starting privacy boundary.
- **Cache and policy:** owner-private caching is separate from public sharing. Content checks
  and resource admission must preserve privacy; encrypted custody is not proof of lawful content.

## No always-on personal server does not mean no running infrastructure

Immich currently relies on an API service, PostgreSQL and background workers. Connecting its
storage alone does not remove those dependencies. The integration must supply the necessary
application functions on available authorized devices while peers retain encrypted objects.
When an owner's original device is off, a receiving device still needs access to enough online
storage holders and its recovery credentials. Availability cannot be guaranteed if every
relevant copy is offline.

The first storage bridge is a development step toward that architecture, not a claim that an
unmodified Immich phone app can already operate without its server. Native mobile daemon
integration, simultaneous-device changes, unattended repair and server-independent library
browsing remain open. Normal Immich use must remain available during development.

## Development

Three connected development components are available:

1. [Private snapshots](docs/SNAPSHOT.md): a quiesced database/media copy is streamed into
   standard OpenPGP encryption. Real synthetic-data tests exercise two identical restores,
   wrong-key/corruption rejection and cleanup. The recovery key remains with the owner.
2. [Core storage bridge](docs/STORAGE_BRIDGE.md): a Node adapter passes only the encrypted
   snapshot to the existing core fragment-storage operations, retaining the same recovery
   journal across retries and verifying complete restored ciphertext. Its process/contract
   tests do **not** yet prove peer-backed Immich storage.
3. [Snapshot storage CLI](docs/SNAPSHOT_STORAGE.md): explicit create, deposit, progress,
   restore, renew and delete commands connect the snapshot receipt to that bridge. The
   CLI uploads only hash-checked ciphertext and restores into a new private bundle;
   supplying the owner's key and decrypting remain separate operations.

Do not upload the entire snapshot bundle: only `snapshot.pgp` belongs on storage peers,
never `recovery.key`. Keep originals until independently verified recovery and an explicit
owner decision to remove them.

The [combined peer snapshot trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/36905847039)
passes on exact Image `e177afebabd99ac0773de2a73d60275346a5de52` and core
`cf4de524ce885af95d0f75fcb53d80254486c27f`: a synthetic encrypted snapshot is spread
as eight fragment copies over three providers, provider A is stopped, and B/C supply
two complete decryptions/restores. All-copy deletion and private/network cleanup pass.
This proves that pinned snapshot/storage slice, **not the newer Node adapter**, a
running restored Immich library, device synchronization or server-independent mobile use.
Those application paths still require their own functional proofs.

See [upstream pin and source boundaries](docs/UPSTREAM.md) and
[Android, iOS and web integration points](docs/CLIENT_INTEGRATION.md).

Upstream source and build products belong under ignored `build/`, not in your photo library.
No test should use personal photos or start host services. The core lives separately in
[VOLPAROSSA/volparossa](https://github.com/VOLPAROSSA/volparossa).

Architecture references: [Immich architecture](https://docs.immich.app/developer/architecture/),
[backup and restore](https://docs.immich.app/administration/backup-and-restore/),
[remote machine learning](https://docs.immich.app/guides/remote-machine-learning/).
