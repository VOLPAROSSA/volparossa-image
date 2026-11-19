![VOLPAROSSA Image banner with photographs developing in a warmly lit darkroom](docs/assets/banner-volparossa-image.png)

# VOLPAROSSA Image

**Keep your photo library, without having to become a full-time server operator.**

Family photos and videos need more than a place to upload bytes: albums, browsing
and recovery must still work when a device is replaced. VOLPAROSSA Image builds
on Immich, with the goal of managing and synchronizing that library without a
personally maintained server that must stay online.

A fresh Immich 3.2.4 installation recovered a private test album through three
VOLPAROSSA Storage providers. With the original installation removed and one
provider offline, an owner signed in again and downloaded the original photo.
Storage held only ciphertext. The recovery key stayed with the owner.
[Recovery evidence and exact revisions](docs/SNAPSHOT_STORAGE.md#joined-immich-recovery)

Continuous library availability, Android and iOS synchronization, and background
processing on authorized devices remain in development.

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

The bridge and CLI now also expose [finite owner maintenance](docs/STORAGE_BRIDGE.md#finite-owner-maintenance):
explicit enrollment, supervised core maintenance, and foreground pause/join/resume
through one adapter instance. Process/contract checks are available; a combined
real-peer maintenance proof and installed background service are still pending.

Do not upload the entire snapshot bundle: only `snapshot.pgp` belongs on storage peers,
never `recovery.key`. Keep originals until independently verified recovery and an explicit
owner decision to remove them.

The earlier synthetic archive trial verified fragment recovery and deletion on
Image `e177afeb` and Core `cf4de524`. The subsequent Immich trial verified the
live database and media through the same recovery lifecycle using a real API
client and a new application instance.
[Archive trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/36905847039) ·
[Immich application and peer trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44411540175)

See [upstream pin and source boundaries](docs/UPSTREAM.md) and
[Android, iOS and web integration points](docs/CLIENT_INTEGRATION.md).

Upstream source and build products belong under ignored `build/`, not in your photo library.
No test should use personal photos or start host services. The core lives separately in
[VOLPAROSSA/volparossa](https://github.com/VOLPAROSSA/volparossa).

Architecture references: [Immich architecture](https://docs.immich.app/developer/architecture/),
[backup and restore](https://docs.immich.app/administration/backup-and-restore/),
[remote machine learning](https://docs.immich.app/guides/remote-machine-learning/).
