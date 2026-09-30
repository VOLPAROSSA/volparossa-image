# Immich source and integration boundary

## Exact upstream

Source inspected on **2026-09-30**: [Immich v3.2.4](https://github.com/immich-app/immich/releases/tag/v3.2.4),
the official latest non-prerelease at inspection time, published 2026-09-28.
The release tag and independent remote tag lookup resolve to
`db355f79d910bbfc6378117ed10868493c97b922`.
[upstream.lock.json](../upstream.lock.json) records committed-source sizes and
SHA-256 hashes, including the dependency lock and API definition.

The local, unmodified inspection checkout is `build/upstream`. It is a shallow,
filtered, sparse source checkout, not an installed Immich application. No packages,
containers, models or services were installed or started for this inspection.
Upstream pins Node 24.15.0 and pnpm 11.22.0 in `mise.toml`; those dependencies have
not been provisioned here. No container digest or executable is validated by this
source pin.

## License and notices

Immich declares **GNU Affero General Public License version 3**. Its original
[LICENSE](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/LICENSE)
is retained unchanged in the checkout; `packages/cli/LICENSE` contains the same
license text. Both are identified by hash in the lock. Preserve these files,
upstream copyright notices and applicable third-party notices when packaging or
modifying upstream code. Modified network-served Immich must retain the applicable
AGPL corresponding-source offer; distribution must include the required license
and source information. The repository's original GPL license does **not** relabel
Immich or replace its AGPL obligations. Dependency-specific licenses still need
to accompany any later actual distribution.

## First executable connection: private snapshot and restore

The suitable initial integration is an owner-controlled **database dump plus
media snapshot**, encrypted locally before passing it to VOLPAROSSA private
storage, then restored into a new owner-controlled location. This is a backup
connection, not yet Immich without a personally operated always-on server.

[`StorageRepository`](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/server/src/repositories/storage.repository.ts)
is a concrete local-filesystem implementation: reads, writes, atomic renames and
archive generation all use local paths. It is not an object-storage plug-in slot.
Replacing it with peer storage alone would not make database, media processing or
client access independent of the server.

The genuine database producer is
[`DatabaseBackupService.createDatabaseBackup()`](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/server/src/services/database-backup.service.ts).
It streams `pg_dump` through gzip into a `.tmp` file and renames that file only
after the pipeline succeeds. A future server-side integration can attach after
that completed-producer boundary, without replacing the storage repository.
Dump completion does not freeze uploads, deletions or background media jobs.

The initial snapshot adapter must therefore require a quiescent owner instance or
an explicitly coordinated consistent snapshot. Merely supplying an old dump and a
changing media directory is not evidence of consistency. Include original media,
database metadata and required profile data; external libraries need separately
declared roots. Never copy an active PostgreSQL data directory. The pinned
[upstream backup instructions](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/docs/docs/administration/backup-and-restore.md)
distinguish database dumps from media and describe the required folders. Database
backups alone do not contain photos or videos.

The whole snapshot, including its inventory, filenames, EXIF, album metadata and
database contents, is private. Use existing core encryption, placement and
reciprocal-storage accounting; do not invent a second peer scheduler or expose
decryption keys to storage peers. Keep local source data unchanged. Archive
restoration must check exact contents and paths into a fresh destination, not
overwrite a working installation. A byte-for-byte archive round trip proves only
the archive path; a restored gallery additionally needs actual database import
and application readback in an isolated test instance.

## Verified local API seams

The normal API prefix is `/api`. An explicitly supplied owner admin API key can
use the `x-api-key` header; admin-only routes also check the user's administrator
flag, not just key permissions. These are source contracts, not claims that an
Immich server is running here.

| Operation | Exact request | Required admin-key permission |
| --- | --- | --- |
| Queue database dump | `POST /api/jobs`, JSON `{"name":"backup-database"}` | `job.create` |
| List available dump files | `GET /api/admin/database-backups` | `maintenance` |
| Download selected dump | `GET /api/admin/database-backups/:filename` | `backup.download` |

The queue request is admission only. Listing returns
`{"backups":[{"filename":"…","filesize":123,"timezone":"…"}]}`;
there is no task correlation identifier or creation timestamp in this response.
The current filename filter excludes `.tmp` files, but listing alone does not
prove a dump belongs to a particular queue request. Choose and validate the
completed file explicitly; do not silently treat any pre-existing dump as the
new job's result. API keys, backup bytes and filenames must not be logged or sent
to public caches.
([Job controller](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/server/src/controllers/job.controller.ts),
[backup controller](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/server/src/controllers/database-backup.controller.ts),
[authentication](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/server/src/services/auth.service.ts))

`POST /api/admin/database-backups/upload` accepts multipart field `file` and
stores a dump; it does **not** restore the database. Actual restore is a
maintenance-mode operation using `action: "restore_database"` and
`restoreBackupFilename`, with maintenance-session authentication after the worker
switch. It replaces database contents and creates a restore point. The first
adapter must not invoke this on an existing installation.
([Maintenance controller](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/server/src/controllers/maintenance.controller.ts),
[maintenance worker](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/server/src/maintenance/maintenance-worker.controller.ts))

For later live integration, asset upload is multipart `POST /api/assets`, original
retrieval is `GET /api/assets/:id/original`, and streaming sync uses
`POST /api/sync/stream` plus session-bound `/api/sync/ack`. Download archives contain
selected media, not a full restorable database. Those routes must retain existing
account checks, range support, checkpoints, deletions and album permissions.
([Asset media](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/server/src/controllers/asset-media.controller.ts),
[sync](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/server/src/controllers/sync.controller.ts),
[download](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/server/src/controllers/download.controller.ts))

## Remaining client and privacy work

Android, iPhone/iPad and web are all target clients. Their actual hook points and
remaining work are in [CLIENT_INTEGRATION.md](CLIENT_INTEGRATION.md). The Linux
core and snapshot connector are not evidence of a mobile core port, an offline
client or uninterrupted background execution.

Immich's current ML repository sends image bytes or text as multipart requests to
configured `/predict` endpoints. Remote execution therefore exposes that input to
the chosen ML operator. Keep private images, faces, embeddings and search text on
owner-controlled execution; an encrypted storage upload does not make arbitrary
peer ML private.
([ML repository](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/server/src/repositories/machine-learning.repository.ts))

Existing album/shared-link access is enforced by the reachable Immich service.
It is not a ciphertext-only, recipient-key sharing protocol. Availability while
the owner is offline needs authenticated metadata synchronization, durable
encrypted custody, authorized decryption on recipient devices, revocation and
conflict handling. Snapshot replication is useful groundwork, but none of those
capabilities is marked implemented by this source audit.
([Shared-link controller](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/server/src/controllers/shared-link.controller.ts))
