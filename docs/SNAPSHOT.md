# Private Immich snapshot bridge

This slice packages and reconstructs a **completed, explicitly quiesced copy** of an
Immich database dump and asset directories. It does not stop Immich, produce a database
dump, establish a consistent database/filesystem snapshot, upload to peers, or start a
restored Immich installation. `--quiesced-copy` is the operator's assertion, not a proof
that the database and media describe the same instant.

## Inputs and ownership

Prepare a separate owner-controlled directory containing:

```text
quiesced-copy/
├── database.sql.gz       completed gzip-compressed SQL dump
├── upload/               and/or library/; original media
├── library/
├── profile/              optional
├── thumbs/               optional
├── encoded-video/        optional
└── backups/              optional copied backup files
```

The gzip stream must finish successfully and contain nonempty data. SQL/schema compatibility
is not assessed here. Active PostgreSQL data directories, unexpected top-level entries,
symlinks, hard-linked files, devices, FIFOs and sockets are rejected. The source root and
parents must not be symlinks. Source file opens walk directory descriptors with no-follow
checks; file identity/size/timestamps are checked while streaming, and the complete inventory
is compared again before publication. These checks detect ordinary concurrent changes, not
a malicious owner or an application-consistency mistake made before the copy.

The candidate bounds a snapshot to 100,000 entries, a 32 MiB manifest and 60 GiB of source
bytes by default; `--max-bytes` can explicitly raise the **standalone** byte bound up to 1 TiB. The same
byte bound limits decompressed database validation. Paths must fit standard UTF-8 USTAR
headers; unsupported names fail rather than being renamed. Media bytes are streamed in
64 KiB chunks, not loaded as one archive. The bounded manifest/inventory is held in memory.

The storage core accepts at most **64 GiB of ciphertext per archive**. The 60 GiB source
default leaves room for archive/encryption overhead; callers must still check the actual
`cipher_bytes` before upload. Raising the standalone limit does not raise the core limit
or split an archive automatically. The core also allows at most 256 fragments: a 16 MiB
fragment setting supports only about 4 GiB, so larger archives require an explicit larger
fragment bound. Reject an incompatible plan; never truncate media to fit.

## Create a new private bundle

Dependencies are the explicitly installed system Python 3 and GnuPG (`gpg`, `gpg-agent`,
`gpgconf`). The real targeted proof uses Debian's GnuPG 2.4.7; nothing is downloaded or
installed by this script.

```sh
python3 scripts/immich_snapshot.py create \
  --source /owner/private/quiesced-copy \
  --output /owner/private/new-snapshot \
  --quiesced-copy
```

The output's immediate parent must be an existing canonical directory owned by the current
user with mode **exactly `0700`**. Group-writable parents are rejected before creating any
staging directory, so another group member cannot replace the named private staging tree.
The output must not exist or overlap the source. Publication uses Linux
`renameat2(RENAME_NOREPLACE)`, including rejection of an existing empty directory.
The output is mode `0700`, with mode `0600` files:

- `snapshot.pgp`: standard symmetric OpenPGP encrypted with AES-256 and GnuPG's integrity
  protection. The encrypted USTAR includes the database/assets and a manifest binding every
  relative filename, type, size and SHA-256. Names and media metadata are not exported to peers.
- `recovery.key`: 32 cryptographically random bytes encoded as 64 hexadecimal characters.
  Keep an independent private recovery copy; without it the snapshot cannot be restored.
  **Never upload this key or the entire bundle to storage peers.**
- `receipt.json`: closed metadata with `version`, `kind`, `cipher_file`, `cipher_sha256`,
  `cipher_bytes`, `encryption` and `source_consistency`. No asset names or content hashes
  appear outside the encrypted manifest. This receipt is not a signed proof of its sender.

Only `snapshot.pgp` is a storage-adapter input. GnuPG receives the recovery secret through
an inherited pipe descriptor, never argv, an environment variable, stdout or a passphrase
filename. GnuPG's own standard S2K/OpenPGP implementation derives encryption keys; the
application defines no encryption primitive or custom cipher format. GnuPG compression is
disabled, as much of the input is already compressed and expansion must remain bounded.

## Restore without consuming or replacing anything

Obtain `snapshot.pgp` and the private recovery key in an owner-only bundle directory. Supply
the expected ciphertext SHA-256 from the owner or the authenticated core storage journal;
do not treat an arbitrary fetched `receipt.json` as the trust anchor.

```sh
python3 scripts/immich_snapshot.py restore \
  --bundle /owner/private/recovered-bundle \
  --expected-sha256 OWNER_VERIFIED_64_HEX_SHA256 \
  --output /owner/private/new-restored-copy
```

The operation verifies the entire ciphertext hash before decryption, then checks standard
GnuPG AES-256/MDC status and successful process exit. A bounded tar reader rejects links,
special/extended records, unsafe paths, duplicate entries, over-limit data, mismatched
manifest hashes and unexpected trailing bytes. Every output is staged privately; the new
target is published only after **all** integrity, manifest and database-gzip checks succeed.
Wrong keys, corruption, interruption and existing targets leave no published partial restore.
The archive, original files and existing installations remain unchanged. Repeated restores
do not consume the snapshot. The output is a recovery copy, not a booted or migration-tested
Immich instance; preserve the matching upstream version and follow its database restore rules.

## Temporary agent, no permanent configuration

Every operation starts one private `gpg-agent --supervised` foreground child using a socket
explicitly created for that run, with no agent autostart, smartcard daemon or external cache.
There is no use or shutdown of the user's existing agent and no modification of `HOME`,
`~/.gnupg`, system services or networking. The existing system executable is used unchanged.

GnuPG 2.4.7 computes a distinct socket directory for each temporary homedir. On a desktop
this is a fresh `/run/user/UID/gnupg/d.<hash>`; on a system without that runtime root it is
inside the temporary homedir. Because even `gpgconf --list-dirs` can create the directory,
the implementation checks the standard path before acquisition and requires exact agreement
with GnuPG afterward. SHA-1/z-base32 here is only the upstream socket filename convention,
not snapshot/key security. The parent runtime directory must already be private and owned
by the current user. Different socket-location layouts are rejected, not guessed.

Only the exact newly acquired directory and socket, with recorded device/inode and ownership,
are cleaned. The owned agent is stopped and joined before socket removal and `rmdir`; cleanup
never recursively removes a pre-existing runtime directory or kills unrelated processes.
Private temporary files are removed after success/failure. A per-operation GnuPG deadline
defaults to one hour; the CLI handles interruption through the same cleanup. Kernel/process
crashes, power loss and secure physical erasure are not claimed by this development slice.

## Evidence and remaining work

`python3 -B tests/test_snapshot.py` performs real local GnuPG encryption/decryption of a
synthetic gzip database and approximately 2 MiB of synthetic media. It verifies two complete
non-consuming restores, wrong-key rejection, ciphertext corruption including a replaced
external hash, source mutation, overwrite/link/traversal/resource rejection, owner-only modes
and exact child/runtime cleanup. No personal photos or live database are used.

Peer storage durability, redundant fragment recovery, original Immich database import,
mobile sync, native UI and server-independent operation require their own real integration
proofs. This local archive result does not complete any of those paths.

Primary implementation references:
[GnuPG 2.4.7 foreground socket activation](https://github.com/gpg/gnupg/blob/gnupg-2.4.7/agent/gpg-agent.c),
[GnuPG 2.4.7 socket-directory selection](https://github.com/gpg/gnupg/blob/gnupg-2.4.7/common/homedir.c),
[Immich backup and restore](https://docs.immich.app/administration/backup-and-restore/).
