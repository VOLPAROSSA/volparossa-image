# VOLPAROSSA Image

Follow the [shared development workflow](https://github.com/VOLPAROSSA/volparossa/blob/main/docs/development/WORKFLOW.md).

- Integrate Immich with the shared VOLPAROSSA core; do not create another peer scheduler,
  storage accounting system or identity authority in this application.
- The goal is no personally operated always-on server. A backup connector alone does not
  meet that goal. Keep live browsing, database/album state, device sync, access control and
  background processing explicitly tracked until their actual paths work.
- Photos, videos, thumbnails, EXIF/GPS, face embeddings, album names and database snapshots
  are private by default. Storage peers receive ciphertext, not keys or readable metadata.
  Never silently publish them to public cache, model training or arbitrary compute peers.
- Keep working Immich accounts/data unchanged. Never remove originals after upload without
  independently verified restoration and an explicit owner deletion request.
- Do not place an active PostgreSQL data directory on peer storage. Coordinate snapshots;
  restore into a new owner-controlled location, not over an existing installation.
- Pin upstream Immich by exact release commit; preserve its AGPL license and notices.
  Do not relabel imported upstream code as this repository's original GPL code.
- Opening the project must not trigger model/runtime downloads, installation or background
  participation. Do not change host networking.
- Task-scoped acquisition of pinned and verified sources and models is authorized
  within the workspace. Run builds and isolated tests on approved disposable
  hosted runners. Do not use untrusted executable downloads. Global installation
  or permanent changes outside the workspace require explicit user approval.
- Develop product model/runtime distribution and release updates under the core's
  pre-established authorization. Verify provenance, authenticity and integrity, enforce
  privacy and resource limits, and do not expand permissions. This does not authorize
  installation outside the workspace or make an unimplemented update facility complete.
- Disposable tests use synthetic lawful media only.
- Use targeted checks, actual integration evidence, bounded resource use and honest status.
