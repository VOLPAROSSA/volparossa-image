# VOLPAROSSA Image

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
- No automatic model/runtime downloads, installation, host networking changes or background
  participation on opening the project. Disposable tests use synthetic lawful media only.
- Use targeted checks, actual integration evidence, bounded resource use and honest status.
