# Android, iPhone/iPad and web integration seams

All three are required target clients. This is an implementation map for the
exact [Immich pin](UPSTREAM.md), **not a claim that these clients already use
VOLPAROSSA**. Keep the existing Immich account and library usable while each
connection is added. Do not confuse restoring a backup with serving a live
gallery while its original owner device is offline.

## Mobile: shared Dart state, platform-specific transport

Start from the existing Flutter application's boundaries:

- [`mobile/lib/services/api.service.dart`](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/mobile/lib/services/api.service.dart)
  selects the API endpoint, discovers `/.well-known/immich`, creates the generated
  API clients and updates request headers. A local core endpoint needs explicit
  account binding here, not an untrusted peer-provided replacement URL.
- [`mobile/lib/infrastructure/repositories/network.repository.dart`](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/mobile/lib/infrastructure/repositories/network.repository.dart)
  shares native OkHttp on Android and URLSession on iOS for HTTP and WebSocket
  access. Changing only the Dart API base URL misses native image loading,
  background transfers and WebSocket traffic. Native bridges are
  `mobile/android/app/src/main/kotlin/app/alextran/immich/core/NetworkApiPlugin.kt`
  and `mobile/ios/Runner/Core/NetworkApiImpl.swift`.
- [`mobile/lib/infrastructure/repositories/sync_api.repository.dart`](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/mobile/lib/infrastructure/repositories/sync_api.repository.dart)
  consumes ordered JSON-line sync events and sends acknowledgements. Preserve
  session identity, asset/album changes and tombstones. Local state is not a
  complete authority for other users' permissions when disconnected.
- [`mobile/lib/presentation/widgets/images/remote_image_provider.dart`](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/mobile/lib/presentation/widgets/images/remote_image_provider.dart)
  selects previews and originals through native image requests. Encrypted peer
  retrieval needs a verified local decryption/read seam, with cancellation and
  size limits; private images must not become public-cache objects.

The shared background entrypoint is
[`mobile/lib/domain/services/background_worker.service.dart`](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/mobile/lib/domain/services/background_worker.service.dart).
Android uses a
[`ListenableWorker` and foreground data-sync notification](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/mobile/android/app/src/main/kotlin/app/alextran/immich/background/BackgroundWorker.kt);
iOS uses
[`BackgroundTasks`, a separate Flutter engine and completion/timeout handling](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/mobile/ios/Runner/Background/BackgroundWorker.swift).
These are resumable work opportunities, not proof that a Linux daemon can run
continuously on a phone or tablet. A mobile core port, platform key storage,
network permissions and real suspension/resumption tests are separate required
work. Participation must respect platform and resource capabilities rather than
pretend every device is an always-reachable provider.

## Web: generated SDK plus media and events

[`web/src/lib/utils/server.ts`](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/web/src/lib/utils/server.ts)
installs the SDK fetch function during application initialization.
[`packages/sdk/src/fetch-client.ts`](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/packages/sdk/src/fetch-client.ts)
is generated from OpenAPI and defaults to same-origin `/api`. Add integration
around SDK configuration, not handwritten replacements for hundreds of generated
methods. Preserve login/logout and account checks through
`web/src/lib/managers/auth-manager.svelte.ts`.

[`web/src/lib/stores/websocket.ts`](https://github.com/immich-app/immich/blob/db355f79d910bbfc6378117ed10868493c97b922/web/src/lib/stores/websocket.ts)
connects separately to `/api/socket.io`. Media requests and video ranges also need
coverage; intercepting JSON fetch alone is insufficient. A normal website cannot
connect to the existing private Unix socket. It needs an explicitly authorized,
origin-bound local application bridge, or a separately implemented browser-safe
transport. Never expose an unrestricted localhost control API, place bearer
secrets in URLs or claim a web tab remains a storage provider after closing.

## Small, real next verticals

1. Finish private snapshot capture, encrypted core storage and exact fresh-target
   restore. Prove the complete archive path separately from actual Immich
   database import and image readback.
2. Wire one real account's asset upload and original retrieval through an
   authenticated local core adapter, retaining ordinary Immich operation. Cover
   native mobile media paths and browser media/events, not just API JSON.
3. Add private encrypted asset custody plus synchronized, recipient-authorized
   metadata so a second authorized device can read while the original owner is
   offline. Persist pending writes/deletions and reconcile them on reconnect;
   do not expose the database to storage peers.
4. Complete multi-device permissions, shared albums, cancellation, mobile
   suspension/recovery and owner-controlled ML. Test real Android, iPhone/iPad
   and browser behavior before describing the no-always-on-server goal as met.

No mobile builds, signing profiles, app-store deployment, live server or native
client execution were performed for this source map.
