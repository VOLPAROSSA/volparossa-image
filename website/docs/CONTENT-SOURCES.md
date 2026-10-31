# Content sources and claim boundaries

Reviewed on 31 October 2026 against Image base commit
`a1472cb50be1e799823a011ef204e53a76bcd25e`. The owner's English-copy requirements
and selected composition are implemented in semantic HTML, not burned into art.

| Page content | Reviewed source | Boundary retained |
| --- | --- | --- |
| Immich foundation | [UPSTREAM](../../docs/UPSTREAM.md), [upstream lock](../../upstream.lock.json) | Immich v3.2.4, exact commit `db355f79d910bbfc6378117ed10868493c97b922`; source inspection does not prove a supported app release. |
| Snapshot contents | [SNAPSHOT](../../docs/SNAPSHOT.md) | A prepared consistent database/media copy is required; the snapshot script does not coordinate a running library. Keep originals intact. |
| Storage custody | [STORAGE_BRIDGE](../../docs/STORAGE_BRIDGE.md) | Core owns fragment placement and accounting. Participants receive ciphertext, never the owner's recovery key. |
| Recovery sequence | [SNAPSHOT_STORAGE](../../docs/SNAPSHOT_STORAGE.md) | Retrieval verifies ciphertext. Supplying the retained key and decrypting are separate operations. Trusted receipt/journal records stay independently available to the owner. A recovered archive still needs verified Immich import. |
| Devices and live library | [CLIENT_INTEGRATION](../../docs/CLIENT_INTEGRATION.md) | Android, iPhone, iPad and web are the target; live library, sync and mobile integration remain under development. No supported end-user release is claimed. |
| Scoped evidence | [README](../../README.md), [recorded workflow](https://github.com/VOLPAROSSA/volparossa-image/actions/runs/36905847039) | Synthetic archive across three providers; one offline; two local owner decrypt/restore operations; recorded deletion/cleanup. This is historical snapshot evidence, not evidence for the new adapter, mobile sync or a running restored library. |
| Privacy | [AGENTS](../../AGENTS.md), the integration documents above | Media, EXIF/GPS, faces and private metadata remain private; no automatic public cache/training. Storage encryption does not make arbitrary remote analysis private. |

Historical trial pins: Image `e177afebabd99ac0773de2a73d60275346a5de52`, Core
`cf4de524ce885af95d0f75fcb53d80254486c27f`. No runtime, network, private media or
live storage trial was run for this website task.

The device photo grids are fictional illustrations without UI controls. Their
visible `Target experience` badge and caption distinguish aspiration from
working integration. The authentic Immich screenshot is a separate, attributed
upstream example; it is not a VOLPAROSSA product capture.

## Central documentation

The missing reading path was added separately in
[homepage PR #12](https://github.com/VOLPAROSSA/volparossa.github.io/pull/12).
Commit `0856917668f26ed016ff468efea354a8e5d8a3d8` was deployed successfully in
[Pages run 41236433816](https://github.com/VOLPAROSSA/volparossa.github.io/actions/runs/41236433816).
Live `/docs/` matches the generated artifact, `#image` exists, and all six Image
reading-path destinations returned HTTP 200 before this page used the route.
See [live observations](../review/central-docs-live.json).

The central Image `published` flag is intentionally independent of documentation:
it is enabled only after the new product page is live and verified. All public
links and claims must continue to describe current implementation evidence.
