# Image artwork and attribution

The owner selected **only the hero from concept 5** and **the body from concept 6**.
Both chosen reference images were inspected before implementation, together with
the original VOLPAROSSA logo and the Core style reference. The current trial site
was not used as a visual reference. Reference filenames and SHA-256 hashes are in
[reference-sources.json](../review/reference-sources.json).

## Clean artwork

OpenAI image generation created six separate clean scene masters on 31 October
2026 from those owner-supplied references. Exact prompts, source reference and
original output filenames are in [generation.json](../masters/generation.json).
The masters are retained in the repository, excluded from served output. No
screenshot of a concept is used as a webpage section; titles, labels, process
arrows, numbering, links and all product copy are real HTML/SVG/CSS.

| Master | Composition | Responsive treatment |
| --- | --- | --- |
| `hero-lantern.png` | Concept 5: natural fox, brass right-facing magic lantern, projected landscapes, dark copy area | Full desktop scene, explicit mobile crop; mobile copy stacks above visible fox/projector. |
| `immich-photo-surround.png` | Concept 6 light paper, loose prints and edge foliage; empty center | Real screenshot is layered separately; crop follows the figure without bleeding behind mobile copy. |
| `library-table.png` | Concept 6 photos, open album, separate owner recovery folio and key | One desktop workbench, three ordered close crops on mobile. |
| `recovery-workbench.png` | Concept 6 dark four-step table | Four desktop groups and separate ordered mobile crops. Peer containers are opaque and closed; no keys or readable private media at participants. |
| `devices-platform.png` | Concept 6 phone, tablet and laptop on a light stone platform | Blank generated displays receive CSS-aligned fictional landscape grids. Visible target label and caption; no invented clickable UI. |
| `closing-resting-fox.png` | Concept 6 resting fox with prints on the right | Wide crossover into quiet dark copy space, explicit mobile fox crop. |

The photographic landscapes and device collection are fictional. No user's
photo library, personal data or runtime evidence was used. The privacy edge and
three small gallery crops are derivatives of the same generated masters.

[export_images.py](../scripts/export_images.py) records all pixel crop coordinates,
AVIF/WebP/JPEG settings and maximum source sizes. Exports never enlarge masters.
[asset-manifest.json](../asset-manifest.json) registers dimensions, byte sizes and
SHA-256 for every master and local asset. `assets/image/variants.json` lists every
responsive candidate. The 1200×630 social crop comes from the Lantern hero.

## Original project and upstream assets

Shared VOLPAROSSA theme 1.0.3, logo, fonts, navigation and GitHub mark are a
byte-verified export from homepage commit
`cebc20cd25f369da9bca2d6e80f972a63f7f27a8`; the vendored manifest is immutable.
Original font licenses, GPL source license and Octicons MIT notice are retained.
The owner's original logo remains a separate unmodified project asset.

The complete real Immich tag-view screenshot and original mark are reused
byte-for-byte from that same pinned homepage commit:

- [Official screenshot](https://github.com/immich-app/immich/blob/main/docs/docs/features/img/tag-view.webp): public sample architecture/scenery; complete frame resized to 900×603 upstream of this change, no private library.
- [Official mark](https://github.com/immich-app/immich/blob/main/design/immich-logo.svg): unchanged geometry and colours; text says `Immich`.
- Original source registry: [central assets](https://github.com/VOLPAROSSA/volparossa.github.io/blob/cebc20cd25f369da9bca2d6e80f972a63f7f27a8/docs/development/ASSETS.md).

AGPL attribution is retained in `assets/upstream/IMMICH-LICENSE.txt`. Source links,
brand conditions and shared-license notices remain in the theme. The screenshot
caption explicitly says the integration is in development; no affiliation,
endorsement, relicensing or completed integration is implied.

Local Lucide icons use original paths from commit
`a630cec77eac6568b989e87e4947a8bfe45caacd`. Every source URL and git blob hash is
registered in `assets/icons/lucide/source.json`; the build checker verifies exact
geometry. The original ISC license is included. No hand-redrawn gear or distorted
satellite symbol is introduced.

Public [CREDITS.txt](../assets/CREDITS.txt) links visitors to source and notices.
The root Image license and upstream AGPL separation are unchanged.
