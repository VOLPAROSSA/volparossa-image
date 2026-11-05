# Asset and rights register — 30 October 2026

The supplied mockups are design references, never a page-sized screenshot with
hotspots. All headings, copy, buttons and status labels are semantic HTML.
`02-applications-worktable-FINAL.png` takes precedence over section 2 in reference
01. Original logo files remain unchanged. The owner-requested illustration edit uses
the supplied emblem as the reference for a physical gold print on the mug.

## VOLPAROSSA artwork

| Shipped assets | Provenance and transformation |
| --- | --- |
| `assets/logo-original.png` | Exact pixel/alpha content of supplied `03-volparossa-logo-original.png`, 853×853 RGBA. Original retained. |
| `assets/logo.png`, `assets/favicon.png`, `favicon.ico` | Technical resizes only; shape, colour and transparency preserved. |
| `assets/library/hero-*` | New clean image generation from the top library scene in reference 01. Separate portrait mobile composition preserves the arch and resting fox. |
| `assets/library/worktable-*`, `{code,image,cloud}-mobile.*` | New clean image generation from reference 02; blank device displays. Owner-requested image edit adds a gold VOLPAROSSA emblem to the ceramic mug. The lossless 1536×710 `worktable-master.png` retains the edited scene for future exports; WebP/JPEG desktop and mobile variants use the existing coordinates. Interface layers remain separate. |
| `assets/library/shared-*` | New clean generation of reference 01's cooperative reading table. |
| `assets/library/chapter-*` | New clean generation of reference 01's closing fox balcony. |
| `assets/social.jpg` | 1200×630 technical crop of the new hero. |

Artwork was generated with OpenAI image generation on 30 October 2026. The
original generation prompts requested the approved composition/materials, no
text or logos, and empty device displays. Optimized AVIF (hero), WebP/JPEG variants and
mobile crops are committed; generation is not a visitor runtime dependency.
The subsequent mug edit used the original logo and worktable as image-generation
references; it is baked into the illustration, with no link or HTML logo overlay.
No stock image substitutes the library. No private files or visitor data are used.

## Interface images

Original upstream SVGs and license notices retain their original bytes and line
endings. Narrow .gitattributes rules exempt only those vendor files from whitespace
normalization/checking; authored HTML, CSS, scripts and documentation remain checked.

The source bytes were fetched from official public repositories and matched to
GitHub's blob hashes. Exact URLs, source SHA-256 and Git blob IDs are recorded
in [upstream-sources.json](upstream-sources.json). Public display is explicitly
labelled as upstream examples, never evidence of a completed integration.

| Local file | Official source | Treatment and boundaries |
| --- | --- | --- |
| `assets/upstream/code-screen.webp` | [OpenCode terminal screenshot](https://github.com/anomalyco/opencode/blob/dev/packages/web/src/assets/lander/screenshot.png) | Cropped window padding, resized. Actual upstream TUI and its public sample task, not the mockup's invented editor. MIT notice retained as `OPENCODE-LICENSE.txt`. |
| `assets/upstream/image-screen.webp` | [Immich public sample library](https://github.com/immich-app/immich/blob/main/docs/docs/features/img/tag-view.webp) | Complete official tag-view screenshot; sample architecture and scenery, no private user library. Resized to 900×603 without cropping. AGPL notice retained as `IMMICH-LICENSE.txt`. |
| `assets/upstream/cloud-screen.webp` | [OpenCloud Files documentation](https://github.com/opencloud-eu/docs/blob/main/docs/user/files-and-folders/img/favorites/favorites-personal.png) | Public sample favourites grid; crop (8,61)–(1272,711) omits the profile header and outer frame, retaining all three files, navigation and status; resized to 1000×514. Source: OpenCloud GmbH. AGPL documentation notice retained as `OPENCLOUD-DOCS-LICENSE.txt`. |

Screenshot excerpting and technical resampling do not create new software
functionality. The screens are decorative demonstrations of the tool category;
all relevant application information is available in the neighbouring HTML.
Upstream component licenses remain separate from the website's GPL license.

## Marks and public-use decisions

| Mark | Source and review | Public build |
| --- | --- | --- |
| OpenCode | [Brand page](https://opencode.ai/brand) and official `packages/console/app/src/asset/brand/opencode-logo-light.svg`. The page's current source and English strings expose downloadable assets; no partnership is implied. Direct brand-page HTTP access returned 403 here, so its official GitHub source was inspected. | Original SVG, unmodified aspect/colour, attribution. |
| Immich | Original `design/immich-logo.svg`. [Current FAQ](https://docs.immich.app/FAQ/) was checked through official `docs/docs/FAQ.mdx` after direct HTTP returned 403. It discusses commercial integration notification, prohibits reseller marketing marks and rejects implied affiliation. It is not blanket permission for this website's promotional logo use. | Original supplied SVG displayed with “Built on Immich”, per the owner’s follow-up request; no recolouring or tracing. |
| OpenCloud | Original supplied SVG with protective space, from [press assets](https://opencloud.eu/en/about-us/press). [Terms](https://opencloud.eu/en/press/terms-of-use) fetched successfully: source attribution; no logo modification; prior written consent for commercial use. | Original supplied SVG displayed with “Built on OpenCloud”, per the owner’s follow-up request; protective space and attribution retained. |

The owner explicitly requested the missing Immich and OpenCloud logos in the
follow-up desktop correction. That request supersedes the attachment's default
text-only publication choice. It is an instruction to display the original marks,
not evidence of third-party permission. No permission, partnership or endorsement
is claimed, and no external party has been contacted. Keep the cited conditions
visible in this register: any commercial use of OpenCloud visual material still
requires the prior written consent described in its terms, and Immich's commercial
integration/reseller conditions still apply. `--text-brands` provides a clean
fallback for a publication context that requires text-only attribution.

## GitHub navigation mark

`assets/icons/github.svg` is the unchanged `mark-github-16.svg` from
[GitHub Primer Octicons](https://github.com/primer/octicons/blob/main/icons/mark-github-16.svg).
The [MIT notice](../../assets/icons/OCTICONS-LICENSE.txt) accompanies the asset and
is copied with the shared theme export. The builder embeds the original path,
adding decorative accessibility attributes; CSS uses the surrounding link colour.
It precedes the GitHub label in desktop/mobile navigation and the footer. No
external icon service or font is loaded, and link names remain readable text.

## Fonts

- Cormorant Garamond, normal 400, Latin WOFF2, by Christian Thalmann.
- Inter, normal 400, Latin WOFF2, by Rasmus Andersson.

Files were downloaded from Fontsource's public CDN to `assets/fonts/` and are
served locally. The matching SIL Open Font License notices are stored beside
them. No other font weights or runtime font service are loaded. Source URLs:
`https://cdn.jsdelivr.net/fontsource/fonts/{cormorant-garamond,inter}@latest/latin-400-normal.woff2`;
notices from `https://cdn.jsdelivr.net/npm/@fontsource/{name}@latest/LICENSE`.
The committed bytes are fixed; future visitors do not follow the `latest` alias.

[asset-manifest.json](asset-manifest.json) records shipped image/font hashes and
byte sizes. The original repository GPL-3.0-only `LICENSE` remains unchanged.
Historical prototype-art provenance is retained in the README and Git history.
