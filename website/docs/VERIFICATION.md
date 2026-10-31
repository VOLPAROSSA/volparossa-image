# Website verification — 31 October 2026

Image base: `a1472cb50be1e799823a011ef204e53a76bcd25e`.
Shared theme: 1.0.3 from homepage
`cebc20cd25f369da9bca2d6e80f972a63f7f27a8`.
Scope: static product website, its assets, review evidence and separate workflow.
No runtime, model, private library, host network or storage behavior was changed.

## Build and links

Preview and production build/check pass. Two preview builds produce identical
SHA-256 contents across 151 output files. Alternate origin/base path
`https://preview.example.org/nested/image/` passes the same artifact checks.
Python 3 builds offline from committed files. The actual served preview path is
`/volparossa-image/`, not the server root.

Checks cover local paths and anchors, English language, one H1, landmarks,
metadata, production sitemap, noindex previews, image dimensions, local fonts,
notices, pinned theme hashes and original Lucide geometry. Only visitor files
enter the production output; no masters, source briefs, packages, CNAME or root
robots policy. All 15 external page destinations returned HTTP 200.

The central `docs/#image` route was published separately and its actual anchor,
six document links and deployed HTML verified before using it in this page.
See [build results](../review/build-results.json),
[external links](../review/external-links.json) and
[central documentation observations](../review/central-docs-live.json).

## Browser and visual checks

The optional browser script passes 13 profiles using Chromium 154 and Playwright
Firefox. Browser resources are local, without external subresource requests.

- Chromium: 320×740, 390×844, 768×1024, 1440×900, 1920×1080 and 844×390 landscape.
- Firefox: 390×844, 1440×900 and 2560×1440.
- No JS at 390px; 200% root text at 1440px; 400% reflow equivalent (1440×900
  reduced to 360×225 CSS pixels); raster images disabled.
- No horizontal overflow, header overlap, missing visible images, console errors
  or failed requests in normal runs. All four process steps remain in DOM order.
- Skip link reaches main, visible focus, native menu, Escape/outside click,
  no-JS disclosure and reduced-motion behavior pass.
- Zero axe WCAG A/AA, 2.1 AA and 2.2 AA violations at 390 and 1440px.

Actual decoded exports were inspected in desktop/mobile screenshots, including
the 2560px Firefox render. Review checked crop, natural fox anatomy, projector
visibility, complete authentic screenshot, screen alignment, reading order,
contrast, image descriptions and keyboard focus. Initial mobile decoration
behind copy and the wide-screen device text overlap were corrected. The large
scene and the text share the same maximum width, keeping the phone unobscured.

The hero uses concept 5's fox/projector scene. Every following artwork follows
concept 6's light photo setting, library table, dark archive workbench, device
platform, restrained privacy band and resting-fox closing. The full evidence and
scope copy require more height than the concept's shortened labels. The upstream
Immich screenshot intentionally replaces the concept's invented interface.

WebKit was attempted but could not launch: the host lacks GTK4, Graphene,
Harfbuzz ICU, Manette, Hyphen and GLES libraries. No global packages or host
configuration were changed. Physical Safari/iOS and literal browser-UI zoom were
not tested. Automated accessibility is not a certification.

[Desktop](../review/firefox-1440-full.webp) ·
[Mobile](../review/firefox-390-full.webp) ·
[Wide desktop](../review/firefox-2560-full.webp) ·
[Browser observations](../review/browser-results.json)

## Performance

Lighthouse 13.6.0, Chromium 154 headless/Linux, Python loopback server, default
simulated mobile throttling. This is a local lab measurement, not field data.

| Metric | Result |
| --- | ---: |
| Performance | 98 |
| Accessibility | 100 |
| Best practices | 100 |
| First contentful paint | 1.2 s |
| Largest contentful paint | 2.3 s |
| Total blocking time | 0 ms |
| Cumulative layout shift | 0.0000233 |
| Lighthouse measured transfer | 394 KiB |

Browser Resource Timing at 390px/DPR 1 records 290,991 initial bytes, including
HTML, fonts, CSS, JS, hero and nearby requested lazy images. Local fonts transfer
47,140 bytes. After complete scrolling, images transfer 296,454 bytes on mobile
and 551,544 bytes at 1920px. HTML/CSS/JS total 18,959 bytes gzip in production.
The local server does not compress text. These are actual selected derivatives,
not the combined size of every exported format. All specified budgets are met.

[Lighthouse settings and metrics](../review/lighthouse-summary.json)

## Repository checks and publication

The existing synthetic source contracts are run unchanged with Node 24.19.0 and
standard `umask 022`, matching the hosted runner. The first local run inherited
`umask 077`, making its intentionally exposed 0755 test directory private and
causing one expected-rejection assertion to fail; no product code was changed to
alter this test. All 61 source contracts pass with standard permissions. Hosted results are
recorded in the PR. No new GnuPG round trip or heavy Immich/storage trial was necessary.

All five workflow Actions pins were compared with their official tag refs on
31 October 2026. PR validation has read-only contents permission; the separate
manual main-only deploy job has only Pages write and OIDC permissions. The Pages
API reports the existing workflow source and intended project URL, without CNAME.

The owner's current request explicitly authorizes publication. After successful
hosted checks, merge and dispatch the production workflow, compare live HTML and
loaded asset bytes, and inspect live desktop/mobile renders. Enable the central
Image product link only after that verification. The PR records actual release
runs and live observations; this source report records the prepublication checks.
