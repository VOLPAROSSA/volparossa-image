# VOLPAROSSA Image website

The static Image page uses the Lantern hero from concept 5 and the Mosaic body
from concept 6, with the shared VOLPAROSSA design 1.0.3. It describes the current
private-snapshot integration honestly; it does not start Immich or Core.

## Build and review

Python 3 alone builds the committed sources offline. Run from the repository root:

```sh
python3 website/scripts/build_site.py
python3 website/scripts/check_site.py
python3 -m http.server 8776 --bind 127.0.0.1 --directory website/preview
```

Open <http://127.0.0.1:8776/volparossa-image/>. Review output is `noindex,nofollow`.
The builder refuses to replace a nonempty directory it does not own. Output,
optional development dependencies and full QA captures are ignored by git.

Optional browser checks use the pinned tools in this directory, not the Image
runtime package. Install with `npm ci --prefix website`, provide supported
Playwright browsers, then run:

```sh
CHROME_PATH=/usr/bin/chromium node website/scripts/browser_check.mjs
# Optional where WebKit's system libraries are already available:
QA_ENGINES=webkit QA_OUTPUT=qa/webkit node website/scripts/browser_check.mjs
```

`SITE_QA_URL` selects another served preview. No global installation is required
by the build. The browser suite records real layout, keyboard, no-JS, enlarged
text, reflow, image fallback, accessibility and resource observations.

## Production

```sh
python3 website/scripts/build_site.py --production --output website/dist/volparossa-image
python3 website/scripts/check_site.py --production --output website/dist/volparossa-image
```

The origin defaults to `https://volparossa.org`, project path `/volparossa-image/`.
Both are explicit CLI options (`--origin`, `--base-path`). Local assets stay
relative. Production includes indexable metadata and a project sitemap. It does
not include CNAME, domain robots policy, source briefs, masters or QA artifacts.

The `Image website` workflow validates pull requests and main pushes. Publishing
is a separate manual dispatch on main; it uploads only the production output.
The repository already uses GitHub Actions as the Pages source. Its project URL
is <https://volparossa.org/volparossa-image/>. No domain or host setting is changed.

The owner's current request explicitly authorizes publishing this implementation,
superseding the attached brief's older preview-only instruction. Merge after
checks, dispatch `image-website.yml` on main, verify the actual live HTML and
assets, and only then enable the Image publication flag on the central site.
Publication runs and live verification are recorded in the pull request.

## Maintenance and evidence

- [Assets, references, crops and licenses](docs/ASSETS.md)
- [Content sources and claim boundaries](docs/CONTENT-SOURCES.md)
- [Verification report and screenshots](docs/VERIFICATION.md)

The theme is a byte-verified source-only export from homepage commit
`cebc20cd25f369da9bca2d6e80f972a63f7f27a8`. Never edit vendor files to update Image.
Keep Image composition changes in `src/image.css`. Re-export a new reviewed theme
from the central repository if shared navigation or design changes are required.

Artwork exports are already committed. Maintainer regeneration requires Pillow
12.3.0 and `python3 website/scripts/export_images.py`; it is not part of the site
build. Exact generation prompts, original masters, crop coordinates, dimensions,
asset hashes and original icon geometry are retained for review.
