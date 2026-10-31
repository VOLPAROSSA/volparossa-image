# Shared VOLPAROSSA theme

This is a fixed export from `VOLPAROSSA/volparossa.github.io`. The exact reviewed
source commit, theme version and SHA-256 file inventory are in
`theme-version.json`. Keep this manifest with the copied files. No assets or
configuration are fetched at visitor runtime.

## Project integration

- Reuse `templates/header.html`, `templates/footer.html` and `templates/layout.html`.
- Load `data/navigation.json` and `data/projects.json` at build time.
- Import `site_links` and `navigation_links` from `shared/navigation.py`.
- Call `site_links(navigation, projects, homepage_url, overrides)` with a trailing
  slash on `homepage_url`. For Core, use `overrides={'core': core_canonical,
  'github': 'https://github.com/VOLPAROSSA/volparossa'}`.
- Produce `nav_links` with `navigation_links(navigation['main'], links,
  active='core', github_icon=icon)`. Produce `footer_links` using
  `navigation['footer']`, the same arguments and `footer=True`.
- Read `assets/icons/github.svg` and add decorative `aria-hidden="true"`,
  `focusable="false"`, and `class="github-icon"` to its root SVG before passing
  the icon string. Preserve the original SVG file and accompanying MIT notice.
- The template `root` variable is the project-relative prefix for **local**
  `assets/`. All common homepage URLs come from `links`; don't point a project
  site's asset URLs at the homepage's `/assets/` directory.
- Fill the layout's `title`, `description`, `canonical`, `social_image`,
  `social_alt`, `body_class`, `head_extra`, `header`, `footer` and `content`.
  Escape text attributes. `social_image` must be an absolute production URL.
- Keep the native mobile-menu markup and local `assets/site.js`. The shared
  `.button`, `.status`, focus, reduced-motion and typography styles are in
  `assets/site.css`. Add project styles separately.

`data/applications.json` selects real destinations: `publication_url` only when
`published` is true; otherwise use `repository` and visibly mark the GitHub
route. The Core project follows the same explicit publication flag in
`data/projects.json`. Enable a flag only after verifying its production site.

Original upstream SVG marks and notices are included without screenshots.
`notices/ASSETS.md` records the owning site's complete asset provenance and
brand-use conditions; files it describes outside this export are not implied to
be included. `notices/upstream-sources.json` fixes their source hashes. Preserve
original mark proportions and attribution; owner instructions do not constitute
third-party permission or endorsement. Keep a text-only fallback where required.
Font and icon licenses travel with their assets. The original GPL license is
unchanged.

## Updates

Export from a clean reviewed homepage commit:

```sh
python3 scripts/export_theme.py --source-only --output /tmp/volparossa-theme
```

Replace the vendored directory in a dedicated update, inspect the manifest and
navigation/application changes, then rebuild and test the project under its
actual repository subpath. Don't independently edit the shared navigation or
vendored components. Send common changes to the homepage repository first.
Without `--source-only`, the export also includes a `noindex` example page and
its library social image. Replace the example canonical and metadata before
publication. No CNAME, root robots policy or deployment settings are exported.
