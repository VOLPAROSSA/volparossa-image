#!/usr/bin/env python3
"""Build the Image product page offline. Review previews are noindex by default."""
import argparse
import hashlib
from html import escape
import importlib.util
import json
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
THEME = ROOT / 'vendor/volparossa-theme'
DATA = json.loads((ROOT / 'src/content.json').read_text())


def render(source, values):
    def replace(match):
        key = match.group(1)
        if key not in values:
            raise ValueError('Unknown template variable: ' + key)
        return str(values[key])
    return re.sub(r'{{(\w+)}}', replace, source)


def icon(name):
    svg = (ROOT / 'assets/icons/lucide' / (name + '.svg')).read_text()
    return re.sub(r'<svg\b[^>]*>', '<svg class="image-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">', svg, count=1)


def picture(name, hero=False, fragment=False):
    group = json.loads((ROOT / 'assets/image/variants.json').read_text())[name]
    sources = []
    for kind, media in [('mobile', '(max-width: 800px)'), ('desktop', None)]:
        if kind not in group:
            continue
        items = group[kind]
        condition = f' media="{media}"' if media else ''
        sizes = '(max-width:550px) 100vw, 50vw' if fragment else '100vw'
        for ext, mime in [('avif', 'image/avif'), ('webp', 'image/webp'), ('jpg', 'image/jpeg')]:
            srcset = ', '.join(f'assets/image/{i["stem"]}.{ext} {i["width"]}w' for i in items)
            sources.append(f'<source{condition} type="{mime}" srcset="{srcset}" sizes="{sizes}" width="{items[-1]["width"]}" height="{items[-1]["height"]}">')
    fallback = group.get('desktop', group.get('mobile'))[-1]
    loading = 'fetchpriority="high"' if hero else 'loading="lazy" decoding="async"'
    return '<picture class="image-picture">' + ''.join(sources) + f'<img src="assets/image/{fallback["stem"]}.jpg" width="{fallback["width"]}" height="{fallback["height"]}" alt="" {loading}></picture>'


def canonical_url(origin, base_path):
    parts = urlsplit(origin)
    if parts.scheme not in ('http', 'https') or not parts.netloc or parts.query or parts.fragment or parts.path not in ('', '/'):
        raise ValueError('Origin must be an HTTP(S) origin without a path')
    if not base_path.startswith('/') or not base_path.endswith('/') or '..' in base_path or '?' in base_path or '#' in base_path:
        raise ValueError('Base path must be an absolute directory path with a trailing slash')
    return origin.rstrip('/') + base_path


def build(output, production, origin, base_path):
    canonical = canonical_url(origin, base_path)
    manifest = json.loads((THEME / 'theme-version.json').read_text())
    if manifest['source_commit'] != DATA['theme_commit']:
        raise SystemExit('Unexpected shared theme source')
    for name, digest in manifest['files'].items():
        if hashlib.sha256((THEME / name).read_bytes()).hexdigest() != digest:
            raise SystemExit('Changed pinned theme file: ' + name)
    output = output.resolve()
    if output == ROOT or output in ROOT.parents or any(output.is_relative_to(ROOT / p) for p in ['src', 'vendor', 'assets', 'masters', 'scripts', 'docs', 'review']):
        raise SystemExit('Output must be a dedicated build directory')
    if output.exists() and any(output.iterdir()) and not (output / '.image-website-build').exists():
        raise SystemExit('Refusing to replace a directory not owned by this builder')
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    (output / '.image-website-build').write_text('Static Image website output\n')
    shutil.copytree(THEME / 'assets', output / 'assets')
    shutil.copytree(ROOT / 'assets', output / 'assets', dirs_exist_ok=True)
    shutil.copy2(ROOT / 'src/image.css', output / 'assets/image.css')
    shutil.copy2(THEME / 'favicon.ico', output / 'favicon.ico')
    shutil.copy2(THEME / 'LICENSE', output / 'LICENSE')
    (output / '.nojekyll').touch()
    spec = importlib.util.spec_from_file_location('shared_navigation', THEME / 'shared/navigation.py')
    navigation_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(navigation_module)
    nav = json.loads((THEME / 'data/navigation.json').read_text())
    projects = json.loads((THEME / 'data/projects.json').read_text())
    links = navigation_module.site_links(nav, projects, 'https://volparossa.org/', {'github': DATA['repository']})
    github = (THEME / 'assets/icons/github.svg').read_text().replace('<svg ', '<svg class="github-icon" aria-hidden="true" focusable="false" ', 1)
    values = {**links, 'root': '', 'github_icon': github}
    # Only the breadcrumb is current. Image is not the central Applications page.
    values['nav_links'] = navigation_module.navigation_links(nav['main'], links, github_icon=github)
    values['footer_links'] = navigation_module.navigation_links(nav['footer'], links, github_icon=github, footer=True)
    values['header'] = render((THEME / 'templates/header.html').read_text(), values)
    values['footer'] = render((THEME / 'templates/footer.html').read_text(), values)
    values.update({key: escape(str(value), quote=True) for key, value in DATA.items()})
    values['canonical'] = escape(canonical, quote=True)
    values.update(hero_picture=picture('hero-lantern', True), surround_picture=picture('immich-photo-surround'), library_picture=picture('library-table'), recovery_picture=picture('recovery-workbench'), devices_picture=picture('devices-platform'), closing_picture=picture('closing-resting-fox'))
    for number in range(1, 5):
        values[f'step_{number}_picture'] = picture(f'recovery-{number}', fragment=True)
    for number in range(1, 4):
        values[f'library_{number}_picture'] = picture(f'library-{number}', fragment=True)
    names = {'photos': 'images', 'storage': 'database', 'user': 'user-round', 'key': 'key-round', 'lock': 'lock-keyhole', 'shield': 'shield-check', 'check': 'circle-check'}
    values.update({key + '_icon': icon(name) for key, name in names.items()})
    photos = [('photo-lake',210,175),('photo-coast',150,112),('photo-garden',120,82)] * 2
    values['device_gallery'] = ''.join(f'<img src="assets/image/{name}-desktop-{width}.webp" width="{width}" height="{height}" alt="" loading="lazy" decoding="async">' for name,width,height in photos)
    values['content'] = render((ROOT / 'src/index.html').read_text(), values)
    values.update(social_image=escape(canonical + 'assets/image/social.jpg', quote=True), body_class='image-page')
    robots = 'index,follow' if production else 'noindex,nofollow'
    values['head_extra'] = f'<meta name="robots" content="{robots}"><link rel="stylesheet" href="assets/image.css">'
    html = render((THEME / 'templates/layout.html').read_text(), values)
    external_arrow = '<svg class="external-arrow" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M3 13 13 3M3 3h10v10"/></svg>'
    html = re.sub(r'(>[^<>]*)↗', lambda m: m.group(1) + external_arrow, html)
    (output / 'index.html').write_text(html)
    if production:
        (output / 'sitemap.xml').write_text('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>' + escape(canonical) + '</loc></url></urlset>\n')
    print(f'Built {"production" if production else "noindex preview"}: {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'preview/volparossa-image')
    parser.add_argument('--production', action='store_true')
    parser.add_argument('--origin', default='https://volparossa.org')
    parser.add_argument('--base-path', default='/volparossa-image/')
    args = parser.parse_args()
    build(args.output, args.production, args.origin, args.base_path)
