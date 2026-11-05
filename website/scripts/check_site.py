#!/usr/bin/env python3
"""Offline checks for the actual nested project artifact, assets and metadata."""
import argparse
import gzip
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = []
        self.assets = []
        self.images = []
        self.headings = []
        self.errors = []
        self.tags = []
        self.canonical = self.og_url = self.robots = ''

    def handle_starttag(self, tag, pairs):
        a = dict(pairs)
        self.tags.append(tag)
        if 'id' in a:
            if a['id'] in self.ids:
                self.errors.append('Duplicate ID: '+a['id'])
            self.ids.add(a['id'])
        if tag in ('h1','h2','h3'):
            self.headings.append(tag)
        if tag == 'html' and a.get('lang') != 'en':
            self.errors.append('Document language must be English')
        if 'href' in a:
            self.links.append(a['href'])
        if 'src' in a:
            self.assets.append(a['src'])
        if 'srcset' in a:
            self.assets.extend(x.strip().split()[0] for x in a['srcset'].split(','))
        if tag == 'img':
            self.images.append(a)
            for key in ('alt','width','height'):
                if key not in a:
                    self.errors.append('Image missing '+key)
        if tag == 'link' and a.get('rel') == 'canonical':
            self.canonical = a['href']
        if tag == 'meta' and a.get('property') == 'og:url':
            self.og_url = a['content']
        if tag == 'meta' and a.get('name') == 'robots':
            self.robots = a['content']


def check(output, production, origin='https://volparossa.org', base_path='/volparossa-image/'):
    html = (output/'index.html').read_text()
    page = Page(); page.feed(html)
    data = json.loads((ROOT/'src/content.json').read_text())
    errors = page.errors
    expected = origin.rstrip('/') + base_path
    if page.canonical != expected or page.og_url != expected:
        errors.append('Incorrect canonical/Open Graph project path')
    if page.robots != ('index,follow' if production else 'noindex,nofollow'):
        errors.append('Wrong preview/publication indexing')
    if (output/'sitemap.xml').exists() != production:
        errors.append('Only the explicit production build should include a sitemap')
    if production and '<loc>'+expected+'</loc>' not in (output/'sitemap.xml').read_text():
        errors.append('Wrong sitemap route')
    if page.headings.count('h1') != 1 or any(tag not in page.tags for tag in ['header','main','footer','nav']):
        errors.append('Heading or landmark structure is missing')
    for ident in ['main','top','immich','library','how-it-works','devices','privacy','development','contribute']:
        if ident not in page.ids:
            errors.append('Missing section anchor '+ident)
    for path in page.links + page.assets:
        url = urlsplit(path)
        if url.scheme or url.netloc:
            continue
        if url.path.startswith('/'):
            errors.append('Root-relative local URL breaks independent project prefix: '+path)
            continue
        target = (output / unquote(url.path or 'index.html')).resolve()
        if not target.is_relative_to(output.resolve()) or not target.is_file():
            errors.append('Missing or escaping local file: '+path)
        if (not url.path or url.path == 'index.html') and url.fragment and unquote(url.fragment) not in page.ids:
            errors.append('Missing anchor: '+path)
    for path in page.assets:
        if urlsplit(path).scheme:
            errors.append('External runtime asset: '+path)
    for p in output.rglob('*.css'):
        for name in re.findall(r'url\([\'\"]?([^\)\'\"]+)',p.read_text()):
            if not name.startswith('data:') and not (p.parent/name).is_file():
                errors.append('Missing CSS asset: '+name)
    for forbidden in ['CNAME','robots.txt','AGENTS.md','BUILD-INSTRUCTIONS.txt','ASSET-BRIEF.txt','package.json']:
        if (output/forbidden).exists():
            errors.append('Non-public or domain-level file in output: '+forbidden)
    if list(output.rglob('*.png')) and any('masters' in p.parts for p in output.rglob('*')):
        errors.append('Masters shipped in public output')
    if '{{' in html or '<form' in html:
        errors.append('Unresolved template or misleading interactive form')
    asset_manifest = json.loads((ROOT/'asset-manifest.json').read_text())
    for name, record in asset_manifest['files'].items():
        source = ROOT/name
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != record['sha256']:
            errors.append('Asset provenance hash differs: '+name)
    icons = ROOT/'assets/icons/lucide'
    for item in json.loads((icons/'source.json').read_text())['files']:
        raw = (icons/item['file']).read_bytes()
        blob = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if blob != item['git_blob']:
            errors.append('Lucide source geometry changed: '+item['file'])
    theme = ROOT/'vendor/volparossa-theme'
    manifest = json.loads((theme/'theme-version.json').read_text())
    for name, digest in manifest['files'].items():
        if hashlib.sha256((theme/name).read_bytes()).hexdigest() != digest:
            errors.append('Modified pinned theme file: '+name)
    for asset in ['site.css','site.js','tokens.css','logo.png','upstream/immich.svg']:
        if (output/'assets'/asset).read_bytes() != (theme/'assets'/asset).read_bytes():
            errors.append('Shared asset changed during build: '+asset)
    code_bytes = len(gzip.compress(html.encode(),mtime=0)) + sum(len(gzip.compress(p.read_bytes(),mtime=0)) for p in (output/'assets').glob('*') if p.suffix in ['.css','.js'])
    if code_bytes > 150_000:
        errors.append('HTML/CSS/JavaScript exceeds 150 KB gzip')
    for name, budget in [('hero-lantern-mobile-768.webp',500_000),('hero-lantern-desktop-1774.webp',1_000_000)]:
        if (output/'assets/image'/name).stat().st_size > budget:
            errors.append('Hero byte budget exceeded: '+name)
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'PASS: nested project paths, anchors, metadata, images, pinned theme, local assets; HTML/CSS/JS gzip {code_bytes:,} bytes')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, default=ROOT/'preview/volparossa-image')
    p.add_argument('--production', action='store_true')
    p.add_argument('--origin', default='https://volparossa.org')
    p.add_argument('--base-path', default='/volparossa-image/')
    a = p.parse_args(); check(a.output, a.production, a.origin, a.base_path)
