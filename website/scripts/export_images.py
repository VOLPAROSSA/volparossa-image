#!/usr/bin/env python3
"""Maintainer exports using Pillow 12.3.0; never required by the site build."""
import argparse
import hashlib
import json
from pathlib import Path
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'assets/image'
# All coordinates are in untouched master pixels. No generated letters or UI.
COMPOSITIONS = {'hero-lantern': {'master': 'hero-lantern', 'desktop': ((0, 0, 1774, 887), [960, 1440, 1774]), 'mobile': ((350, 100, 1774, 887), [480, 768])}, 'immich-photo-surround': {'master': 'immich-photo-surround', 'desktop': ((530, 0, 1774, 887), [960, 1244]), 'mobile': ((530, 0, 1774, 887), [480, 768])}, 'library-table': {'master': 'library-table', 'desktop': ((0, 240, 1774, 820), [960, 1440, 1774])}, 'library-1': {'master': 'library-table', 'desktop': ((0, 300, 560, 800), [480, 560])}, 'library-2': {'master': 'library-table', 'desktop': ((530, 295, 1315, 795), [480, 768])}, 'library-3': {'master': 'library-table', 'desktop': ((1290, 285, 1774, 800), [480])}, 'recovery-workbench': {'master': 'recovery-workbench', 'desktop': ((0, 220, 2036, 760), [960, 1600, 2036])}, 'recovery-1': {'master': 'recovery-workbench', 'desktop': ((0, 245, 570, 715), [480, 570])}, 'recovery-2': {'master': 'recovery-workbench', 'desktop': ((570, 245, 1010, 715), [440])}, 'recovery-3': {'master': 'recovery-workbench', 'desktop': ((1020, 235, 1475, 705), [455])}, 'recovery-4': {'master': 'recovery-workbench', 'desktop': ((1470, 235, 2036, 715), [480, 566])}, 'devices-platform': {'master': 'devices-platform', 'desktop': ((0, 0, 1774, 887), [960, 1440, 1774])}, 'closing-resting-fox': {'master': 'closing-resting-fox', 'desktop': ((0, 0, 1942, 809), [960, 1440, 1942]), 'mobile': ((970, 0, 1942, 809), [480, 768])}, 'photo-lake': {'master': 'library-table', 'desktop': ((650, 390, 860, 565), [210])}, 'photo-coast': {'master': 'immich-photo-surround', 'desktop': ((1040, 82, 1190, 194), [150])}, 'photo-garden': {'master': 'immich-photo-surround', 'desktop': ((1620, 340, 1740, 422), [120])}}
COMPOSITIONS['privacy-edge'] = {'master':'immich-photo-surround','desktop':((1500,0,1774,887),[274])}


def inventory():
    manifest = {'compositions': COMPOSITIONS, 'social_crop': [84, 0, 1774, 887], 'files': {}}
    for directory in [ROOT / 'masters', ROOT / 'assets']:
        for p in sorted(directory.rglob('*')):
            if not p.is_file():
                continue
            record = {'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
            if p.suffix in ['.png', '.jpg', '.webp', '.avif']:
                with Image.open(p) as im:
                    record['width'], record['height'] = im.size
            manifest['files'][p.relative_to(ROOT).as_posix()] = record
    (ROOT / 'asset-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


def export():
    OUT.mkdir(parents=True, exist_ok=True)
    # Remove only obsolete variants listed by our previous export manifest.
    previous = json.loads((OUT / 'variants.json').read_text()) if (OUT / 'variants.json').exists() else {}
    planned = {f'{name}-{kind}-{width}' for name, plan in COMPOSITIONS.items()
               for kind in ['desktop', 'mobile'] if kind in plan for width in plan[kind][1]}
    for composition in previous.values():
        for entries in composition.values():
            for entry in entries:
                stem = entry['stem']
                if stem not in planned and Path(stem).name == stem:
                    for suffix in ['.avif', '.webp', '.jpg']:
                        (OUT / (stem + suffix)).unlink(missing_ok=True)
    variants = {}
    for name, plan in COMPOSITIONS.items():
        source = Image.open(ROOT / 'masters' / (plan['master'] + '.png')).convert('RGB')
        variants[name] = {}
        for kind in ['desktop', 'mobile']:
            if kind not in plan:
                continue
            box, widths = plan[kind]
            crop = source.crop(box)
            variants[name][kind] = []
            for width in widths:
                assert width <= crop.width, 'Do not enlarge source pixels'
                size = (width, round(width * crop.height / crop.width))
                image = crop.resize(size, Image.Resampling.LANCZOS)
                stem = f'{name}-{kind}-{width}'
                image.save(OUT / (stem + '.avif'), quality=57, speed=6)
                image.save(OUT / (stem + '.webp'), quality=83, method=6)
                image.save(OUT / (stem + '.jpg'), quality=84, optimize=True, progressive=True)
                variants[name][kind].append({'stem': stem, 'width': size[0], 'height': size[1]})
    hero = Image.open(ROOT / 'masters/hero-lantern.png').convert('RGB').crop((84, 0, 1774, 887))
    hero.resize((1200, 630), Image.Resampling.LANCZOS).save(OUT / 'social.jpg', quality=85, optimize=True)
    (OUT / 'variants.json').write_text(json.dumps(variants, indent=2) + '\n')
    inventory()
    print('Exported responsive scenes and registered dimensions, crops and hashes.')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory-only', action='store_true')
    args = p.parse_args()
    inventory() if args.inventory_only else export()
