"""Compile complete language editions from protected source fragments."""
import json
import os
from functools import cache
from pathlib import Path
import re
import subprocess
from .book import CHAPTERS, PROTECTED, write_sources
from .locale import metadata


def typst_string(value):
    return json.dumps(value, ensure_ascii=False)


@cache
def available_fonts():
    result = subprocess.run(['typst', 'fonts'], check=True, text=True, capture_output=True)
    return set(result.stdout.splitlines())


def configuration(locale):
    data = metadata(locale)
    installed = [font for font in data['font'] if font in available_fonts()]
    if not installed or locale in ('zh-Hans', 'ko', 'ja', 'hi', 'ar') and len(installed) == 1:
        raise ValueError(f'{locale}: install the Noto fonts listed in docs/i18n/locales.json')
    fonts = ', '.join(map(typst_string, installed))
    title = data['title'] + ': ' + data['subtitle']
    return (f'title: {typst_string(title)}, running_head: {typst_string(data["title"])}, '
            f'language: {typst_string(data["language"])}, font: ({fonts},)')


def remap_assets(source, original, destination):
    """Relative reads resolve against original data, not a disposable translated directory."""
    original, destination = original.resolve(), destination.resolve()
    protected = []
    def save(match):
        protected.append(match[0])
        return f'⟦{len(protected) - 1}⟧'
    text = PROTECTED.sub(save, source)
    def asset(match):
        value = match[1]
        # Imports remain local so translated helper tables resolve to translated sources.
        # Data branches such as json(if loopback { "..." }) also contain asset literals.
        if value.startswith('/') or Path(value).suffix == '.typ':
            return match[0]
        path = (original / value).resolve()
        if not path.is_file():
            return match[0]
        target = Path(os.path.relpath(path, destination)).as_posix()
        return typst_string(target)
    text = re.sub(r'"([^"\n]+)"', asset, text)
    return re.sub(r'⟦(\d+)⟧', lambda match: protected[int(match[1])], text)


def prepare(root, locale):
    directory = root / 'docs/build/i18n' / locale
    chapters = directory / 'book'
    write_sources(root, locale, chapters)
    for name in CHAPTERS:
        path = chapters / f'{name}.typ'
        path.write_text(remap_assets(path.read_text(), root / 'docs/book', chapters))
    settings = configuration(locale)
    includes = '\n'.join(f'#include "book/{name}.typ"' for name in CHAPTERS[:15])
    main = ('#import "book/theme.typ": *\n#import "book/figures.typ": *\n'
            f'#show: book.with({settings})\n' + includes + '\n')
    # Keep the source book's chapter counter reset after its two front-matter sections.
    main = main.replace('#include "book/01_foundations.typ"',
                        '#counter(heading).update(0)\n#include "book/01_foundations.typ"')
    (directory / 'book.typ').write_text(main)
    figures = Path(os.path.relpath(root / 'docs/shared/html.typ', chapters)).as_posix()
    title = typst_string(metadata(locale)['title'])
    bundle = (f'#import "{figures}": preserve-figures\n#import "theme.typ": *\n'
              f'#document("index.html", title: {title})[\n'
              '#show: preserve-figures\n#include "../book.typ"\n]\n')
    for route, chapter in [('operations', '09_operations'), ('reference', '10_reference')]:
        bundle += (f'#document("{route}.html", title: {title})[\n'
                   f'#show: preserve-figures\n#show: book.with({settings})\n'
                   f'#include "{chapter}.typ"\n]\n')
    (chapters / 'bundle.typ').write_text(bundle)
    return directory / 'book.typ', chapters / 'bundle.typ'
