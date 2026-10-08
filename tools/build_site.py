#!/usr/bin/env python3
"""Publish the existing Typst book, operations guide, SIDs and whitepaper together."""
from pathlib import Path
from html.parser import HTMLParser
import shutil
import json
import hashlib
import subprocess
from site_html import decorate, inventory
from i18n.build import prepare
from i18n.locale import LOCALES, source_revision
from i18n.readme import render, FILENAMES
from i18n.tables import check_bundle as check_tables

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "docs/build/site"


class FigureCheck(HTMLParser):
    """Reject exports that retain captions but silently discard positioned artwork."""
    def __init__(self):
        super().__init__()
        self.figures = 0
        self.in_figure = False
        self.artwork = False
        self.captions = 0

    def handle_starttag(self, tag, attrs):
        if tag == "figure":
            assert not self.in_figure, "unexpected nested figure"
            self.in_figure = True
            self.artwork = False
            self.figures += 1
            self.captions = 0
        if tag == "svg" and self.in_figure:
            self.artwork = True
        if tag == "figcaption" and self.in_figure:
            self.captions += 1
            assert self.captions == 1, "duplicate or nested figure caption"

    def handle_endtag(self, tag):
        if tag == "figure":
            assert self.in_figure and self.artwork, "figure artwork missing from HTML export"
            assert self.captions == 1, "figure caption missing from HTML export"
            self.in_figure = False


def check_bundle_figures(directory):
    figures = 0
    pages = {}
    for path in directory.rglob("*.html"):
        parser = FigureCheck()
        parser.feed(path.read_text())
        parser.close()
        assert not parser.in_figure, f"unterminated figure in {path}"
        figures += parser.figures
        pages[path.relative_to(directory).as_posix()] = parser.figures
    assert figures > 0, f"no figures exported in {directory}"
    print(f"documentation-figures: {directory.name}: {figures} preserved")
    return pages


def compile_typst(source, output, bundle=False, root="."):
    output.parent.mkdir(parents=True, exist_ok=True)
    args = ["typst", "compile", "--root", root]
    if bundle:
        output.mkdir(parents=True, exist_ok=True)
        args += ["--features", "html,bundle", "--format", "bundle"]
    subprocess.run(args + [source, str(output)], cwd=ROOT, check=True)
    if bundle:
        return check_bundle_figures(output)


def compile_sid_pdfs():
    # Bundle outlines query every record and share heading counters. Compile each
    # downloadable PDF in its own document, matching the standalone `sid` build.
    for page in inventory(SITE, ROOT):
        if page["group"] == "sid" and "pdf" in page:
            compile_typst(page["source"], SITE / page["pdf"])


def check_animation_assets():
    """Ordinary documentation builds need neither npm nor a network dependency fetch."""
    manifest = json.loads((ROOT / "docs/site/admission-assets.json").read_text())
    for name, expected in manifest["files"].items():
        data = (ROOT / "docs/site" / name).read_bytes()
        assert len(data) == expected["bytes"], f"stale animation asset: {name}"
        assert hashlib.sha256(data).hexdigest() == expected["sha256"], name


def compile_language_editions(reference_figures):
    for locale, meta in LOCALES.items():
        if locale == "en":
            continue
        readme = ROOT / f"README.{FILENAMES[locale]}.md"
        assert readme.read_text() == render(ROOT, locale), f"stale README edition: {locale}"
        source, bundle = prepare(ROOT, locale)
        directory = SITE / meta["prefix"]
        compile_typst(str(source), directory / "pdf/sibuna-book.pdf")
        figures = compile_typst(str(bundle), directory / "book", bundle=True)
        assert figures == reference_figures, f"{locale}: figures differ from the English book"
        check_tables(SITE / "book", directory / "book")
        (directory / "source-revision.json").write_text(
            json.dumps(source_revision(ROOT), indent=2) + "\n")


def main():
    check_animation_assets()
    if SITE.exists():
        shutil.rmtree(SITE)
    SITE.mkdir(parents=True)
    compile_typst("docs/book.typ", SITE / "pdf/sibuna-book.pdf")
    figures = compile_typst("docs/book/bundle.typ", SITE / "book", bundle=True)
    compile_typst("docs/whitepaper/whitepaper.typ", SITE / "pdf/sibuna-whitepaper.pdf")
    compile_typst("docs/whitepaper/bundle.typ", SITE / "whitepaper", bundle=True)
    compile_typst("docs/sid/bundle.typ", SITE / "sid", bundle=True, root="docs")
    compile_sid_pdfs()
    compile_language_editions(figures)
    (SITE / "assets").mkdir()
    for name in ("site.css", "site.js", "site-i18n.css", "site-language.js", "favicon.svg",
                 "admission-demo.css", "admission-model.js",
                 "admission-animation.js", "admission-scene.bundle.js", "three-LICENSE.txt"):
        shutil.copyfile(ROOT / "docs/site" / name, SITE / "assets" / name)
    decorate(SITE, ROOT)
    (SITE / ".nojekyll").touch()
    print(f"documentation-site: {SITE}")


if __name__ == "__main__":
    main()
