#!/usr/bin/env python3
"""Publish the existing Typst book, operations guide, SIDs and whitepaper together."""
from pathlib import Path
from html.parser import HTMLParser
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "docs/build/site"


class FigureCheck(HTMLParser):
    """Reject exports that retain captions but silently discard positioned artwork."""
    def __init__(self):
        super().__init__()
        self.figures = 0
        self.in_figure = False
        self.artwork = False

    def handle_starttag(self, tag, attrs):
        if tag == "figure":
            assert not self.in_figure, "unexpected nested figure"
            self.in_figure = True
            self.artwork = False
            self.figures += 1
        if tag == "svg" and self.in_figure:
            self.artwork = True

    def handle_endtag(self, tag):
        if tag == "figure":
            assert self.in_figure and self.artwork, "figure artwork missing from HTML export"
            self.in_figure = False


def check_bundle_figures(directory):
    figures = 0
    for path in directory.rglob("*.html"):
        parser = FigureCheck()
        parser.feed(path.read_text())
        parser.close()
        assert not parser.in_figure, f"unterminated figure in {path}"
        figures += parser.figures
    assert figures > 0, f"no figures exported in {directory}"
    print(f"documentation-figures: {directory.name}: {figures} preserved")


def compile_typst(source, output, bundle=False, root="."):
    output.parent.mkdir(parents=True, exist_ok=True)
    args = ["typst", "compile", "--root", root]
    if bundle:
        output.mkdir(parents=True, exist_ok=True)
        args += ["--features", "html,bundle", "--format", "bundle"]
    subprocess.run(args + [source, str(output)], cwd=ROOT, check=True)
    if bundle:
        check_bundle_figures(output)


def main():
    if SITE.exists():
        shutil.rmtree(SITE)
    SITE.mkdir(parents=True)
    compile_typst("docs/book.typ", SITE / "pdf/sibuna-book.pdf")
    compile_typst("docs/book/bundle.typ", SITE / "book", bundle=True)
    compile_typst("docs/whitepaper/whitepaper.typ", SITE / "pdf/sibuna-whitepaper.pdf")
    compile_typst("docs/whitepaper/bundle.typ", SITE / "whitepaper", bundle=True)
    compile_typst("docs/sid/bundle.typ", SITE / "sid", bundle=True, root="docs")
    shutil.copyfile(ROOT / "docs/site/index.html", SITE / "index.html")
    (SITE / ".nojekyll").touch()
    print(f"documentation-site: {SITE}")


if __name__ == "__main__":
    main()
