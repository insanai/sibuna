#!/usr/bin/env python3
"""Publish the existing Typst book, operations guide, SIDs and whitepaper together."""
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "docs/build/site"


def compile_typst(source, output, bundle=False, root="."):
    output.parent.mkdir(parents=True, exist_ok=True)
    args = ["typst", "compile", "--root", root]
    if bundle:
        output.mkdir(parents=True, exist_ok=True)
        args += ["--features", "html,bundle", "--format", "bundle"]
    subprocess.run(args + [source, str(output)], cwd=ROOT, check=True)


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
