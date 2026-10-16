#!/usr/bin/env python3
"""Build the Sibuna website for GitHub Pages at https://insanai.github.io/sibuna/.

    python3 docs/site/build.py [--out DIR] [--no-build]

The site has four parts, served under /sibuna/:

    /sibuna/              the landing page (docs/site/index.html and the admission demo)
    /sibuna/book/         The Sibuna Book, `guidedog build html` of docs/book
    /sibuna/whitepaper/   the whitepaper, `guidedog build html` of docs/whitepaper
    /sibuna/sid/          the Sibuna Discussions, `guidedog dsc build` of docs/sid
    /sibuna/pdf/          the book and whitepaper as PDF; /sibuna/sid/pdf/ holds one per record

Guidedog writes each project into its own _build folder; this script copies the results,
adds the site's links to the header of every documentation page, wraps the landing page
in the site's shell, and checks every local link and anchor. It needs guidedog on PATH
and nothing else beyond the Python standard library. --no-build reuses the _build folders.
The default output is target/site.
"""
from html import escape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit
import argparse
import hashlib
import json
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs/site"
BASE = "/sibuna/"
REPO = "https://github.com/insanai/sibuna"
# The workspace version; the landing page must name it (a release bump updates index.html).
VERSION = re.search(r'^version = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M)[1]
DESCRIPTION = ("Sibuna: self-hosted web protection with browser proof of work"
               " and an optional console.")
# Files the landing page loads, copied to /sibuna/assets/.
ASSETS = ("site.css", "favicon.svg", "admission-demo.css", "admission-model.js",
          "admission-animation.js", "admission-scene.bundle.js", "three-LICENSE.txt")
# The documentation bundles: site folder, guidedog project, PDF built from it.
BUNDLES = (("book", "docs/book", "the-sibuna-book-en.pdf", "sibuna-book.pdf"),
           ("whitepaper", "docs/whitepaper", "sibuna-whitepaper-en.pdf",
            "sibuna-whitepaper.pdf"))
NAVIGATION = (("Home", ""), ("Book", "book/"), ("Operations", "book/operations.html"),
              ("Whitepaper", "whitepaper/"), ("SIDs", "sid/"))


def run(args, cwd):
    print("+", " ".join(args), f"(in {cwd.relative_to(ROOT)})", flush=True)
    subprocess.run(args, cwd=cwd, check=True)


def build_documents():
    """Fresh guidedog builds; warnings fail the build, as `guidedog dsc build` does."""
    for _, project, _, _ in BUNDLES:
        for builder in ("html", "pdf"):
            run(["guidedog", "build", "-E", "-a", "-W", "-q", builder], ROOT / project)
    run(["guidedog", "dsc", "build"], ROOT / "docs/sid")


def check_animation_assets():
    """The bundled 3D scene is checked in; its manifest records how it was made."""
    manifest = json.loads((SOURCE / "admission-assets.json").read_text())
    for name, expected in manifest["files"].items():
        data = (SOURCE / name).read_bytes()
        assert len(data) == expected["bytes"], f"stale animation asset: {name}"
        assert hashlib.sha256(data).hexdigest() == expected["sha256"], f"changed: {name}"


def site_links(route, pdf):
    """The list items added to a guidedog header: the site sections, a PDF and GitHub."""
    section = route if route == "book/operations.html" else route.split("/")[0] + "/"
    items = []
    for label, target in NAVIGATION:
        mark = ' aria-current="page"' if target == section else ""
        items.append(f'<li><a href="{BASE}{target}"{mark}>{label}</a></li>')
    if pdf:
        items.append(f'<li><a href="{BASE}{pdf}">PDF</a></li>')
    items.append(f'<li><a href="{REPO}">GitHub</a></li>')
    return '<ul class="rellinks">' + "".join(items) + "</ul>"


def record_pdf(site, route):
    """The PDF of a SID record: sid/records/NNNN-name.html has sid/pdf/sid-NNNN-name-en.pdf."""
    match = re.fullmatch(r"sid/records/(.+)\.html", route)
    if not match:
        return None
    pdf = f"sid/pdf/sid-{match[1]}-en.pdf"
    return pdf if (site / pdf).is_file() else None


def decorate_bundle(site, folder, pdf):
    """Put the site's links into the empty link list of every guidedog header."""
    empty = re.compile(r'<ul class="rellinks">\s*</ul>')
    for path in sorted((site / folder).rglob("*.html")):
        route = path.relative_to(site).as_posix()
        text = path.read_text()
        found = len(empty.findall(text))
        assert found == 1, f"{route}: expected one empty header link list, found {found}"
        links = site_links(route, record_pdf(site, route) or pdf)
        text = empty.sub(lambda _: links, text)
        if 'rel="icon"' not in text:
            text = text.replace("</head>", f'<link rel="icon" type="image/svg+xml" '
                                f'href="{BASE}assets/favicon.svg">\n</head>', 1)
        path.write_text(text)


def copy_bundles(site):
    (site / "pdf").mkdir(parents=True)
    for folder, project, built, published in BUNDLES:
        shutil.copytree(ROOT / project / "_build/html", site / folder)
        shutil.copyfile(ROOT / project / "_build/pdf" / built, site / "pdf" / published)
        decorate_bundle(site, folder, f"pdf/{published}")
    shutil.copytree(ROOT / "docs/sid/_build/html", site / "sid")
    (site / "sid/pdf").mkdir()
    for pdf in sorted((ROOT / "docs/sid/_build/pdf").glob("*.pdf")):
        shutil.copyfile(pdf, site / "sid/pdf" / pdf.name)
    decorate_bundle(site, "sid", None)


def shell(title, body):
    """The landing page's document: header, the body, and the footer."""
    nav = "".join(f'<a href="{BASE}{target}">{label}</a>\n'
                  for label, target in NAVIGATION[1:])
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="{DESCRIPTION}">
<title>{escape(title)} · Sibuna</title>
<link rel="icon" type="image/svg+xml" href="{BASE}assets/favicon.svg">
<link rel="stylesheet" href="{BASE}assets/site.css">
<link rel="stylesheet" href="{BASE}assets/admission-demo.css">
<script type="module" src="{BASE}assets/admission-animation.js"></script></head><body>
<a class="skip" href="#main">Skip to content</a>
<header class="nav"><a class="brand" href="{BASE}"><i aria-hidden="true">s.</i>sibuna</a>
<nav aria-label="Main">{nav}<a href="{REPO}">GitHub</a></nav></header>
<main id="main" class="home">{body}</main>
<footer class="footer"><span>Sibuna is written by Vikrant Rathore with assistance from Ronak
Rathore and Kanak Rathore.<br>Companies seeking other licensing terms can contact Vikrant
Rathore.</span>
<span><a href="{REPO}/blob/main/LICENSE">LGPL 3.0 or later</a> · v{VERSION}<br>
Third-party libraries retain their respective licenses.</span></footer>
</body></html>
'''


def build_home(site):
    body = (SOURCE / "index.html").read_text()
    assert body.count("<!-- admission-demo -->") == 1, "index.html needs one demo marker"
    assert f"v{VERSION}" in body, f"index.html does not name the version v{VERSION}"
    body = body.replace("<!-- admission-demo -->", (SOURCE / "admission-demo.html").read_text())
    (site / "index.html").write_text(shell("Web application protection", body))
    (site / "assets").mkdir()
    for name in ASSETS:
        shutil.copyfile(SOURCE / name, site / "assets" / name)


class Links(HTMLParser):
    """Collects the links and element ids of one page."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key in ("id", "name") and value:
                self.ids.add(value)
            if key in ("href", "src") and value:
                self.links.append(value)


def validate(site):
    """Every local link must reach a file, and every fragment an id on that page."""
    pages = {}
    for path in site.rglob("*.html"):
        parser = Links()
        parser.feed(path.read_text())
        pages[path.resolve()] = parser
    broken = []
    for path, parser in pages.items():
        for link in parser.links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                continue
            if url.path.startswith(BASE):
                target = site / unquote(url.path[len(BASE):])
            elif url.path.startswith("/"):
                broken.append((path, link))
                continue
            else:
                target = path.parent / unquote(url.path) if url.path else path
            if target.is_dir():
                target /= "index.html"
            target = target.resolve()
            missing = url.fragment and target in pages and unquote(url.fragment) not in (
                pages[target].ids)
            if not target.is_file() or missing:
                broken.append((path, link))
    for path, link in broken:
        print(f"broken link: {path.relative_to(site.resolve())}: {link}")
    if broken:
        raise SystemExit(f"{len(broken)} broken links in the site")
    print(f"site-links: {len(pages)} pages; every local link and anchor resolves")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=ROOT / "target/site")
    parser.add_argument("--no-build", action="store_true",
                        help="reuse the guidedog _build folders")
    options = parser.parse_args()
    site = options.out.resolve()
    check_animation_assets()
    if not options.no_build:
        build_documents()
    if site.exists():
        shutil.rmtree(site)
    site.mkdir(parents=True)
    copy_bundles(site)
    build_home(site)
    (site / ".nojekyll").touch()
    validate(site)
    print(f"site: {site}")


if __name__ == "__main__":
    main()
