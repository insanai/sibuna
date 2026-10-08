"""Shared SQLodin-style documentation shell, navigation, search and link validation."""
from html import escape
from html.parser import HTMLParser
import json
import re
from urllib.parse import unquote, urlsplit

BASE = "/sibuna/"
REPO = "https://github.com/insanai/sibuna"
GROUPS = (("book", "The book"), ("whitepaper", "Architecture"),
          ("sid", "Design discussions"))


class Content(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.words = []
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key == "id":
                self.ids.add(value)
            if key in ("href", "src") and value:
                self.links.append(value)

    def handle_data(self, data):
        self.words.append(data)


def inventory(site, root):
    pages = [
        dict(route="book/index.html", title="The book", group="book",
             source="docs/book.typ", pdf="pdf/sibuna-book.pdf"),
        dict(route="book/operations.html", title="Operations and deployment", group="book",
             source="docs/book/09_operations.typ", pdf="pdf/sibuna-book.pdf"),
        dict(route="book/reference.html", title="CLI and protocol reference", group="book",
             source="docs/book/10_reference.typ", pdf="pdf/sibuna-book.pdf"),
        dict(route="whitepaper/index.html", title="Architecture whitepaper", group="whitepaper",
             source="docs/whitepaper/whitepaper.typ", pdf="pdf/sibuna-whitepaper.pdf"),
        dict(route="sid/index.html", title="Shibuna Discussions", group="sid",
             source="docs/sid/registry.typ"),
    ]
    registry = (root / "docs/sid/registry.typ").read_text()
    for record in re.findall(r"  \(\n(.*?)\n  \),", registry, re.S):
        fields = dict(re.findall(r'^    (\w+): "([^"]*)",', record, re.M))
        pages.append(dict(route="sid/" + fields["html"],
                          title=f"SID {fields['number']}: {fields['title']}", group="sid",
                          source=fields["source"], pdf="sid/" + fields["pdf"]))
    assert {page["route"] for page in pages} == {
        path.relative_to(site).as_posix() for path in site.rglob("*.html")
    }, "exported pages and navigation inventory disagree"
    return pages


def navigation(pages, active):
    result = '<aside class="sidebar"><details open><summary>Documentation</summary>'
    for group, label in GROUPS:
        result += f'<span class="group">{label}</span>'
        for page in pages:
            if page["group"] != group:
                continue
            current = ' aria-current="page"' if page["route"] == active else ""
            result += (f'<a href="{BASE}{page["route"]}"{current}>'
                       f'{escape(page["title"])}</a>')
    return result + "</details></aside>"


def shell(title, body, pages, route="", tools="", styles=""):
    if route:
        content = (f'<div class="docs-layout">{navigation(pages, route)}'
                   f'<main id="main" class="reading">{tools}<article>{body}</article>'
                   '</main></div>')
    else:
        content = f'<main id="main" class="home">{body}</main>'
    animation = "" if route else (
        f'<link rel="stylesheet" href="{BASE}assets/admission-demo.css">'
        f'<script type="module" src="{BASE}assets/admission-animation.js"></script>')
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="Sibuna: proof-of-work admission, bounded web application inspection and an optional management console.">
<title>{escape(title)} · Sibuna</title>{styles}
<link rel="icon" type="image/svg+xml" href="{BASE}assets/favicon.svg">
<link rel="stylesheet" href="{BASE}assets/site.css">
<script defer src="{BASE}assets/site.js"></script>{animation}</head><body>
<a class="skip" href="#main">Skip to content</a>
<header class="nav"><a class="brand" href="{BASE}"><i aria-hidden="true">s.</i>sibuna</a>
<nav aria-label="Main"><a href="{BASE}book/">Book</a>
<a href="{BASE}book/operations.html">Operations</a><a href="{BASE}sid/">SIDs</a>
<a href="{REPO}">GitHub ↗</a><button class="search-open" type="button">Search</button></nav></header>
{content}<footer class="footer"><span>Vikrant Rathore and Ronak Rathore.<br>
Companies seeking alternative licensing can contact the authors.</span>
<span><a href="{REPO}/blob/main/LICENSE">Engine: LGPL 3.0 · Console: AGPL 3.0</a><br>
Third-party libraries retain their respective licenses.</span></footer>
<dialog id="search-dialog" aria-labelledby="search-title"><header>
<strong id="search-title">Search the documentation</strong>
<button id="search-close" type="button" aria-label="Close search">✕</button></header>
<label for="search-query">Words or a topic</label><input id="search-query" type="search"
placeholder="Try uploads, challenges, or policies" autocomplete="off">
<div id="results" aria-live="polite"></div></dialog></body></html>'''


def home_body(root):
    source = root / "docs/site"
    body = (source / "index.html").read_text()
    assert body.count("<!-- admission-demo -->") == 1
    return body.replace("<!-- admission-demo -->", (source / "admission-demo.html").read_text())


def decorate(site, root):
    pages = inventory(site, root)
    search = []
    for page in pages:
        path = site / page["route"]
        raw = path.read_text()
        body = re.search(r"<body[^>]*>(.*)</body>", raw, re.S)[1]
        # Preserve Typst's MathML layout rules; replace the embedded SID website theme.
        styles = "".join(re.findall(r"<style[^>]*>.*?</style>", raw.split("<body", 1)[0], re.S))
        body = re.sub(r"<style[^>]*>.*?</style>", "", body, flags=re.S)
        if page["route"] in ("book/operations.html", "book/reference.html"):
            body = re.sub(r"<h2([^>]*)>.*?</h2>",
                          lambda match: f'<h1{match[1]}>{escape(page["title"])}</h1>',
                          body, count=1, flags=re.S)
        if "<h1" not in body:
            body = f'<h1>{escape(page["title"])}</h1>' + body
        tools = ('<div class="reader-tools">'
                 f'<span>{dict(GROUPS)[page["group"]]}</span>'
                 f'<a href="{REPO}/blob/main/{page["source"]}">View source ↗</a>')
        if "pdf" in page:
            tools += f'<a href="{BASE}{page["pdf"]}">Download PDF ↓</a>'
        tools += "</div>"
        content = Content()
        content.feed(body)
        search.append(dict(title=page["title"], url=BASE + page["route"],
                           text=re.sub(r"\s+", " ", " ".join(content.words))))
        path.write_text(shell(page["title"], body, pages, page["route"], tools, styles))
    home = home_body(root)
    (site / "index.html").write_text(shell("Web application protection", home, pages))
    (site / "search.json").write_text(json.dumps(search))
    validate(site)


def validate(site):
    parsed = {}
    for path in site.rglob("*.html"):
        parser = Content()
        parser.feed(path.read_text())
        parsed[path.resolve()] = parser
    broken = []
    for path, parser in parsed.items():
        for link in parser.links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                continue
            if url.path.startswith(BASE):
                target = site / unquote(url.path[len(BASE):])
            else:
                target = path.parent / unquote(url.path) if url.path else path
            if target.is_dir():
                target /= "index.html"
            target = target.resolve()
            missing_anchor = (url.fragment and target in parsed and
                              unquote(url.fragment) not in parsed[target].ids)
            if not target.is_file() or missing_anchor:
                broken.append((str(path.relative_to(site)), link))
    if broken:
        raise SystemExit(f"Broken documentation links: {broken}")
    print(f"documentation-links: {len(parsed)} pages, links and anchors verified")
