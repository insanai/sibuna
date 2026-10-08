"""Shared SQLodin-style documentation shell, navigation, search and link validation."""
from html import escape
from html.parser import HTMLParser
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit
from i18n.locale import LOCALES, metadata, language_choices
from i18n.tables import isolate_numbers
from i18n.html import words as locale_words, translate_fragment, safe_json

ROOT = Path(__file__).resolve().parents[1]
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
    books = [page for page in pages if page["group"] == "book"]
    for locale, data in LOCALES.items():
        if locale == "en" or not (site / data["prefix"] / "book").exists():
            continue
        for page in books:
            name = Path(page["source"]).stem
            source = (f"docs/i18n/{locale}/book/{name}.json" if name != "book"
                      else f"docs/i18n/{locale}/book")
            pages.append(dict(page, route=data["prefix"] + page["route"], locale=locale,
                              source=source, pdf=data["prefix"] + page["pdf"]))
    assert {page["route"] for page in pages} == {
        path.relative_to(site).as_posix() for path in site.rglob("*.html")
    }, "exported pages and navigation inventory disagree"
    return pages


def navigation(pages, active, locale="en"):
    words = locale_words(ROOT, locale)
    result = ('<aside class="sidebar"><details open><summary>'
              + escape(words["Documentation"]) + '</summary>')
    for group, label in GROUPS:
        result += f'<span class="group">{escape(words[label])}</span>'
        for page in pages:
            if page["group"] != group:
                continue
            page_locale = page.get("locale", "en")
            if group == "book" and page_locale != locale:
                continue
            current = ' aria-current="page"' if page["route"] == active else ""
            title = page["title"] if group != "book" else words[page["title"]]
            result += (f'<a href="{BASE}{page["route"]}"{current}>'
                       f'{escape(title)}</a>')
    return result + "</details></aside>"


def language_menu(route, locale, words):
    links = []
    for choice in language_choices(route, locale):
        current = ' aria-current="true"' if choice["selected"] else ""
        same = str(choice["same_page"]).lower()
        code = choice["locale"]
        target = BASE + choice["path"] + "?lang=" + code
        links.append(f'<a href="{target}" lang="{code}" dir="auto"'
                     f' data-language-choice="{code}" data-same-page="{same}"{current}>'
                     f'{escape(choice["label"])}</a>')
    return ('<details class="language-menu"><summary>' + escape(words["Language"])
            + '</summary><div>' + ''.join(links) + '</div></details>')


def shell(title, body, pages, route="", tools="", styles="", locale="en"):
    words = locale_words(ROOT, locale)
    meta = metadata(locale)
    prefix = meta["prefix"]
    canonical = route.removeprefix(prefix) if prefix else route
    if route:
        content = (f'<div class="docs-layout">{navigation(pages, route, locale)}'
                   f'<main id="main" class="reading">{tools}<article>{body}</article>'
                   '</main></div>')
    else:
        content = f'<main id="main" class="home">{body}</main>'
    animation = "" if route else (
        f'<link rel="stylesheet" href="{BASE}assets/admission-demo.css">'
        f'<script type="module" src="{BASE}assets/admission-animation.js"></script>')
    translatable = not route or canonical.startswith("book/")
    detect = str(locale == "en" and translatable).lower()
    page_title = words.get(title, title)
    main_label = escape(words["Main"])
    menu = language_menu(canonical, locale, words)
    alternates = ""
    if translatable:
        for code, edition in LOCALES.items():
            target = "https://insanai.github.io" + BASE + edition["prefix"] + canonical
            alternates += f'<link rel="alternate" hreflang="{code}" href="{target}">'
    description = words['Web application protection']
    failed = escape(words['Search could not load. Use the documentation navigation or try again.'])
    license_label = escape(words['Engine: LGPL 3.0 · Console: AGPL 3.0'])
    return f'''<!doctype html><html lang="{locale}" dir="{meta['direction']}"
 data-locale="{locale}" data-detect-language="{detect}" data-search="{BASE}{prefix}search.json"
 data-search-empty="{escape(words['No matching pages. Try a shorter term.'], quote=True)}"
 data-search-failed="{failed}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="{escape(description, quote=True)}">{alternates}
<title>{escape(page_title)} · Sibuna</title>{styles}
<link rel="icon" type="image/svg+xml" href="{BASE}assets/favicon.svg">
<link rel="stylesheet" href="{BASE}assets/site.css">
<link rel="stylesheet" href="{BASE}assets/site-i18n.css">
<script type="module" src="{BASE}assets/site-language.js"></script>
<script defer src="{BASE}assets/site.js"></script>{animation}</head><body>
<a class="skip" href="#main">{escape(words['Skip to content'])}</a>
<header class="nav"><a class="brand" href="{BASE}{prefix}"><i aria-hidden="true">s.</i>sibuna</a>
<nav aria-label="{main_label}"><a href="{BASE}{prefix}book/">{escape(words['Book'])}</a>
<a href="{BASE}{prefix}book/operations.html">{escape(words['Operations'])}</a>
<a href="{BASE}sid/">{escape(words['SIDs'])}</a>
<a href="{REPO}">GitHub ↗</a>
<button class="search-open" type="button">{escape(words['Search'])}</button>
{menu}</nav></header>
{content}<footer class="footer"><span>Vikrant Rathore and Ronak Rathore.<br>
{escape(words['Companies seeking alternative licensing can contact the authors.'])}</span>
<span><a href="{REPO}/blob/main/LICENSE">{license_label}</a><br>
{escape(words['Third-party libraries retain their respective licenses.'])}</span></footer>
<dialog id="search-dialog" aria-labelledby="search-title"><header>
<strong id="search-title">{escape(words['Search the documentation'])}</strong>
<button id="search-close" type="button"
aria-label="{escape(words['Close search'])}">✕</button></header>
<label for="search-query">{escape(words['Words or a topic'])}</label>
<input id="search-query" type="search"
placeholder="{escape(words['Try uploads, challenges, or policies'])}" autocomplete="off">
<div id="results" aria-live="polite"></div></dialog></body></html>'''


def home_body(root, locale="en"):
    source = root / "docs/site"
    words = locale_words(root, locale)
    body = translate_fragment((source / "index.html").read_text(), words)
    assert body.count("<!-- admission-demo -->") == 1
    demo = translate_fragment((source / "admission-demo.html").read_text(), words)
    data = '<script type="application/json" data-demo-language>' + safe_json(words) + '</script>'
    demo = demo.replace('</section>', data + '</section>')
    body = body.replace("<!-- admission-demo -->", demo)
    if locale != "en":
        prefix = metadata(locale)["prefix"]
        body = body.replace(f'href="{BASE}book/', f'href="{BASE}{prefix}book/')
    return body


def page_body(raw):
    body = re.search(r"<body[^>]*>(.*)</body>", raw, re.S)[1]
    styles = "".join(re.findall(r"<style[^>]*>.*?</style>", raw.split("<body", 1)[0], re.S))
    return re.sub(r"<style[^>]*>.*?</style>", "", body, flags=re.S), styles


def stable_headings(original, translated):
    """Language switches retain anchors; a missing section cannot silently shift them."""
    pattern = re.compile(r'<h([1-6])([^>]*)>.*?</h\1>', re.S)
    headings = list(pattern.finditer(original))
    native = list(pattern.finditer(translated))
    assert len(headings) == len(native), "translated book heading count differs"
    mappings = {}
    for source, target in zip(headings, native):
        assert source[1] == target[1], "translated book heading hierarchy differs"
        old = re.search(r' id="([^"]+)"', source[2])
        new = re.search(r' id="([^"]+)"', target[2])
        assert bool(old) == bool(new), "translated heading has different anchor ownership"
        if old:
            mappings[new[1]] = old[1]
    return re.sub(r'(\b(?:id|href)=")(#?)([^"]+)(")',
                  lambda match: match[1] + match[2] +
                  mappings.get(match[3], match[3]) + match[4], translated)


def reader_tools(page, words):
    view = 'blob' if Path(page['source']).suffix else 'tree'
    result = ('<div class="reader-tools">'
              f'<span>{escape(words[dict(GROUPS)[page["group"]]])}</span>'
              f'<a href="{REPO}/{view}/main/{page["source"]}">'
              f'{escape(words["View source ↗"])}</a>')
    if "pdf" in page:
        result += (f'<a href="{BASE}{page["pdf"]}">'
                   f'{escape(words["Download PDF ↓"])}</a>')
    return result + '</div>'


def decorate_page(site, root, page, pages, originals):
    locale = page.get("locale", "en")
    words = locale_words(root, locale)
    prefix = metadata(locale)["prefix"]
    canonical = page["route"].removeprefix(prefix) if prefix else page["route"]
    path = site / page["route"]
    body, styles = page_body(path.read_text())
    if locale != "en":
        body = stable_headings(originals[canonical], body)
        body = body.replace(f'href="{BASE}book/', f'href="{BASE}{prefix}book/')
    if locale == "ar":
        body = isolate_numbers(body)
    title = words.get(page["title"], page["title"])
    if canonical in ("book/operations.html", "book/reference.html"):
        body = re.sub(r"<h2([^>]*)>.*?</h2>",
                      lambda match: f'<h1{match[1]}>{escape(title)}</h1>',
                      body, count=1, flags=re.S)
    if "<h1" not in body:
        body = f'<h1>{escape(title)}</h1>' + body
    content = Content()
    content.feed(body)
    tools = reader_tools(page, words)
    path.write_text(shell(page["title"], body, pages, page["route"], tools, styles, locale))
    return dict(title=title, url=BASE + page["route"], locale=locale,
                text=re.sub(r"\s+", " ", " ".join(content.words)))


def decorate(site, root):
    pages = inventory(site, root)
    originals = {page["route"]: page_body((site / page["route"]).read_text())[0]
                 for page in pages if page.get("locale", "en") == "en"}
    search = [decorate_page(site, root, page, pages, originals) for page in pages]
    for locale, meta in LOCALES.items():
        directory = site / meta["prefix"]
        directory.mkdir(exist_ok=True)
        home = home_body(root, locale)
        (directory / "index.html").write_text(
            shell("Web application protection", home, pages, locale=locale))
        entries = [entry for entry in search if entry["locale"] == locale or
                   not entry["url"].startswith(BASE + 'book/') and
                   entry["locale"] == 'en']
        (directory / "search.json").write_text(json.dumps(entries, ensure_ascii=False))
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
