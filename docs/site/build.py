#!/usr/bin/env python3
"""Build the Sibuna website for GitHub Pages at https://insanai.github.io/sibuna/.

    python3 docs/site/build.py [--out DIR] [--no-build]

The site has these parts, served under /sibuna/:

    /sibuna/              the landing page (docs/site/index.html and the admission demo)
    /sibuna/book/         The Sibuna Book, `guidedog build html` of docs/book
    /sibuna/whitepaper/   the whitepaper, `guidedog build html` of docs/whitepaper
    /sibuna/sid/          the Sibuna Discussions, `guidedog dsc build` of docs/sid
    /sibuna/pdf/          the book and whitepaper as PDF; /sibuna/sid/pdf/ holds one per record
    /sibuna/<lang>/       the landing page, book/, whitepaper/ and pdf/ in another language

The other languages are zh-hans, ko, ja, es, de, hi and ar (see languages.py). Their books
and whitepapers are built from the gettext catalogs in docs/book/locales and
docs/whitepaper/locales; a message not yet translated, or a language without a catalog
yet, stays English. A few words that no source file holds come from the language's phrase
map instead (see Bundle.shown). The SIDs exist only in English.

Guidedog writes each project into its own _build folder; this script copies the results,
adds the site's links and the language menu to the header of every documentation page,
wraps the landing page in the site's shell, translates it, and checks every local link and
anchor. It needs guidedog on PATH and nothing else beyond the Python standard library; the
PDF books and whitepapers in Chinese, Japanese, Korean, Hindi and Arabic need the Noto
fonts (Debian packages fonts-noto-cjk and fonts-noto-core). --no-build reuses the _build
folders. The default output is target/site.
"""
from dataclasses import dataclass
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
import tomllib

from languages import ENGLISH, LANGUAGES, TRANSLATIONS
import languages

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs/site"
BASE = "/sibuna/"
SITE_URL = "https://insanai.github.io/sibuna/"
REPO = "https://github.com/insanai/sibuna"
# The workspace version; the landing page must name it (a release bump updates index.html).
VERSION = re.search(r'^version = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M)[1]
DESCRIPTION = ("Sibuna: self-hosted web protection with browser proof of work"
               " and an optional console.")
# Files the landing page loads, copied to /sibuna/assets/.
ASSETS = ("site.css", "favicon.svg", "admission-demo.css", "admission-model.js",
          "admission-animation.js", "admission-scene.bundle.js", "three-LICENSE.txt",
          "language.css", "site-language.js")


@dataclass(frozen=True)
class Bundle:
    """A guidedog project the site publishes in every language."""
    folder: str     # the site folder, in every edition
    project: str    # the guidedog project, relative to the repository
    built: str      # the English PDF guidedog writes into _build/pdf
    published: str  # the PDF's name in the edition's pdf/ folder
    # The conf.toml settings whose text readers see (on the PDF cover or title page, in
    # the HTML footer or title) but which no source file holds, so no catalog translates
    # them. A translated build overrides each with -D, taking the translation of its
    # English value from the language's phrase map (docs/site/i18n/<code>.json); the
    # build reports a missing one, which stays English. A setting that holds only a
    # name, such as the whitepaper's author, is not listed.
    shown: tuple[str, ...]


BUNDLES = (
    Bundle("book", "docs/book", "the-sibuna-book-en.pdf", "sibuna-book.pdf",
           ("author", "copyright")),
    Bundle("whitepaper", "docs/whitepaper", "sibuna-whitepaper-en.pdf",
           "sibuna-whitepaper.pdf", ("copyright", "html_title", "today")),
)
NAVIGATION = (("Home", ""), ("Book", "book/"), ("Operations", "book/operations.html"),
              ("Whitepaper", "whitepaper/"), ("SIDs", "sid/"))
# The sections that exist in every language: the landing page and the bundles. The SIDs
# exist only in English, and every edition links to them.
TRANSLATED = ("",) + tuple(f"{bundle.folder}/" for bundle in BUNDLES)
TITLE = "Web application protection"
# The phrases the landing page's scripts and the documentation headers show.
SCRIPT_PHRASES = languages.model_phrases() | set(languages.EXTRA_PHRASES)


def run(args, cwd):
    print("+", " ".join(args), f"(in {cwd.relative_to(ROOT)})", flush=True)
    subprocess.run(args, cwd=cwd, check=True)


def build_documents():
    """Fresh guidedog builds; warnings fail the build, as `guidedog dsc build` does."""
    for bundle in BUNDLES:
        for builder in ("html", "pdf"):
            run(["guidedog", "build", "-E", "-a", "-W", "-q", builder],
                ROOT / bundle.project)
    run(["guidedog", "dsc", "build"], ROOT / "docs/sid")
    for bundle in BUNDLES:
        for language in TRANSLATIONS:
            build_translated(bundle, language)


def settings(bundle):
    """The settings of a bundle's conf.toml."""
    return tomllib.loads((ROOT / bundle.project / "conf.toml").read_text())


def catalog_messages(path):
    """The translations of a gettext catalog, from msgid to msgstr.

    Fuzzy and empty translations are left out; a string may continue over several
    quoted lines, as msgmerge wraps long ones. A missing catalog has none.
    """
    messages = {}
    if not path.is_file():
        return messages
    for entry in path.read_text().split("\n\n"):
        if re.search(r"^#,.*\bfuzzy\b", entry, re.M):
            continue
        fields = {}
        field = None
        for line in entry.splitlines():
            keyword = re.match(r'(msgid|msgstr) (".*")$', line)
            if keyword:
                field = keyword[1]
                fields[field] = json.loads(keyword[2])
            elif line.startswith('"') and field:
                fields[field] += json.loads(line)
            else:
                field = None
        if fields.get("msgid") and fields.get("msgstr"):
            messages[fields["msgid"]] = fields["msgstr"]
    return messages


def translated_title(bundle, language):
    """A bundle's title in a language: the translation of its English title (the title of
    index.rst, and project in conf.toml) in the bundle's catalog, else the English."""
    english = settings(bundle)["project"]
    catalog = ROOT / bundle.project / "locales" / language.gettext / "LC_MESSAGES/index.po"
    return catalog_messages(catalog).get(english, english)


def shown_phrases():
    """The English text of every setting that the phrase maps translate (Bundle.shown)."""
    return {settings(bundle)[name] for bundle in BUNDLES for name in bundle.shown}


def build_translated(bundle, language):
    """A bundle in another language, HTML and PDF, in its _build/i18n/<language>/.

    The title comes from the bundle's catalog, the shown settings from the language's
    phrase map. Warnings do not fail these builds: the catalogs are still being filled,
    and a language may have no catalog yet.
    """
    words = languages.load_words(language)
    english = settings(bundle)
    overrides = ["-D", f"language={language.gettext}",
                 "-D", f"project={translated_title(bundle, language)}"]
    for name in bundle.shown:
        if english[name] in words:
            overrides += ["-D", f"{name}={words[english[name]]}"]
    for builder in ("html", "pdf"):
        output = f"_build/i18n/{language.gettext}/{builder}"
        extra = []
        if builder == "pdf" and language.gettext in ENGLISH_PDF_GRAPHS:
            extra = ["-D", f"locale_dirs={english_graph_catalogs(bundle, language)}"]
        run(["guidedog", "build", "-E", "-a", "-q", "-b", builder, ".", output, *overrides,
             *extra], ROOT / bundle.project)


# The languages whose PDFs draw graph labels in English. Typst draws a graph's SVG text
# without Devanagari shaping (vowel signs come apart, and no font fixes it), while
# browsers draw the same SVG correctly; so these PDFs keep the English graphs and their
# HTML keeps the translated ones.
ENGLISH_PDF_GRAPHS = ("hi",)
GRAPH_STARTS = ("digraph", "graph ", "graph{", "strict ")


def english_graph_catalogs(bundle, language):
    """The bundle's locale_dirs with its own catalogs replaced by a copy in which every
    graph source is untranslated, written below the bundle's _build folder."""
    project = ROOT / bundle.project
    source = project / "locales" / language.gettext / "LC_MESSAGES"
    target = project / "_build/i18n" / language.gettext / "pdf-locales"
    shutil.rmtree(target, ignore_errors=True)
    (target / language.gettext / "LC_MESSAGES").mkdir(parents=True)
    for catalog in source.glob("*.po"):
        entries = [untranslated_graph(entry) for entry in catalog.read_text().split("\n\n")]
        (target / language.gettext / "LC_MESSAGES" / catalog.name).write_text(
            "\n\n".join(entries))
    conf = (project / "conf.toml").read_text()
    dirs = json.loads(re.search(r"^locale_dirs = (\[.*\])$", conf, re.M)[1])
    relative = target.relative_to(project).as_posix()
    return json.dumps([relative if d == "locales" else d for d in dirs])


def untranslated_graph(entry):
    """One catalog entry, with its translation removed when its message is a graph."""
    lines = entry.split("\n")
    start = next((i for i, line in enumerate(lines) if line.startswith("msgid ")), None)
    end = next((i for i, line in enumerate(lines) if line.startswith("msgstr ")), None)
    if start is None or end is None:
        return entry
    msgid = "".join(line.split('"', 1)[1].rsplit('"', 1)[0] for line in lines[start:end])
    if not msgid.lstrip().startswith(GRAPH_STARTS):
        return entry
    rest = [line for line in lines[end + 1:] if not line.startswith('"')]
    return "\n".join(lines[:end] + ['msgstr ""'] + rest)


def check_animation_assets():
    """The bundled 3D scene is checked in; its manifest records how it was made."""
    manifest = json.loads((SOURCE / "admission-assets.json").read_text())
    for name, expected in manifest["files"].items():
        data = (SOURCE / name).read_bytes()
        assert len(data) == expected["bytes"], f"stale animation asset: {name}"
        assert hashlib.sha256(data).hexdigest() == expected["sha256"], f"changed: {name}"


def section_url(target, language):
    """The address of a site section in a language; untranslated sections stay English."""
    translated = target.split("/")[0] + "/" in TRANSLATED or target == ""
    return BASE + (language.prefix if translated else "") + target


def site_links(route, pdf, language):
    """The list items added to a guidedog header: the site sections, a PDF and GitHub.

    route is the page's path below its edition's folder, such as "book/index.html".
    """
    words = languages.load_words(language)
    section = route if route == "book/operations.html" else route.split("/")[0] + "/"
    items = []
    for label, target in NAVIGATION:
        mark = ' aria-current="page"' if target == section else ""
        label = escape(languages.word(words, label))
        items.append(f'<li><a href="{section_url(target, language)}"{mark}>{label}</a></li>')
    if pdf:
        items.append(f'<li><a href="{BASE}{pdf}">{languages.word(words, "PDF")}</a></li>')
    items.append(f'<li><a href="{REPO}">GitHub</a></li>')
    return '<ul class="rellinks">' + "".join(items) + "</ul>"


def record_pdf(site, route):
    """The PDF of a SID record: sid/records/NNNN-name.html has sid/pdf/sid-NNNN-name-en.pdf."""
    match = re.fullmatch(r"sid/records/(.+)\.html", route)
    if not match:
        return None
    pdf = f"sid/pdf/sid-{match[1]}-en.pdf"
    return pdf if (site / pdf).is_file() else None


def decorate_bundle(site, folder, pdf, language=ENGLISH):
    """Put the site's links into the empty link list of every guidedog header, add the
    language menu at the header's end, and name the page's other languages."""
    empty = re.compile(r'<ul class="rellinks">\s*</ul>')
    for path in sorted((site / language.prefix / folder).rglob("*.html")):
        route = path.relative_to(site / language.prefix).as_posix()
        text = path.read_text()
        found = len(empty.findall(text))
        assert found == 1, f"{route}: expected one empty header link list, found {found}"
        links = site_links(route, record_pdf(site, route) or pdf, language)
        text = empty.sub(lambda _: links, text)
        translated = folder + "/" in TRANSLATED
        menu = languages.language_menu(BASE, route, language, translated)
        assert text.count("</header>") >= 1 and 'class="gd-header"' in text, route
        text = text.replace("</header>", menu + "</header>", 1)
        head = [f'<link rel="stylesheet" href="{BASE}assets/language.css">',
                f'<script type="module" src="{BASE}assets/site-language.js"></script>']
        if translated:
            head.append(languages.alternates(SITE_URL, route))
        if 'rel="icon"' not in text:
            head.append(f'<link rel="icon" type="image/svg+xml" '
                        f'href="{BASE}assets/favicon.svg">')
        text = text.replace("</head>", "\n".join(head) + "\n</head>", 1)
        path.write_text(text)


def copy_bundles(site):
    (site / "pdf").mkdir(parents=True)
    for bundle in BUNDLES:
        project = ROOT / bundle.project
        shutil.copytree(project / "_build/html", site / bundle.folder)
        shutil.copyfile(project / "_build/pdf" / bundle.built,
                        site / "pdf" / bundle.published)
        decorate_bundle(site, bundle.folder, f"pdf/{bundle.published}")
    shutil.copytree(ROOT / "docs/sid/_build/html", site / "sid")
    (site / "sid/pdf").mkdir()
    for pdf in sorted((ROOT / "docs/sid/_build/pdf").glob("*.pdf")):
        shutil.copyfile(pdf, site / "sid/pdf" / pdf.name)
    decorate_bundle(site, "sid", None)
    for bundle in BUNDLES:
        for language in TRANSLATIONS:
            copy_translated(site, bundle, language)


def copy_translated(site, bundle, language):
    """A bundle in one language at /sibuna/<lang>/<folder>/, its PDF in <lang>/pdf/.

    The English bundle must be in the site already: the translation must have its pages.
    """
    built = ROOT / bundle.project / "_build/i18n" / language.gettext
    edition = site / language.prefix
    shutil.copytree(built / "html", edition / bundle.folder)
    pdfs = sorted((built / "pdf").glob("*.pdf"))
    assert len(pdfs) == 1, f"{language.code}: expected one {bundle.folder} PDF, found {len(pdfs)}"
    (edition / "pdf").mkdir(exist_ok=True)
    shutil.copyfile(pdfs[0], edition / "pdf" / bundle.published)
    english = {path.relative_to(site / bundle.folder)
               for path in (site / bundle.folder).rglob("*.html")}
    pages = {path.relative_to(edition / bundle.folder)
             for path in (edition / bundle.folder).rglob("*.html")}
    assert pages == english, f"{language.code}: the {bundle.folder} pages differ from the English"
    decorate_bundle(site, bundle.folder, f"{language.prefix}pdf/{bundle.published}", language)


def shell(language, title, body):
    """The landing page's document in English: header, the body, and the footer.

    The links and the language menu already point into the language's edition; the
    caller translates the text.
    """
    nav = "".join(f'<a href="{section_url(target, language)}">{label}</a>\n'
                  for label, target in NAVIGATION[1:])
    menu = languages.language_menu(BASE, "", language, True)
    detect = str(language is ENGLISH).lower()
    return f'''<!doctype html><html lang="{language.code}" dir="{language.direction}"
 data-detect-language="{detect}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="{DESCRIPTION}">
<title>{escape(title)} · Sibuna</title>
{languages.alternates(SITE_URL, "")}
<link rel="icon" type="image/svg+xml" href="{BASE}assets/favicon.svg">
<link rel="stylesheet" href="{BASE}assets/site.css">
<link rel="stylesheet" href="{BASE}assets/admission-demo.css">
<link rel="stylesheet" href="{BASE}assets/language.css">
<script type="module" src="{BASE}assets/site-language.js"></script>
<script type="module" src="{BASE}assets/admission-animation.js"></script></head><body>
<a class="skip" href="#main">Skip to content</a>
<header class="nav"><a class="brand" href="{BASE}{language.prefix}" translate="no"><i
aria-hidden="true">s.</i>sibuna</a>
<nav aria-label="Main">{nav}<a href="{REPO}">GitHub</a>
{menu}</nav></header>
<main id="main" class="home">{body}</main>
<footer class="footer"><span>Sibuna is written by Vikrant Rathore with assistance from Ronak
Rathore and Kanak Rathore.<br>Companies seeking other licensing terms can contact Vikrant
Rathore.</span>
<span><a href="{REPO}/blob/main/LICENSE">LGPL 3.0 or later</a> · v{VERSION}<br>
Third-party libraries retain their respective licenses.</span></footer>
</body></html>
'''


def home_body(language, words):
    """The landing page's body with the demo, its links pointing into the edition.

    The demo's script reads its texts in the page's language from a JSON element.
    """
    body = (SOURCE / "index.html").read_text()
    assert body.count("<!-- admission-demo -->") == 1, "index.html needs one demo marker"
    assert f"v{VERSION}" in body, f"index.html does not name the version v{VERSION}"
    demo = (SOURCE / "admission-demo.html").read_text()
    assert demo.count("</section>") == 1, "admission-demo.html is one section"
    messages = languages.demo_messages(words, SCRIPT_PHRASES)
    demo = demo.replace("</section>", '<script type="application/json" data-demo-language>'
                        f"{messages}</script></section>")
    body = body.replace("<!-- admission-demo -->", demo)
    if language is not ENGLISH:
        for bundle in BUNDLES:
            body = body.replace(f'href="{BASE}{bundle.folder}/',
                                f'href="{BASE}{language.prefix}{bundle.folder}/')
            body = body.replace(f'href="{BASE}pdf/{bundle.published}"',
                                f'href="{BASE}{language.prefix}pdf/{bundle.published}"')
    return body


def build_home(site):
    """The landing page in every language, and the assets they share."""
    english = shell(ENGLISH, TITLE, home_body(ENGLISH, {}))
    documents = shown_phrases()
    phrases = languages.catalog(english) | documents
    for language in LANGUAGES:
        words = languages.load_words(language)
        page = shell(language, TITLE, home_body(language, words))
        if language is not ENGLISH:
            page, missing = languages.translate(page, words)
            missing |= (SCRIPT_PHRASES | documents) - set(words)
            report_phrases(language, missing, set(words) - phrases)
        (site / language.prefix).mkdir(exist_ok=True)
        (site / language.prefix / "index.html").write_text(page)
    (site / "assets").mkdir()
    for name in ASSETS:
        shutil.copyfile(SOURCE / name, site / "assets" / name)


def report_phrases(language, missing, unused):
    """Say which phrases of a language stay English, and which are no longer used: those
    of the landing page, the documentation headers and the bundles' shown settings."""
    for phrase in sorted(missing):
        print(f"site-i18n: {language.code}: untranslated: {phrase}")
    for phrase in sorted(unused):
        print(f"site-i18n: {language.code}: unused: {phrase}")


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
