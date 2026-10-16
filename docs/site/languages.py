"""The languages of the Sibuna website: editions, translated text and the language menu.

English is the source. Each other language has a folder under /sibuna/ (its prefix) with
a translated landing page and a translated book; the whitepaper and the SIDs exist only in
English, and a translated page that links to them says so in its own language.

The landing page is translated by phrase. We read the English page, take each run of text
between tags (with its white space made single spaces) and the attributes that people read
(aria-label, title, alt, placeholder and the page description), and look each phrase up in
docs/site/i18n/<code>.json, a map from the English phrase to its translation. Code, pre,
script and style elements, and elements marked translate="no", are left alone. A version
such as v1.0.0-beta.1 is written {version} in a phrase, so a release does not change the
maps. A phrase missing from a map stays English, and the build reports it.
"""
from dataclasses import dataclass
from html import escape
from html.parser import HTMLParser
from pathlib import Path
import json
import re

SOURCE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Language:
    """One edition of the site."""
    code: str       # the BCP 47 tag of the landing page and of hreflang
    prefix: str     # the folder under /sibuna/, "" for English
    gettext: str    # the guidedog language, the name of the book's catalog folder
    label: str      # the language's name in its own script, for the menu
    direction: str  # "ltr" or "rtl"


LANGUAGES = (
    Language("en", "", "en", "English", "ltr"),
    Language("zh-Hans", "zh-hans/", "zh_CN", "简体中文", "ltr"),
    Language("ko", "ko/", "ko", "한국어", "ltr"),
    Language("ja", "ja/", "ja", "日本語", "ltr"),
    Language("es", "es/", "es", "Español", "ltr"),
    Language("de", "de/", "de", "Deutsch", "ltr"),
    Language("hi", "hi/", "hi", "हिन्दी", "ltr"),
    Language("ar", "ar/", "ar", "العربية", "rtl"),
)
ENGLISH = LANGUAGES[0]
TRANSLATIONS = LANGUAGES[1:]

# Text the scripts and the documentation header show, which the landing page's HTML does
# not hold. The demo's step texts come from admission-model.js.
EXTRA_PHRASES = (
    "Home", "Book", "Operations", "Whitepaper", "SIDs", "PDF", "Language:",
    "Play", "Pause", "Playing illustration", "Paused illustration",
    "Reduced motion · step through", "Static view · 3D is unavailable", "Your website",
)
ATTRIBUTES = {"aria-label", "title", "alt", "placeholder"}
PROTECTED = {"code", "pre", "script", "style"}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
        "source", "track", "wbr"}
VERSION = re.compile(r"\bv\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?")
LETTER = re.compile(r"[^\W\d_]")


def normalized(text):
    """A phrase: the text with each run of white space made one space, trimmed."""
    return re.sub(r"\s+", " ", text).strip()


class Phrases(HTMLParser):
    """Rewrites an HTML document with each phrase looked up in a map.

    With words=None it only collects the phrases (in self.found) and copies the page.
    Phrases missing from the map are collected in self.missing and stay English.
    """

    def __init__(self, words=None):
        super().__init__(convert_charrefs=False)
        self.words = words
        self.found = set()
        self.missing = set()
        self.output = []
        self.protected = []  # the open elements whose text we keep as it is

    def phrase(self, text):
        versions = VERSION.findall(text)
        assert len(versions) <= 1, f"one version per phrase: {text!r}"
        if not LETTER.search(VERSION.sub("", text)):
            return text
        key = VERSION.sub("{version}", normalized(text))
        self.found.add(key)
        if self.words is None:
            return text
        if key not in self.words:
            self.missing.add(key)
            return text
        target = self.words[key]
        assert ("{version}" in target) == bool(versions), f"version slot in {key!r}"
        if versions:
            target = target.replace("{version}", versions[0])
        left = " " if text[:1].isspace() else ""
        right = " " if text[-1:].isspace() else ""
        return left + target + right

    def readable(self, tag, attrs, key):
        if key in ATTRIBUTES:
            return True
        return tag == "meta" and key == "content" and ("name", "description") in attrs

    def handle_starttag(self, tag, attrs):
        self.output.append(self.start_tag(tag, attrs, ">"))
        if tag in VOID:
            return
        if self.protected or tag in PROTECTED or ("translate", "no") in attrs:
            self.protected.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.output.append(self.start_tag(tag, attrs, "/>"))

    def start_tag(self, tag, attrs, end):
        parts = [tag]
        for key, value in attrs:
            if value is None:
                parts.append(key)
                continue
            if not self.protected and self.readable(tag, attrs, key):
                value = self.phrase(value)
            parts.append(f'{key}="{escape(value, quote=True)}"')
        return "<" + " ".join(parts) + end

    def handle_endtag(self, tag):
        self.output.append(f"</{tag}>")
        if self.protected and self.protected[-1] == tag:
            self.protected.pop()

    def handle_data(self, data):
        if self.protected:
            self.output.append(data)
        else:
            self.output.append(escape(self.phrase(data), quote=False))

    def handle_comment(self, data):
        self.output.append(f"<!--{data}-->")

    def handle_decl(self, decl):
        self.output.append(f"<!{decl}>")

    def handle_entityref(self, name):
        self.output.append(f"&{name};")

    def handle_charref(self, name):
        self.output.append(f"&#{name};")


def translate(document, words):
    """The document with its phrases translated; also the set of missing phrases."""
    parser = Phrases(words)
    parser.feed(document)
    parser.close()
    assert not parser.protected, "unclosed protected element"
    return "".join(parser.output), parser.missing


def model_phrases():
    """The step titles and texts of the admission demo."""
    model = (SOURCE / "admission-model.js").read_text()
    pattern = r"\[(?:firstTimes|returnTimes)\.\w+,\s*'([^']+)',\s*'([^']+)'\]"
    found = set()
    for match in re.finditer(pattern, model):
        found.update(match.groups())
    found.update(re.findall(r"label: '([^']+)'", model))
    return found


def catalog(english_page):
    """Every phrase a translation map must hold, given the English landing page."""
    parser = Phrases()
    parser.feed(english_page)
    return parser.found | model_phrases() | set(EXTRA_PHRASES)


def load_words(language):
    """The phrase map of a language; English maps each phrase to itself."""
    if language is ENGLISH:
        return {}
    return json.loads((SOURCE / "i18n" / f"{language.code}.json").read_text())


def word(words, phrase):
    """One phrase in a language, or the English phrase when the map lacks it."""
    return words.get(phrase, phrase)


def demo_messages(words, phrases):
    """The JSON the demo script reads to show its texts in the page's language.

    It goes into a <script> element, so a "<" is written as an escape: no translated
    text can end the element early.
    """
    messages = {phrase: words[phrase] for phrase in sorted(phrases) if phrase in words}
    return json.dumps(messages, ensure_ascii=False).replace("<", "\\u003c")


def language_menu(base, route, current, translated):
    """The language menu: a <details> element listing every edition.

    route is the page's path below the edition's folder (such as "book/operations.html",
    or "" for the landing page). When translated is true, each choice opens the same page
    in that language; otherwise the page exists only in English, and a choice opens that
    language's landing page. Each link carries ?lang= so the choice is remembered (see
    site-language.js).
    """
    words = load_words(current)
    links = []
    for language in LANGUAGES:
        same = translated or language is ENGLISH
        target = base + language.prefix + (route if same else "")
        mark = ' aria-current="true"' if language is current else ""
        links.append(f'<a href="{target}?lang={language.code}" lang="{language.code}"'
                     f' data-language-choice="{language.code}"'
                     f' data-same-page="{str(same).lower()}"{mark}>{language.label}</a>')
    label = escape(word(words, "Language:"))
    return (f'<details class="language-menu" translate="no"><summary>'
            f'<span class="language-sr">{label} </span>'
            f'<span lang="{current.code}">{current.label}</span></summary>'
            f'<div>{"".join(links)}</div></details>')


def alternates(site_url, route):
    """The hreflang links of a page that exists in every language."""
    links = [f'<link rel="alternate" hreflang="{language.code}"'
             f' href="{site_url}{language.prefix}{route}">' for language in LANGUAGES]
    links.append(f'<link rel="alternate" hreflang="x-default" href="{site_url}{route}">')
    return "\n".join(links)
