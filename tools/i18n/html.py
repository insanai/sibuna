"""Translate site prose while retaining markup, addresses, IDs and executable examples."""
from html import escape
from html.parser import HTMLParser
import json
import re

ATTRIBUTES = {"aria-label", "placeholder", "title", "alt"}
PROTECTED = {"code", "pre", "script", "style"}
VERSION = re.compile(r"\bv[0-9]+\.[0-9]+\.[0-9]+\b")
SHELL_TEXT = (
    "Skip to content", "Main", "Book", "Operations", "SIDs", "GitHub ↗", "Search",
    "Language", "Documentation", "The book", "Architecture", "Design discussions",
    "Companies seeking alternative licensing can contact the authors.",
    "Engine: LGPL 3.0 · Console: AGPL 3.0",
    "Third-party libraries retain their respective licenses.", "Search the documentation",
    "Close search", "Words or a topic", "Try uploads, challenges, or policies",
    "View source ↗", "Download PDF ↓", "Web application protection", "Operations and deployment",
    "CLI and protocol reference", "No matching pages. Try a shorter term.",
    "Search could not load. Use the documentation navigation or try again.",
    "Play", "Pause", "Playing illustration", "Paused illustration",
    "Reduced motion · step through", "Static view · 3D is unavailable", "Your website",
)


def normalized(text):
    return re.sub(r"\s+", " ", text).strip()


class Prose(HTMLParser):
    def __init__(self, words=None):
        super().__init__(convert_charrefs=False)
        self.words = words
        self.keys = set()
        self.output = []
        self.protected = []

    def translated(self, text):
        values = []
        def version(match):
            values.append(match[0])
            return f"⟦{len(values) - 1}⟧"
        key = VERSION.sub(version, normalized(text))
        if not key:
            return text
        self.keys.add(key)
        if self.words is None:
            return text
        if key not in self.words:
            raise ValueError(f"site translation missing: {key}")
        left = " " if text[:1].isspace() else ""
        right = " " if text[-1:].isspace() else ""
        target = self.words[key]
        slots = re.findall(r"⟦(\d+)⟧", target)
        if sorted(map(int, slots)) != list(range(len(values))):
            raise ValueError(f"site version slots changed: {key}")
        target = re.sub(r"⟦(\d+)⟧", lambda m: values[int(m[1])], target)
        return left + target + right

    def handle_starttag(self, tag, attrs):
        translated = []
        for key, value in attrs:
            if key in ATTRIBUTES and value:
                value = self.translated(value)
            translated.append(key if value is None else f'{key}="{escape(value, quote=True)}"')
        suffix = " " + " ".join(translated) if attrs else ""
        self.output.append(f"<{tag}{suffix}>")
        if tag in PROTECTED:
            self.protected.append(tag)

    def handle_endtag(self, tag):
        self.output.append(f"</{tag}>")
        if tag in PROTECTED:
            assert self.protected.pop() == tag

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.output[-1] = self.output[-1][:-1] + "/>"

    def handle_data(self, data):
        self.output.append(data if self.protected else escape(self.translated(data), quote=False))

    def handle_comment(self, data):
        self.output.append(f"<!--{data}-->")

    def handle_entityref(self, name):
        self.output.append(f"&{name};")

    def handle_charref(self, name):
        self.output.append(f"&#{name};")


def site_catalog(root):
    parser = Prose()
    for name in ("index.html", "admission-demo.html"):
        parser.feed((root / "docs/site" / name).read_text())
    keys = parser.keys | set(SHELL_TEXT)
    model = (root / "docs/site/admission-model.js").read_text()
    pattern = r"\[(?:firstTimes|returnTimes)\.\w+,\s*'([^']+)',\s*'([^']+)'\]"
    for match in re.finditer(pattern, model):
        keys.update(match.groups())
    return {key: key for key in sorted(keys)}


def words(root, locale):
    if locale == "en":
        return site_catalog(root)
    result = json.loads((root / "docs/i18n" / locale / "site.json").read_text())
    expected = set(site_catalog(root))
    if set(result) != expected:
        raise ValueError(f"{locale} site: {len(expected - set(result))} missing; "
                         f"{len(set(result) - expected)} obsolete phrases")
    return result


def translate_fragment(source, dictionary):
    parser = Prose(dictionary)
    parser.feed(source)
    parser.close()
    assert not parser.protected
    return "".join(parser.output)


def safe_json(value):
    # A data script is still raw HTML: prevent a translated string from closing it.
    return json.dumps(value, ensure_ascii=False).replace("<", "\\u003c")
