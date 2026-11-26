"""Shared site languages and translated navigation for the book, whitepaper and SIDs.

The landing theme and these document headers read the same Guidedog gettext catalogs.
"""
from dataclasses import dataclass
from functools import lru_cache
from html import escape
from pathlib import Path
import json
import re
import tomllib

SOURCE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Language:
    """One edition of the site."""
    code: str       # the BCP 47 tag of the landing page and of hreflang
    prefix: str     # the folder under /sibuna/, "" for English
    gettext: str    # the guidedog language, the name of the catalog folders
    label: str      # the language's name in its own script, for the menu
    direction: str  # "ltr" or "rtl"


_context = tomllib.loads((SOURCE / "home/conf.toml").read_text())["html_context"]
LANGUAGES = tuple(Language(**edition) for edition in _context["site_languages"])
ENGLISH = LANGUAGES[0]
TRANSLATIONS = LANGUAGES[1:]


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


@lru_cache(maxsize=None)
def load_words(language):
    """Read the same interface catalog used by the landing page's Guidedog theme."""
    return catalog_messages(SOURCE / "home/locales" / language.gettext / "LC_MESSAGES/guidedog.po")


def word(words, phrase):
    """One phrase in a language, or the English phrase when the map lacks it."""
    return words.get(phrase, phrase)


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
