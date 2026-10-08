"""Shared language metadata for the site and complete translated Typst books."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCALES = json.loads((ROOT / "docs/i18n/locales.json").read_text())


def metadata(locale):
    return LOCALES[locale]


def language_choices(route, locale):
    translatable = not route or route.startswith("book/")
    result = []
    for code, words in LOCALES.items():
        target = route if translatable or code == "en" else ""
        result.append({"locale": code, "label": words["label"],
                       "path": words["prefix"] + target,
                       "same_page": translatable or code == "en", "selected": code == locale})
    return result


def source_revision(root):
    """Record source identity without depending on uncommitted Git state."""
    from hashlib import sha256
    from .book import CHAPTERS, chapter_source
    return {name: sha256(chapter_source(root, name).encode()).hexdigest()
            for name in CHAPTERS}
