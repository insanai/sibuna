"""Generate translated READMEs from complete, reviewed prose catalogs."""
from hashlib import sha256
import json
import re
from .book import blocks, restore
from .locale import ROOT

FILENAMES = {"zh-Hans": "zh-CN", "ko": "ko", "ja": "ja", "es": "es", "de": "de",
             "hi": "hi", "ar": "ar"}


def catalog(root):
    source = (root / "README.md").read_text()
    return {block.key: block.text for block in blocks(source) if block.translated}


def render(root, locale):
    source = (root / "README.md").read_text()
    target = json.loads((root / "docs/i18n" / locale / "readme.json").read_text())
    parts = blocks(source)
    expected = {block.key for block in parts if block.translated}
    if set(target) != expected:
        raise ValueError(f"{locale} README has missing or obsolete translation blocks")
    result = []
    for block in parts:
        translated = restore(block, target[block.key]) if block.translated else block.source
        # Stable English anchors keep the README's navigation usable in every edition.
        if block.source.startswith("##"):
            title = block.source.splitlines()[0].lstrip("# ")
            anchor = re.sub(r"[^a-z0-9 -]", "", title.lower()).replace(" ", "-")
            translated = f'<a id="{anchor}"></a>\n\n' + translated
        result.append(translated)
    text = "".join(result)
    prefix = "zh-hans" if locale == "zh-Hans" else locale
    text = text.replace("https://insanai.github.io/sibuna/book/",
                        f"https://insanai.github.io/sibuna/{prefix}/book/")
    if locale == "ar":
        # Let GitHub retain the document's direction while isolating executable examples.
        text = re.sub(r"(```[\s\S]*?```)", r'<div dir="ltr">\n\n\1\n\n</div>', text)
        text = '<div dir="rtl">\n\n' + text + '\n</div>\n'
    digest = sha256(source.encode()).hexdigest()
    return f'<!-- English source SHA-256: {digest} -->\n' + text


def write(root, locale):
    path = root / f"README.{FILENAMES[locale]}.md"
    path.write_text(render(root, locale))
    return path


if __name__ == '__main__':
    for language in FILENAMES:
        print(write(ROOT, language).relative_to(ROOT))
