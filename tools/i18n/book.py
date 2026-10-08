"""Build complete translated books without copying examples or mathematical expressions."""
from dataclasses import dataclass
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import re

CHAPTERS = (
    "00_front", "00_learning", "01_foundations", "02_prior_art", "03_cryptography",
    "04_protocol", "05_zero_alloc", "06_algorithms", "07_wasm_engine", "08_benchmarks",
    "09_operations", "10_reference", "11_quick_reference", "12_solutions", "13_glossary",
    "comparison", "products", "product_admission", "crs_request_path", "measurements",
)
# Raw examples and equations are immutable slots. Translators may reorder inline slots
# to fit the grammar, but may neither omit them nor change the enclosed source.
PROTECTED = re.compile(r"```[\s\S]*?```|`[^`]+`|(?<!\\)\$[\s\S]*?(?<!\\)\$"
                       r"|https?://[^\s\")>\]]+|(?<=\]\()[^)]+"
                       r'|(?:href|src|srcset)="[^"]+"' )
DIRECTIVE = re.compile(r"^\s*#(?:import|include|pagebreak|v\(|counter\(|show:)")
SLOT = re.compile(r"⟦(\d+)⟧")
CALL = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\(")
MACRO = re.compile(r"#[^\W\d]\w*(?:\.[^\W\d]\w*)*")


@dataclass(frozen=True)
class Block:
    key: str
    source: str
    text: str
    slots: tuple[str, ...]
    translated: bool


def split_blocks(source):
    """Blank lines separate prose; fenced listings stay within their enclosing block."""
    parts = []
    current = []
    fence = False
    for line in source.splitlines(keepends=True):
        if line.lstrip().startswith("```"):
            fence = not fence
        if not line.strip() and not fence:
            if current:
                parts.append("".join(current))
                current = []
            parts.append(line)
        else:
            current.append(line)
    if current:
        parts.append("".join(current))
    assert not fence, "unterminated raw example"
    return parts


def blocks(source):
    result = []
    for part in split_blocks(source):
        slots = []
        def protect(match):
            slots.append(match[0])
            return f"⟦{len(slots) - 1}⟧"
        text = PROTECTED.sub(protect, part)
        prose = "\n".join(line for line in text.splitlines()
                          if not line.lstrip().startswith("//"))
        translated = bool(re.search(r"[A-Za-z]{3}", SLOT.sub("", prose)))
        if part.startswith("<!-- language-navigation -->") or all(
                not line.strip() or DIRECTIVE.match(line) for line in prose.splitlines()):
            translated = False
        result.append(Block(sha256(part.encode()).hexdigest()[:16], part, text,
                            tuple(slots), translated))
    assert "".join(block.source for block in result) == source
    return result


def restore(block, text):
    numbers = [int(match[1]) for match in SLOT.finditer(text)]
    if sorted(numbers) != list(range(len(block.slots))):
        raise ValueError(f"missing, duplicate or unknown protected slot in {block.key}")
    # Keep executable Typst structure as well as its math and raw material. This catches
    # omitted exercises, callouts and data calculations before the edition is compiled.
    source_calls = Counter(CALL.findall(block.text))
    native_calls = Counter(CALL.findall(text))
    if any(native_calls[name] != count for name, count in source_calls.items()):
        raise ValueError(f"changed document calls in {block.key}")
    if Counter(MACRO.findall(block.text)) != Counter(MACRO.findall(text)):
        raise ValueError(f"changed document structure in {block.key}")
    return SLOT.sub(lambda match: block.slots[int(match[1])], text)


def chapter_source(root, name):
    if name == "measurements":
        from .measurements import source
        return source(root)
    return (root / "docs/book" / f"{name}.typ").read_text()


def catalog(root):
    result = {}
    for name in CHAPTERS:
        source = chapter_source(root, name)
        result[name] = {block.key: block.text for block in blocks(source) if block.translated}
    return result


def render_chapter(root, locale, name):
    source = chapter_source(root, name)
    path = root / "docs/i18n" / locale / "book" / f"{name}.json"
    translations = json.loads(path.read_text())
    segments = blocks(source)
    expected = {block.key for block in segments if block.translated}
    if set(translations) != expected:
        missing = expected - set(translations)
        obsolete = set(translations) - expected
        raise ValueError(f"{locale}/{name}: {len(missing)} missing; {len(obsolete)} obsolete")
    return "".join(restore(block, translations[block.key]) if block.translated
                   else block.source for block in segments)


def write_sources(root, locale, destination):
    destination.mkdir(parents=True, exist_ok=True)
    for name in CHAPTERS:
        (destination / f"{name}.typ").write_text(render_chapter(root, locale, name))
    # Preserve the original drawings. Only table prose and provenance labels vary.
    original = root / "docs/book"
    for name in ("theme", "figures"):
        relative = Path(os.path.relpath(original / f"{name}.typ", destination))
        header = f'#import "{relative.as_posix()}": *\n'
        if name == "figures":
            header += '#import "measurements.typ": *\n'
        (destination / f"{name}.typ").write_text(header)
    relative = Path(os.path.relpath(original / "figures.typ", destination))
    path = destination / "measurements.typ"
    path.write_text(f'#import "{relative.as_posix()}": *\n#import "theme.typ": *\n'
                    + path.read_text())
