"""Publication requires all editions, original examples and identical measured tables."""
from collections import Counter
from pathlib import Path
import re
import unittest
from i18n.book import CHAPTERS, render_chapter, PROTECTED, chapter_source
from i18n.locale import LOCALES
from i18n.readme import FILENAMES, render

ROOT = Path(__file__).resolve().parents[2]


def measured_rows(source):
    rows = '\n'.join(line for line in source.splitlines() if line.startswith('|'))
    return Counter(re.findall(r'(?<![A-Za-z])[0-9]+(?:[.,][0-9]+)*', rows))


class CompleteEditionsTest(unittest.TestCase):
    def test_every_book_contains_every_source_chapter(self):
        for locale in LOCALES:
            if locale == 'en':
                continue
            directory = ROOT / 'docs/i18n' / locale / 'book'
            self.assertEqual({path.stem for path in directory.glob('*.json')}, set(CHAPTERS))
            for name in CHAPTERS:
                native = render_chapter(ROOT, locale, name)
                source = chapter_source(ROOT, name)
                # Translators may reorder inline code and equations for native grammar.
                self.assertEqual(Counter(PROTECTED.findall(source)),
                                 Counter(PROTECTED.findall(native)), (locale, name))

    def test_measurement_lookups_cannot_change_with_table_labels(self):
        # The first string in each benchmark row is a display label. Every other
        # quoted value selects the original dataset or a program branch.
        def lookups(text):
            text = re.sub(r'(?m)^  \("[^"\n]+",', '  (LABEL,', text)
            return Counter(re.findall(r'"(?:\\.|[^"\\])*"', text))
        source = chapter_source(ROOT, "measurements")
        for locale in LOCALES:
            if locale != "en":
                native = render_chapter(ROOT, locale, "measurements")
                self.assertEqual(lookups(source), lookups(native), locale)

    def test_readmes_include_all_examples_and_measurements(self):
        original = (ROOT / 'README.md').read_text()
        for locale, suffix in FILENAMES.items():
            native = render(ROOT, locale)
            self.assertEqual((ROOT / f'README.{suffix}.md').read_text(), native)
            self.assertEqual(measured_rows(original), measured_rows(native), locale)
            self.assertEqual(re.findall(r'```[\s\S]*?```', original),
                             re.findall(r'```[\s\S]*?```', native), locale)


if __name__ == '__main__':
    unittest.main()
