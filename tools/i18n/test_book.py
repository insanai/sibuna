"""Protected material and exact coverage are publication requirements, not translator hints."""
import unittest
from pathlib import Path
import tempfile
from .book import blocks, restore, catalog, chapter_source
from .build import remap_assets


class BookTranslationTest(unittest.TestCase):
    def test_round_trip_every_chapter(self):
        root = Path(__file__).resolve().parents[2]
        for name in catalog(root):
            source = chapter_source(root, name)
            self.assertEqual(''.join(restore(b, b.text) for b in blocks(source)), source)

    def test_reorder_math_and_code_without_editing_them(self):
        b = blocks('Check $p = 2^(-b)$ with `--gate`.\n')[0]
        self.assertEqual(restore(b, 'Mit ⟦1⟧ prüfst du ⟦0⟧.\n'),
                         'Mit `--gate` prüfst du $p = 2^(-b)$.\n')
        for broken in ('Missing ⟦0⟧.', 'Duplicate ⟦0⟧ ⟦0⟧ ⟦1⟧.', 'Unknown ⟦0⟧ ⟦2⟧.'):
            with self.assertRaises(ValueError):
                restore(b, broken)

    def test_blank_lines_inside_code_are_not_prose_boundaries(self):
        text = 'An example:\n```zig\nconst x = 1;\n\nconst y = 2;\n```\n\nContinue.\n'
        parsed = blocks(text)
        self.assertEqual(len(parsed[0].slots), 1)
        self.assertIn('const x = 1;\n\nconst y = 2;', parsed[0].slots[0])

    def test_multiline_inline_commands_and_json_are_protected(self):
        source = 'Run `crs test --origin <origin>\n--revision <n>`.\n'
        block = blocks(source)[0]
        self.assertEqual(block.slots, ('`crs test --origin <origin>\n--revision <n>`',))
        self.assertEqual(restore(block, '执行 ⟦0⟧。\n'),
                         '执行 `crs test --origin <origin>\n--revision <n>`。\n')

    def test_document_helpers_cannot_be_omitted(self):
        block = blocks('#exercise("1.1")[Check this claim.]\n')[0]
        restore(block, '#exercise("1.1")[この主張を確認してください。]\n')
        with self.assertRaises(ValueError):
            restore(block, 'この主張を確認してください。\n')
        citation = blocks('Vadhan (CRYPTO 2013) gives the argument.\n')[0]
        restore(citation, 'Vadhan(CRYPTO 2013) でこの議論が示されています。\n')
        field = blocks('There are #data.load.threads workers.\n')[0]
        with self.assertRaises(ValueError):
            restore(field, '#data.load.threads个工作线程。\n')
        restore(field, '#data.load.threads 个工作线程。\n')

    def test_assets_in_branches_and_images_resolve_without_changing_examples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original, destination = root / 'source', root / 'native'
            (original / 'images').mkdir(parents=True)
            (original / 'data.json').write_text('{}')
            (original / 'images/screen.png').touch()
            destination.mkdir()
            source = ('#let data = json(if local { "data.json" } else { "/shared.json" })\n'
                      '#image("images/screen.png")\n#import "theme.typ": *\n'
                      '```typ\n#image("images/screen.png")\n```\n')
            native = remap_assets(source, original, destination)
            self.assertIn('"../source/data.json"', native)
            self.assertIn('#image("../source/images/screen.png")', native)
            self.assertIn('"/shared.json"', native)
            self.assertIn('#import "theme.typ": *', native)
            self.assertIn('```typ\n#image("images/screen.png")\n```', native)
