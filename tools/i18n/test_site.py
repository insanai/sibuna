"""Language routing and document wrappers preserve content and browser safety."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from i18n.html import Prose, safe_json, translate_fragment, words
from i18n.locale import LOCALES, language_choices
from site_html import stable_headings
from i18n.tables import contract, isolate_numbers
from i18n.assets import version

ROOT = Path(__file__).resolve().parents[2]


class SiteTranslationTest(unittest.TestCase):
    def test_every_site_catalog_covers_current_ui(self):
        for locale in LOCALES:
            dictionary = words(ROOT, locale)
            for name in ('index.html', 'admission-demo.html'):
                source = (ROOT / 'docs/site' / name).read_text()
                native = translate_fragment(source, dictionary)
                before, after = Prose(), Prose()
                before.feed(source)
                after.feed(native)
                self.assertEqual(len(before.output), len(after.output))

    def test_examples_attributes_and_versions_remain_safe(self):
        source = '<a href="/book/?v=1" title="Try v0.3.3">Read</a><pre>some code</pre>'
        result = translate_fragment(source, {'Try ⟦0⟧': 'Prueba ⟦0⟧', 'Read': '<Leer>'})
        self.assertIn('href="/book/?v=1"', result)
        self.assertIn('title="Prueba v0.3.3"', result)
        self.assertIn('&lt;Leer&gt;', result)
        self.assertIn('<pre>some code</pre>', result)
        self.assertNotIn('</script>', safe_json({'text': '</script><script>alert(1)'}))
        with self.assertRaises(ValueError):
            translate_fragment('Try v0.3.3', {'Try ⟦0⟧': 'Try'})

    def test_language_switch_preserves_section_and_english_records(self):
        choices = language_choices('book/operations.html', 'ar')
        self.assertTrue(all(choice['same_page'] for choice in choices))
        self.assertEqual(choices[-1]['path'], 'ar/book/operations.html')
        choices = language_choices('sid/0007-console.html', 'en')
        self.assertEqual(choices[0]['path'], 'sid/0007-console.html')
        self.assertTrue(all(not c['same_page'] for c in choices[1:]))
        original = '<h2 id="origin">A</h2><h3 id="detail">B</h3>'
        translated = '<h2 id="native">甲</h2><h3 id="more">乙</h3><a href="#more">丙</a>'
        native = stable_headings(original, translated)
        self.assertIn('id="origin"', native)
        self.assertIn('href="#detail"', native)
        with self.assertRaises(AssertionError):
            stable_headings(original, '<h2 id="native">甲</h2>')

    def test_table_labels_can_change_but_coverage_and_numbers_cannot(self):
        source = '<table><tr><th>Latency</th><td><b>2.3 ms</b></td></tr></table>'
        native = '<table><tr><th>الزمن</th><td><b>2.3 ms</b></td></tr></table>'
        self.assertEqual(contract(source), contract(native))
        isolated = isolate_numbers(native)
        self.assertIn('<td dir="ltr"><b>2.3 ms</b></td>', isolated)
        self.assertEqual(contract(native), contract(isolated))
        self.assertIn('<bdi dir="ltr">2026-10-07T08:46:12+00:00</bdi>',
                      isolate_numbers('<p>سجل 2026-10-07T08:46:12+00:00</p>'))
        self.assertNotEqual(contract(source), contract(native.replace('2.3', '3.2')))
        self.assertNotEqual(contract(source), contract('<table><td>2.3 ms</td></table>'))

    def test_cached_animation_version_changes_with_lazy_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('admission-animation.js', 'admission-model.js',
                         'admission-scene.bundle.js'):
                (root / name).write_text(name)
            initial = version(root, 'admission-animation.js')
            (root / 'admission-scene.bundle.js').write_text('new renderer')
            updated = version(root, 'admission-animation.js')
            self.assertNotEqual(initial, updated)
            (root / 'admission-model.js').write_text('new journey')
            self.assertNotEqual(updated, version(root, 'admission-animation.js'))

    def test_browser_language_matching(self):
        source = (ROOT / 'docs/site/site-language.js').as_uri()
        script = f'''import {{ languageCode, preferredLanguage }} from {json.dumps(source)};
import assert from 'node:assert/strict';
for (const [input, expected] of Object.entries({{
    'zh-CN':'zh-Hans', 'zh-SG':'zh-Hans', 'zh-Hans-TW':'zh-Hans', 'zh':'zh-Hans',
    'zh-Hant-CN':null, 'zh-CN-Hant':null, 'zh-TW':null, 'ja-Hans': 'ja',
    'ko-KR':'ko', 'ja-JP':'ja', 'es-MX':'es', 'de-CH':'de', 'hi-IN':'hi', 'ar-EG':'ar'
}})) assert.equal(languageCode(input), expected);
assert.equal(preferredLanguage('en', ['ar']), 'en');
assert.equal(preferredLanguage(null, ['fr-FR', 'ko-KR']), 'ko');
assert.equal(preferredLanguage('invalid', ['fr-FR']), 'en');
'''
        with tempfile.NamedTemporaryFile(suffix='.mjs', mode='w') as file:
            file.write(script)
            file.flush()
            subprocess.run(['node', file.name], check=True)


if __name__ == '__main__':
    unittest.main()
