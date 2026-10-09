#!/usr/bin/env python3
"""Check that tap imports refuse altered release bytes and source provenance."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sync_tap', ROOT / 'distribution/homebrew/sync_tap.py')
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


class TapImportTests(unittest.TestCase):
    def fixture(self, alteration=None):
        source = 'sibuna-1.2.3-source.tar.gz'
        source_digest = 'a' * 64
        formula = (ROOT / 'distribution/homebrew/sibuna.rb.in').read_text().replace(
            '@VERSION@', '1.2.3').replace('@SHA256@', source_digest).replace('@ZIG@', '0.17.0').encode()
        if alteration == 'wrong_source':
            formula = formula.replace(b'/v1.2.3/', b'/v9.9.9/')
        digest = hashlib.sha256(formula).hexdigest()
        assets = [{'name': 'sibuna.rb', 'digest': 'sha256:' + digest},
                  {'name': source, 'digest': 'sha256:' + source_digest},
                  {'name': 'SHA256SUMS'}]
        if alteration == 'asset_digest':
            assets[1]['digest'] = 'sha256:' + 'b' * 64
        release = {'tag_name': 'v1.2.3', 'draft': False, 'prerelease': False, 'assets': assets}

        def download(command, **_):
            directory = Path(command[command.index('--dir') + 1])
            (directory / 'sibuna.rb').write_bytes(formula + (b'# altered\n' if alteration == 'bytes' else b''))
            (directory / 'SHA256SUMS').write_text(f'{digest}  sibuna.rb\n{source_digest}  {source}\n')

        return formula, release, download

    def test_qualified_formula_import_and_idempotence(self):
        formula, release, download = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / 'Formula/sibuna.rb'
            with patch.object(sync.subprocess, 'check_output', return_value=json.dumps(release)), \
                    patch.object(sync.subprocess, 'run', side_effect=download):
                sync.synchronize(destination=destination)
                sync.synchronize(destination=destination)
            self.assertEqual(destination.read_bytes(), formula)

    def test_tampering_and_wrong_source_preserve_existing_formula(self):
        for alteration in ('bytes', 'asset_digest', 'wrong_source'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                _, release, download = self.fixture(alteration)
                destination = Path(temporary) / 'sibuna.rb'
                destination.write_bytes(b'existing qualified formula')
                with patch.object(sync.subprocess, 'check_output', return_value=json.dumps(release)), \
                        patch.object(sync.subprocess, 'run', side_effect=download):
                    with self.assertRaises(ValueError):
                        sync.synchronize(destination=destination)
                self.assertEqual(destination.read_bytes(), b'existing qualified formula')


if __name__ == '__main__':
    unittest.main()
