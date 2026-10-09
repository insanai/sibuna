#!/usr/bin/env python3
"""Exercise security boundaries in release input verification and seed creation."""
import concurrent.futures
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import os
import subprocess
import tempfile
import unittest
from package_linux import unpack

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('seed', ROOT / 'distribution/linux/seed.py')
seed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)


class SeedTests(unittest.TestCase):
    def test_concurrent_first_start_and_restart_preserve_seed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'admission.seed'
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(lambda _: seed.ensure(path), range(16)))
            original = path.read_bytes()
            self.assertEqual(len(original), 32)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            seed.ensure(path)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(list(path.parent.glob('.admission-*')), [])

    def test_refuse_symlink_public_or_invalid_seed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / 'target'; target.write_bytes(b'x' * 32)
            path = root / 'admission.seed'; path.symlink_to(target)
            with self.assertRaises(OSError): seed.ensure(path)
            path.unlink(); path.write_bytes(b'x' * 32); path.chmod(0o644)
            with self.assertRaises(ValueError): seed.ensure(path)
            path.chmod(0o600); path.write_bytes(b'invalid')
            with self.assertRaises(ValueError): seed.ensure(path)
            self.assertEqual(path.read_bytes(), b'invalid')
            root.chmod(0o755)
            with self.assertRaises(ValueError): seed.ensure(path)


class RemovalTests(unittest.TestCase):
    def test_remove_versions_and_upgrade_counts_are_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            systemctl = root / 'systemctl'
            systemctl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$REMOVAL_TEST_LOG"\n')
            systemctl.chmod(0o755)
            script = root / 'preremove.sh'
            # Simulate systemd PID 1 without touching any actual system service.
            script.write_text((ROOT / 'distribution/linux/preremove.sh').read_text().replace(
                '[ -d /run/systemd/system ]', 'true'))
            log = root / 'calls'
            env = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'], 'REMOVAL_TEST_LOG': str(log)}
            for argument in ['0', 'remove', '0.3.3', '1.0.0', '10.1.0']:
                subprocess.run(['sh', str(script), argument], env=env, check=True)
                self.assertEqual(log.read_text().splitlines(), ['stop sibuna.service', 'disable sibuna.service'])
                log.unlink()
            for argument in ['upgrade', '1', '2', '10']:
                subprocess.run(['sh', str(script), argument], env=env, check=True)
                self.assertFalse(log.exists())


class ArchiveTests(unittest.TestCase):
    def test_provenance_and_digest_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'source'; source.mkdir()
            binary = b'validation fixture, not an executable'
            (source / 'sibuna').write_bytes(binary)
            metadata = {'version':'1.2.3', 'target':'x86_64-linux-musl', 'package':'linux-amd64',
                        'features':{'storage':True,'console':True,'cluster':False}, 'optimization':'safe',
                        'stripped':True,'commit':'abc','binary_sha256':hashlib.sha256(binary).hexdigest()}
            (source / 'sibuna.build.json').write_text(json.dumps(metadata))
            (source / 'LICENSES').mkdir()
            for name in ['LICENSE','NOTICE','SOURCE.txt','SECURITY.md','README.md']:
                (source / name).write_text('fixture')
            archive = root / 'input.tar.gz'
            with tarfile.open(archive,'w:gz') as bundle:
                for p in source.iterdir(): bundle.add(p,arcname=p.name)
            unpack(archive,root / 'good','amd64','1.2.3','abc')
            for number, args in enumerate([('arm64','1.2.3','abc'),('amd64','1.2.4','abc'),('amd64','1.2.3','other')]):
                with self.assertRaises(ValueError): unpack(archive,root / str(number),*args)
            metadata['binary_sha256'] = '0'*64
            (source / 'sibuna.build.json').write_text(json.dumps(metadata))
            with tarfile.open(archive,'w:gz') as bundle:
                for p in source.iterdir(): bundle.add(p,arcname=p.name)
            with self.assertRaises(ValueError): unpack(archive,root / 'bad-digest','amd64','1.2.3','abc')

    def test_refuse_traversal_and_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for number, name in enumerate(['../escape', '/escape', 'link']):
                archive=root / f'{number}.tar.gz'
                with tarfile.open(archive,'w:gz') as bundle:
                    entry=tarfile.TarInfo(name)
                    if name == 'link': entry.type=tarfile.SYMTYPE; entry.linkname='/etc/passwd'
                    bundle.addfile(entry,io.BytesIO())
                with self.assertRaises(ValueError): unpack(archive,root / f'out-{number}','amd64','1.2.3')


if __name__ == '__main__': unittest.main()
