#!/usr/bin/env python3
"""Bundle exact tagged source and pinned SQLite inputs for offline package builds."""
import argparse
import hashlib
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from check_release_version import ROOT, version
from prepare_distribution_source import DEPENDENCIES, prepare


def package(output):
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT):
        raise ValueError('source release requires a clean checkout')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    release = version()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / f'sibuna-{release}'
        root.mkdir()
        # Only tracked source. Cache files, local keys and ignored files never enter the bundle.
        archive = subprocess.check_output(['git', 'archive', 'HEAD'], cwd=ROOT)
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(root, filter='data')
        subprocess.run([sys.executable, str(root / 'tools/console_assets.py'), 'check'], cwd=root, check=True)
        inputs = {}
        for name, dependency in DEPENDENCIES.items():
            data = urllib.request.urlopen(dependency['url'], timeout=120).read()
            directory = Path(temporary) / name
            directory.mkdir()
            with zipfile.ZipFile(io.BytesIO(data)) as bundle:
                for filename in dependency['files']:
                    matches = [n for n in bundle.namelist() if Path(n).name == filename]
                    if len(matches) != 1:
                        raise ValueError(f'{name}: ambiguous or missing {filename}')
                    (directory / filename).write_bytes(bundle.read(matches[0]))
            inputs[name] = directory
        prepare(root, inputs) # exact file/lock digests checked before using dependency bytes
        (root / 'SOURCE.txt').write_text(
            f'Corresponding source: https://github.com/insanai/sibuna/tree/v{release}\nCommit: {commit}\n'
            'SQLite dependency URLs and exact source digests: tools/prepare_distribution_source.py\n'
            'Only dependency paths are changed for offline builds; no source logic is patched.\n'
            'Build: zig build -Doptimize=safe -Dstrip=true -Dstorage=true -Dconsole=true -Dcluster=false -Dcpu=baseline -j2\n')
        output.mkdir(parents=True, exist_ok=True)
        destination = output / f'sibuna-{release}-source.tar.gz'
        with tarfile.open(destination, 'w:gz') as bundle:
            bundle.add(root, arcname=root.name)
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        template = (ROOT / 'distribution/homebrew/sibuna.rb.in').read_text()
        zig = __import__('json').loads((ROOT / 'tools/zig-release.json').read_text())['version']
        (output / 'sibuna.rb').write_text(template.replace('@VERSION@', release).replace('@SHA256@', digest).replace('@ZIG@', zig))
        print(destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('dist'))
    args = parser.parse_args()
    package(args.output)
