#!/usr/bin/env python3
"""Bundle the tracked source of the checked-out commit as sibuna-<version>-source.tar.gz.

The bundle is `git archive` of HEAD under `sibuna-<version>/` plus SOURCE.txt, which names
the commit and the build command. Crates are fetched from crates.io at build time as
Cargo.lock pins them (`cargo build --locked`); they are not vendored.
"""
import argparse
import io
from pathlib import Path
import subprocess
import tarfile
import time

from release_version import ROOT, version


def package(output):
    if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT):
        raise SystemExit('package-source: the source bundle needs a clean checkout')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    release = version()
    prefix = f'sibuna-{release}/'
    archive = subprocess.check_output(['git', 'archive', '--format=tar', f'--prefix={prefix}',
                                       'HEAD'], cwd=ROOT)
    note = (f'Corresponding source of Sibuna {release}\n'
            f'Repository: https://github.com/insanai/sibuna/tree/v{release}\n'
            f'Commit: {commit}\n\n'
            'Build (Rust 1.94 or later, with the wasm32-unknown-unknown target):\n'
            '  cargo build --release --locked -p sibuna\n'
            'Crate versions are pinned by Cargo.lock; their licenses are listed in\n'
            'LICENSES/THIRD-PARTY-RUST.txt.\n').encode()
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f'sibuna-{release}-source.tar.gz'
    with tarfile.open(fileobj=io.BytesIO(archive)) as source, \
            tarfile.open(destination, 'w:gz') as bundle:
        for member in source.getmembers():
            bundle.addfile(member, source.extractfile(member) if member.isfile() else None)
        info = tarfile.TarInfo(prefix + 'SOURCE.txt')
        info.size, info.mode, info.mtime = len(note), 0o644, int(time.time())
        bundle.addfile(info, io.BytesIO(note))
    print(destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('dist'))
    package(parser.parse_args().output)
