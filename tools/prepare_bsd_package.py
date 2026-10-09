#!/usr/bin/env python3
"""Stage an exact-tag BSD executable for native package creation and qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

TARGETS = {'freebsd': ('15.1', 'x86_64-freebsd.15.1'),
           'openbsd': ('7.9', 'x86_64-openbsd.7.9')}
ROOT = Path(__file__).resolve().parents[1]


def git(source, *args):
    return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()


def prepare(source, binary, system, destination, contact, candidate=False):
    if destination.exists():
        raise ValueError('staging destination must not already exist')
    if git(source, 'status', '--porcelain') or git(ROOT, 'status', '--porcelain'):
        raise ValueError('source and packaging recipe checkouts must be clean')
    commit = git(source, 'rev-parse', 'HEAD')
    release = re.search(r'\.version = "([0-9]+\.[0-9]+\.[0-9]+)"',
                        (source / 'build.zig.zon').read_text()).group(1)
    if not candidate and git(source, 'rev-parse', f'v{release}^{{commit}}') != commit:
        raise ValueError('source must be the immutable application tag')
    if not re.fullmatch(r'[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+', contact):
        raise ValueError('an authorized public packaging contact is required')
    if binary.is_symlink() or not binary.is_file():
        raise ValueError('binary must be a regular file')
    minimum, target = TARGETS[system]
    payload = destination / 'payload/usr/local'
    docs = payload / 'share/doc/sibuna'
    docs.mkdir(parents=True)
    (payload / 'bin').mkdir()
    shutil.copyfile(binary, payload / 'bin/sibuna')
    (payload / 'bin/sibuna').chmod(0o755)
    for name in ('README.md', 'LICENSE', 'NOTICE', 'SECURITY.md'):
        shutil.copyfile(source / name, docs / name)
    shutil.copytree(source / 'LICENSES', docs / 'LICENSES',
                    ignore=lambda _, names: [n for n in names if n.startswith('mingw-w64-')
                                             or n == 'musl-COPYRIGHT.txt'])
    manifest = {
        'version': release, 'commit': commit, 'target': target, 'zig': '0.17.0',
        'source': f'https://github.com/insanai/sibuna/tree/{commit if candidate else "v" + release}',
        'release_candidate': candidate,
        'recipe_commit': git(ROOT, 'rev-parse', 'HEAD'), 'os': system, 'minimum_os': minimum,
        'architecture': 'amd64', 'optimization': 'safe', 'stripped': True,
        'features': {'storage': True, 'console': True, 'cluster': False},
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'license': 'AGPL-3.0', 'engine_license': 'LGPL-3.0', 'signed': False,
        'integration': 'CLI only; no service, account, credentials or state created',
    }
    (docs / 'sibuna.build.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (docs / 'SOURCE.txt').write_text(
        f'Corresponding source: {manifest["source"]}\nCommit: {commit}\n' +
        ('Candidate qualification only; no published release/source-bundle claim.\n' if candidate else
         f'Source bundle: https://github.com/insanai/sibuna/releases/download/v{release}/'
         f'sibuna-{release}-source.tar.gz\n') +
        f'Packaging recipe commit: {manifest["recipe_commit"]}\n'
        f'Build natively on {system} {minimum}/amd64 using its system headers/libraries: '
        'zig build -Dcpu=baseline -Doptimize=safe -Dstrip=true '
        '-Dstorage=true -Dconsole=true -Dcluster=false -j2\n'
        'Licenses/notices and pinned dependency sources: LICENSE, LICENSES, NOTICE, build.zig.zon.\n')
    for file in docs.rglob('*'):
        if file.is_file():
            file.chmod(0o644)
    (destination / 'metadata.json').write_text(json.dumps({**manifest, 'contact': contact}, indent=2)
                                             + '\n')
    print(f'{system} {minimum}/amd64: staged {release} from {commit}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--system', choices=TARGETS, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--contact', required=True)
    parser.add_argument('--candidate', action='store_true',
                        help='qualify a clean commit before tagging; never a publishing run')
    args = parser.parse_args()
    prepare(args.source.resolve(), args.binary.resolve(), args.system,
            args.destination.resolve(), args.contact, args.candidate)
