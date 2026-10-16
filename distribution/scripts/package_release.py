#!/usr/bin/env python3
"""Package a verified executable with its license files and a build manifest.

The archive (`sibuna-<package>.tar.gz`, or `.zip` for Windows) holds the executable, LICENSE,
NOTICE, LICENSES/, README.md, SECURITY.md and `sibuna.build.json`: the version, commit,
Rust target, rustc version, features and the SHA-256 of the executable and of the two
embedded WebAssembly modules.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

from release_version import ROOT, version

# Release package name -> Rust target and the oldest system the build is meant for.
TARGETS = {
    'linux-amd64': ('x86_64-unknown-linux-musl', 'Linux 4.19 or later (static musl)'),
    'linux-arm64': ('aarch64-unknown-linux-musl', 'Linux 4.19 or later (static musl)'),
    'macos-arm64': ('aarch64-apple-darwin', 'macOS 12 or later'),
    'macos-amd64': ('x86_64-apple-darwin', 'macOS 12 or later'),
    'windows-amd64': ('x86_64-pc-windows-msvc', 'Windows 10, Server 2016 or later'),
    'freebsd-amd64': ('x86_64-unknown-freebsd', 'FreeBSD 15.1'),
    'openbsd-amd64': ('x86_64-unknown-openbsd', 'OpenBSD 7.9'),
}
DOCUMENTS = ('LICENSE', 'NOTICE', 'README.md', 'SECURITY.md')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()


def manifest(binary, package):
    """The build manifest of `binary`, built for the release package `package`."""
    target, requirements = TARGETS[package]
    wasm = {}
    for variable, name in (('SIBUNA_POW_WASM', 'sibuna-pow.wasm'),
                           ('SIBUNA_CONSOLE_WASM', 'console.wasm')):
        if os.environ.get(variable):
            wasm[name] = sha256(os.environ[variable])
    release = version()
    return {
        'name': 'sibuna',
        'version': release,
        'commit': git('rev-parse', 'HEAD'),
        'source': f'https://github.com/insanai/sibuna/tree/v{release}',
        'package': package,
        'target': target,
        'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
        'profile': 'release',
        'features': ['sqlite', 'console'],
        'binary_sha256': sha256(binary),
        'wasm_sha256': wasm,
        'license': 'LGPL-3.0-or-later',
        'signed': False,
        'requirements': requirements,
    }


def stage(binary, package, root):
    """Copies the executable, the documents and the manifest into `root`."""
    shutil.copyfile(binary, root / binary.name)
    (root / binary.name).chmod(0o755)
    for name in DOCUMENTS:
        shutil.copyfile(ROOT / name, root / name)
    # The musl notice belongs only to the statically linked Linux executables.
    linux = package.startswith('linux-')
    shutil.copytree(ROOT / 'LICENSES', root / 'LICENSES',
                    ignore=lambda _, names: [] if linux else
                    [name for name in names if name == 'musl-COPYRIGHT.txt'])
    data = manifest(binary, package)
    (root / 'sibuna.build.json').write_text(json.dumps(data, indent=2) + '\n')


def package(binary, package_name, destination):
    if git('status', '--porcelain', '--untracked-files=no'):
        raise SystemExit('package-release: release archives need a clean checkout')
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        stage(binary, package_name, root)
        files = sorted(path for path in root.rglob('*') if path.is_file())
        if package_name.startswith('windows-'):
            archive = destination / f'sibuna-{package_name}.zip'
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
                for file in files:
                    bundle.write(file, file.relative_to(root).as_posix())
        else:
            archive = destination / f'sibuna-{package_name}.tar.gz'
            with tarfile.open(archive, 'w:gz') as bundle:
                for file in files:
                    bundle.add(file, arcname=file.relative_to(root).as_posix())
    print(archive)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--package', choices=TARGETS, required=True)
    parser.add_argument('--output', type=Path, default=Path('dist'))
    args = parser.parse_args()
    package(args.binary.resolve(), args.package, args.output)
