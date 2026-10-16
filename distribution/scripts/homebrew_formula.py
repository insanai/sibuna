#!/usr/bin/env python3
"""Write the Homebrew formula sibuna.rb for the release archives in a directory.

The formula installs the macOS and Linux release archives (prebuilt, the executables the
release verified) rather than building from source: Homebrew's Rust has no
wasm32-unknown-unknown standard library, which the build needs for the two embedded
WebAssembly modules. `--local` points the URLs at the archives on disk, for testing the
formula before the release exists.
"""
import argparse
import hashlib
from pathlib import Path

from release_version import ROOT, version

PACKAGES = ['macos-arm64', 'macos-amd64', 'linux-arm64', 'linux-amd64']


def write(archives, output, local):
    release = version()
    base = archives.resolve().as_uri() if local else \
        f'https://github.com/insanai/sibuna/releases/download/v{release}'
    formula = (ROOT / 'distribution/homebrew/sibuna.rb.in').read_text()
    formula = formula.replace('@VERSION@', release).replace('@URL@', base)
    for package in PACKAGES:
        archive = archives / f'sibuna-{package}.tar.gz'
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        formula = formula.replace(f'@SHA256_{package}@', digest)
    if any(marker in formula for marker in ('@VERSION@', '@URL@', '@SHA256_')):
        raise SystemExit('homebrew-formula: a placeholder was left in the formula')
    output.write_text(formula)
    print(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archives', type=Path, help='directory with sibuna-<package>.tar.gz')
    parser.add_argument('--output', type=Path, default=Path('dist/sibuna.rb'))
    parser.add_argument('--local', action='store_true', help='use file:// URLs')
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write(args.archives, args.output, args.local)
