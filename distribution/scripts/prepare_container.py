#!/usr/bin/env python3
"""Build a container context from the verified Linux release archives of both architectures."""
import argparse
from pathlib import Path
import shutil
import subprocess

from package_linux import unpack
from release_version import ROOT, version


def prepare(source, destination):
    destination.mkdir(parents=True, exist_ok=False)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    release = version()
    for architecture in ['amd64', 'arm64']:
        target = destination / f'linux-{architecture}'
        target.mkdir()
        unpack(source / f'sibuna-linux-{architecture}.tar.gz', target, architecture, release,
               commit)
    dockerfile = (ROOT / 'distribution/container/Dockerfile').read_text()
    dockerfile += (
        'LABEL org.opencontainers.image.title="Sibuna"\n'
        'LABEL org.opencontainers.image.description="Web firewall and anti-crawler proxy"\n'
        'LABEL org.opencontainers.image.source="https://github.com/insanai/sibuna"\n'
        f'LABEL org.opencontainers.image.version="{release}"\n'
        f'LABEL org.opencontainers.image.revision="{commit}"\n'
        'LABEL org.opencontainers.image.licenses="LGPL-3.0-or-later"\n')
    (destination / 'Dockerfile').write_text(dockerfile)
    shutil.copytree(ROOT / 'distribution/container/state', destination / 'state')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='directory with sibuna-linux-*.tar.gz')
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    prepare(args.source, args.destination)
