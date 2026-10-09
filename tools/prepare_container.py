#!/usr/bin/env python3
"""Build a container context exclusively from qualified release archives."""
import argparse
from pathlib import Path
import shutil
import subprocess
from check_release_version import version
from package_linux import ROOT, unpack


def prepare(source, destination, release_commit=None, supplemental_security=None):
    destination.mkdir(parents=True, exist_ok=False)
    packaging_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    commit = release_commit or packaging_commit
    for architecture in ['amd64', 'arm64']:
        target = destination / f'linux-{architecture}'
        target.mkdir()
        unpack(source / f'sibuna-linux-{architecture}.tar.gz', target, architecture, version(), commit,
               require_security=supplemental_security is None)
        # Existing releases predate the policy. Keep their manifests/source offers intact;
        # the supplemental policy belongs to the separately recorded packaging revision.
        if supplemental_security:
            shutil.copyfile(supplemental_security, target / 'SECURITY.md')
    dockerfile = (ROOT / 'distribution/container/Dockerfile').read_text()
    dockerfile += (f'LABEL org.opencontainers.image.source="https://github.com/insanai/sibuna"\n'
                   f'LABEL org.opencontainers.image.version="{version()}"\n'
                   f'LABEL org.opencontainers.image.revision="{commit}"\n'
                   f'LABEL io.sibuna.packaging.revision="{packaging_commit}"\n'
                   'LABEL org.opencontainers.image.licenses="AGPL-3.0-only AND LGPL-3.0-only"\n')
    (destination / 'Dockerfile').write_text(dockerfile)
    shutil.copytree(ROOT / 'distribution/container/state', destination / 'state')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    prepare(args.source, args.destination)
