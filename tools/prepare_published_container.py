#!/usr/bin/env python3
"""Bootstrap a chart image from immutable, checksum-verified published binaries."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from check_release_version import ROOT, version
from prepare_container import prepare


def prepare_published(tag, destination):
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag) or tag != f'v{version()}':
        raise ValueError('published app tag must match the current chart/application version')
    repository = 'insanai/sibuna'
    release = json.loads(subprocess.check_output([
        'gh', 'release', 'view', tag, '--repo', repository,
        '--json', 'isDraft,isPrerelease,tagName,assets']))
    if release['isDraft'] or release['isPrerelease'] or release['tagName'] != tag:
        raise ValueError('a published stable application release is required')
    commit = subprocess.check_output(['git', 'rev-parse', f'{tag}^{{commit}}'],
                                     cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary)
        names = ['SHA256SUMS', 'sibuna-linux-amd64.tar.gz', 'sibuna-linux-arm64.tar.gz']
        assets = {asset['name']: asset for asset in release['assets']}
        for name in names:
            if name not in assets:
                raise ValueError(f'missing published asset: {name}')
            subprocess.run(['gh', 'release', 'download', tag, '--repo', repository,
                            '--pattern', name, '--dir', str(source)], check=True)
            api_digest = assets[name].get('digest')
            if api_digest and api_digest != 'sha256:' + hashlib.sha256((source / name).read_bytes()).hexdigest():
                raise ValueError(f'GitHub asset digest mismatch: {name}')
        digests = {}
        for line in (source / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split()
            name = name.removeprefix('*')
            if name in digests or not re.fullmatch(r'[0-9a-f]{64}', digest):
                raise ValueError('malformed or duplicate published checksum')
            digests[name] = digest
        for name in names[1:]:
            if hashlib.sha256((source / name).read_bytes()).hexdigest() != digests.get(name):
                raise ValueError(f'published checksum mismatch: {name}')
        prepare(source, destination, release_commit=commit, supplemental_security=ROOT / 'SECURITY.md')
    print(f'verified published binaries: {tag}, source commit {commit}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tag')
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    prepare_published(args.tag, args.destination)
