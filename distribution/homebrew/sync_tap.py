#!/usr/bin/env python3
"""Import only the formula attached to an upstream qualified stable release."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def synchronize(tag=None, destination=Path('Formula/sibuna.rb')):
    endpoint = 'latest' if tag is None else 'tags/' + tag
    if tag is not None and not re.fullmatch(r'v\d+\.\d+\.\d+', tag):
        raise ValueError('a stable vMAJOR.MINOR.PATCH tag is required')
    release = json.loads(subprocess.check_output(
        ['gh', 'api', 'repos/insanai/sibuna/releases/' + endpoint], text=True))
    tag = release['tag_name']
    if release['draft'] or release['prerelease'] or not re.fullmatch(r'v\d+\.\d+\.\d+', tag):
        raise ValueError('only published stable application releases may update the tap')
    source = f'sibuna-{tag[1:]}-source.tar.gz'
    assets = {a['name']: a for a in release['assets']}
    if 'sibuna.rb' not in assets and endpoint == 'latest':
        print(f'{tag} predates qualified source formula assets; waiting for a newer release')
        return
    for name in ('sibuna.rb', 'SHA256SUMS', source):
        if name not in assets:
            raise ValueError(f'missing release asset: {name}')
    with tempfile.TemporaryDirectory() as scratch:
        subprocess.run(['gh', 'release', 'download', tag, '--repo', 'insanai/sibuna',
                        '--pattern', 'sibuna.rb', '--pattern', 'SHA256SUMS',
                        '--dir', scratch], check=True)
        checksums = {}
        for line in (Path(scratch) / 'SHA256SUMS').read_text().splitlines():
            match = re.fullmatch(r'([a-f0-9]{64})  ([^/\\]+)', line)
            if not match or match[2] in checksums:
                raise ValueError('invalid or duplicate release checksum entry')
            checksums[match[2]] = match[1]
        formula = (Path(scratch) / 'sibuna.rb').read_bytes()
        for name in ('sibuna.rb', source):
            digest = checksums.get(name)
            if digest is None or assets[name].get('digest') != 'sha256:' + digest:
                raise ValueError(f'GitHub asset digest/checksum mismatch: {name}')
        if hashlib.sha256(formula).hexdigest() != checksums['sibuna.rb']:
            raise ValueError('formula checksum mismatch')
        text = formula.decode('utf-8')
        url = f'https://github.com/insanai/sibuna/releases/download/{tag}/{source}'
        if (f'  url "{url}"' not in text
                or f'  sha256 "{checksums[source]}"' not in text
                or re.search(r'@(VERSION|SHA256|ZIG)@', text)
                or not text.startswith('class Sibuna < Formula\n')
                or 'license all_of: ["LGPL-3.0-only", "AGPL-3.0-only"]' not in text):
            raise ValueError('formula provenance, source checksum or licensing mismatch')
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(formula)
        print(f'Imported qualified source formula for {tag}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', help='published stable upstream tag; default latest')
    args = parser.parse_args()
    synchronize(args.tag)
