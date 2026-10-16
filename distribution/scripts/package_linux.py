#!/usr/bin/env python3
"""Wrap a verified Linux release archive as Debian, RPM and Arch packages with nfpm.

The packages install the static executable as /usr/bin/sibuna, a stopped systemd unit,
a sysusers entry for the `sibuna` account, the seed helper, /etc/sibuna/service.env (a
configuration file kept on upgrade) and the license files. They are upstream packages,
not packages of any distribution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

from release_version import ROOT

LINUX = ROOT / 'distribution/linux'
RUST_TARGETS = {'amd64': 'x86_64-unknown-linux-musl', 'arm64': 'aarch64-unknown-linux-musl'}
DOCUMENTS = ['LICENSE', 'NOTICE', 'README.md', 'SECURITY.md', 'sibuna.build.json']
DESCRIPTION = ('Web firewall and anti-crawler proxy with proof-of-work admission.\n'
               'Upstream static binary; not an official distribution package.')


def unpack(archive, destination, architecture, release, commit=None):
    """Extracts a release archive after checking its members and manifest."""
    with tarfile.open(archive) as bundle:
        # No links, devices or path traversal, even from a tampered download.
        for entry in bundle.getmembers():
            if not (entry.isfile() or entry.isdir()) or entry.name.startswith('/') \
                    or '..' in Path(entry.name).parts:
                raise ValueError(f'unsafe archive member: {entry.name}')
        bundle.extractall(destination, filter='data')
    manifest = json.loads((destination / 'sibuna.build.json').read_text())
    expected = {'version': release, 'target': RUST_TARGETS[architecture],
                'package': f'linux-{architecture}'}
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise ValueError(f'release manifest mismatch: {key}')
    if commit and manifest.get('commit') != commit:
        raise ValueError('release commit mismatch')
    digest = hashlib.sha256((destination / 'sibuna').read_bytes()).hexdigest()
    if digest != manifest['binary_sha256']:
        raise ValueError('release executable digest mismatch')
    for name in DOCUMENTS + ['LICENSES']:
        if not (destination / name).exists():
            raise ValueError(f'missing release file: {name}')
    return manifest


def contents(extracted):
    """The nfpm file list shared by every package format."""
    files = [{'src': str(extracted / 'sibuna'), 'dst': '/usr/bin/sibuna',
              'file_info': {'mode': 0o755}}]
    for name in DOCUMENTS:
        files.append({'src': str(extracted / name), 'dst': '/usr/share/doc/sibuna/' + name})
    for path in sorted((extracted / 'LICENSES').rglob('*')):
        if path.is_file():
            relative = path.relative_to(extracted / 'LICENSES').as_posix()
            files.append({'src': str(path), 'dst': '/usr/share/doc/sibuna/LICENSES/' + relative})
    files += [
        {'src': str(LINUX / 'sibuna.service'), 'dst': '/usr/lib/systemd/system/sibuna.service'},
        {'src': str(LINUX / 'sibuna.sysusers'), 'dst': '/usr/lib/sysusers.d/sibuna.conf'},
        {'src': str(LINUX / 'seed.sh'), 'dst': '/usr/lib/sibuna/seed.sh',
         'file_info': {'mode': 0o755}},
        {'src': str(LINUX / 'service.env'), 'dst': '/etc/sibuna/service.env',
         'type': 'config|noreplace', 'file_info': {'mode': 0o644}},
    ]
    return files


def license_files(kind, extracted):
    """Format-specific license locations: Debian's copyright file, or /usr/share/licenses."""
    if kind == 'deb':
        copyright_file = extracted / 'copyright'
        texts = '\n\n'.join(f'{path.name}\n\n{path.read_text()}'
                            for path in sorted((extracted / 'LICENSES').iterdir())
                            if path.is_file())
        copyright_file.write_text(
            'Upstream: https://github.com/insanai/sibuna\n\n'
            + (extracted / 'LICENSE').read_text() + '\n' + (extracted / 'NOTICE').read_text()
            + '\n\nFull license texts:\n\n' + texts)
        return [{'src': str(copyright_file), 'dst': '/usr/share/doc/sibuna/copyright'}]
    root = '/usr/share/licenses/' + ('sibuna-bin' if kind == 'archlinux' else 'sibuna')
    sources = [extracted / 'LICENSE', extracted / 'NOTICE',
               *sorted((extracted / 'LICENSES').iterdir())]
    return [{'src': str(path), 'dst': f'{root}/{path.name}'} for path in sources if path.is_file()]


def asset_name(kind, architecture, release):
    """The release asset name: the plain version, whatever each format does with it."""
    if kind == 'deb':
        return f'sibuna_{release}-1_{architecture}.deb'
    if kind == 'rpm':
        machine = {'amd64': 'x86_64', 'arm64': 'aarch64'}[architecture]
        return f'sibuna-{release}-1.{machine}.rpm'
    return f'sibuna-bin-{release}-1-x86_64.pkg.tar.zst'


def config(kind, args, files):
    maintainer = f'Sibuna package maintainers <{args.contact}>'
    settings = {
        'name': 'sibuna-bin' if kind == 'archlinux' else 'sibuna', 'arch': args.arch,
        'platform': 'linux', 'version': args.version, 'version_schema': 'semver',
        'release': '1', 'section': 'net', 'priority': 'optional', 'maintainer': maintainer,
        'description': DESCRIPTION, 'homepage': 'https://insanai.github.io/sibuna/',
        'license': 'LGPL-3.0-or-later', 'contents': files, 'depends': ['systemd'],
        'scripts': {name: str(LINUX / (name + '.sh'))
                    for name in ['postinstall', 'preremove', 'postremove']},
    }
    if kind == 'archlinux':
        settings['provides'] = ['sibuna']
        settings['conflicts'] = ['sibuna']
        settings['archlinux'] = {'packager': maintainer,
                                 'scripts': {'postupgrade': str(LINUX / 'postinstall.sh')}}
    return settings


def package(args):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?', args.version):
        raise ValueError('a semantic version is required')
    if not re.fullmatch(r'[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+', args.contact):
        raise ValueError('a public package contact address is required')
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        extracted = Path(temporary) / 'release'
        extracted.mkdir()
        unpack(args.archive, extracted, args.arch, args.version, args.commit)
        files = contents(extracted)
        kinds = ['deb', 'rpm'] + (['archlinux'] if args.arch == 'amd64' else [])
        for kind in kinds:
            settings = config(kind, args, files + license_files(kind, extracted))
            path = Path(temporary) / f'{kind}.json'
            path.write_text(json.dumps(settings, indent=2))
            target = args.output.resolve() / asset_name(kind, args.arch, args.version)
            subprocess.run(['nfpm', 'package', '--config', str(path), '--packager', kind,
                            '--target', str(target)], check=True)
            print(target)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--arch', choices=RUST_TARGETS, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit')
    parser.add_argument('--contact', required=True)
    parser.add_argument('--output', type=Path, default=Path('dist'))
    try:
        package(parser.parse_args())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'package-linux: {error}\n')
