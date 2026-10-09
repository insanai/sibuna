#!/usr/bin/env python3
"""Wrap a qualified upstream Linux archive as deb/rpm/Arch packages (not distro inclusion)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def unpack(archive, destination, architecture, release, commit=None, require_security=True):
    with tarfile.open(archive) as bundle:
        # No links/devices or traversal in input, even when a release download is compromised.
        for entry in bundle.getmembers():
            if not (entry.isfile() or entry.isdir()) or entry.name.startswith('/') or '..' in Path(entry.name).parts:
                raise ValueError(f"unsafe archive member: {entry.name}")
        bundle.extractall(destination, filter='data')
    manifest = json.loads((destination / 'sibuna.build.json').read_text())
    target = {'amd64': 'x86_64-linux-musl', 'arm64': 'aarch64-linux-musl'}[architecture]
    expected = {'version': release, 'target': target, 'package': f'linux-{architecture}',
                'features': {'storage': True, 'console': True, 'cluster': False},
                'optimization': 'safe', 'stripped': True}
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise ValueError(f"release manifest mismatch: {key}")
    if commit and manifest.get('commit') != commit:
        raise ValueError('release commit mismatch')
    if hashlib.sha256((destination / 'sibuna').read_bytes()).hexdigest() != manifest['binary_sha256']:
        raise ValueError('release executable digest mismatch')
    names = ['LICENSE', 'LICENSES', 'NOTICE', 'SOURCE.txt', 'README.md']
    if require_security:
        names.append('SECURITY.md')
    for name in names:
        if not (destination / name).exists():
            raise ValueError(f'missing release documentation: {name}')
    return manifest


def package(args):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', args.version):
        raise ValueError('stable semantic release required')
    if not re.fullmatch(r'[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+', args.contact):
        raise ValueError('a real public project contact is required')
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        extracted = Path(temporary) / 'release'
        extracted.mkdir()
        unpack(args.archive, extracted, args.arch, args.version, args.commit)
        contents = [{'src': str(extracted / 'sibuna'), 'dst': '/usr/bin/sibuna', 'file_info': {'mode': 0o755}}]
        for name in ['LICENSE', 'NOTICE', 'SOURCE.txt', 'SECURITY.md', 'README.md', 'sibuna.build.json']:
            contents.append({'src': str(extracted / name), 'dst': '/usr/share/doc/sibuna/' + name})
        for license_file in sorted((extracted / 'LICENSES').rglob('*')):
            if license_file.is_file():
                contents.append({'src': str(license_file), 'dst': '/usr/share/doc/sibuna/LICENSES/' + str(license_file.relative_to(extracted / 'LICENSES'))})
        for src, dst in [('sibuna.service', '/usr/lib/systemd/system/sibuna.service'),
                         ('sibuna.sysusers', '/usr/lib/sysusers.d/sibuna.conf')]:
            contents.append({'src': str(ROOT / 'distribution/linux' / src), 'dst': dst})
        contents += [
            {'src': str(ROOT / 'distribution/linux/seed.py'), 'dst': '/usr/lib/sibuna/seed.py', 'file_info': {'mode': 0o755}},
            {'src': str(ROOT / 'distribution/linux/service.env'), 'dst': '/etc/sibuna/service.env',
             'type': 'config|noreplace', 'file_info': {'mode': 0o644}},
        ]
        copyright_file = extracted / 'copyright'
        copyright_file.write_text(
            'Upstream: https://github.com/insanai/sibuna\n'
            'Copyright and license scopes:\n\n' + (extracted / 'LICENSE').read_text() + '\n' +
            (extracted / 'NOTICE').read_text() + '\n\nFull component license texts:\n\n' +
            '\n\n'.join(f'{p.name}\n{p.read_text()}' for p in sorted((extracted / 'LICENSES').iterdir()) if p.is_file()))
        formats = ['deb', 'rpm'] + (['archlinux'] if args.arch == 'amd64' else [])
        for kind in formats:
            format_contents = contents[:]
            if kind == 'deb':
                format_contents.append({'src': str(copyright_file), 'dst': '/usr/share/doc/sibuna/copyright'})
            else:
                license_root = '/usr/share/licenses/' + ('sibuna-bin' if kind == 'archlinux' else 'sibuna')
                for source in [extracted / 'LICENSE', extracted / 'NOTICE', *sorted((extracted / 'LICENSES').iterdir())]:
                    if source.is_file():
                        format_contents.append({'src': str(source), 'dst': license_root + '/' + source.name})
            config = {
                'name': 'sibuna-bin' if kind == 'archlinux' else 'sibuna', 'arch': args.arch,
                'platform': 'linux', 'version': args.version, 'version_schema': 'semver', 'release': '1',
                'section': 'web', 'priority': 'optional',
                'maintainer': f'Sibuna package maintainers <{args.contact}>',
                'description': 'Sibuna admission proxy with proof-of-work challenges and WAF inspection.\nUpstream static binary; not an official distribution package.',
                'homepage': 'https://github.com/insanai/sibuna', 'license': 'AGPL-3.0-only AND LGPL-3.0-only',
                'contents': format_contents, 'depends': ['systemd', 'python' if kind == 'archlinux' else 'python3'],
                'scripts': {name: str(ROOT / 'distribution/linux' / (name + '.sh'))
                            for name in ['postinstall', 'preremove', 'postremove']},
            }
            if kind == 'archlinux':
                config['provides'] = [f'sibuna={args.version}']
                config['conflicts'] = ['sibuna']
                config['archlinux'] = {'packager': config['maintainer'], 'scripts': {'postupgrade': str(ROOT / 'distribution/linux/postinstall.sh')}}
            config_path = Path(temporary) / f'{kind}.json'
            config_path.write_text(json.dumps(config, indent=2))
            subprocess.run(['nfpm', 'package', '--config', str(config_path), '--packager', kind,
                            '--target', str(args.output.resolve())], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--arch', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit')
    parser.add_argument('--contact', required=True)
    parser.add_argument('--output', type=Path, default=Path('dist'))
    try:
        package(parser.parse_args())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'linux-package: {error}\n')
