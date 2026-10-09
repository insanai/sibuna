#!/usr/bin/env python3
"""Create a native BSD package from staged immutable-tag source provenance."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess


def package(stage, output):
    metadata = json.loads((stage / 'metadata.json').read_text())
    system = platform.system().lower()
    if metadata['os'] != system or platform.machine() not in ('amd64', 'x86_64'):
        raise ValueError('package creation must run on the matching native BSD/amd64')
    actual = subprocess.check_output(['uname', '-r'], text=True).strip()
    if not re.match(re.escape(metadata['minimum_os']) + r'(?:-|$)', actual):
        raise ValueError('only the qualified BSD release may create this package')
    payload = stage / 'payload'
    binary = payload / 'usr/local/bin/sibuna'
    if hashlib.sha256(binary.read_bytes()).hexdigest() != metadata['binary_sha256']:
        raise ValueError('staged executable digest mismatch')
    reported = subprocess.check_output([str(binary), '--version'], text=True,
                                       stderr=subprocess.STDOUT).strip()
    if reported != f'sibuna {metadata["version"]}':
        raise ValueError('native executable version mismatch')
    output.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in payload.rglob('*') if p.is_file())
    release = metadata['version']
    name = f'sibuna-{release}'
    if system == 'freebsd':
        abi = subprocess.check_output(['pkg', 'config', 'ABI'], text=True).strip()
        if abi != 'FreeBSD:15:amd64':
            raise ValueError('unexpected FreeBSD package ABI')
        manifest = {
            'name': 'sibuna', 'version': release, 'origin': 'security/sibuna',
            'comment': 'Admission proxy with proof-of-work and WAF inspection',
            'desc': 'Upstream CLI package; not an official FreeBSD port. No service is installed.',
            'maintainer': metadata['contact'], 'www': 'https://github.com/insanai/sibuna',
            'prefix': '/usr/local', 'abi': abi, 'arch': abi,
            'licenselogic': 'and', 'licenses': ['AGPLv3', 'LGPL3'],
            'files': {'/' + str(p.relative_to(payload)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in files},
        }
        definition = stage / 'manifest.json'
        definition.write_text(json.dumps(manifest, indent=2) + '\n')
        subprocess.run(['pkg', 'create', '-M', str(definition), '-r', str(payload),
                        '-o', str(output), '-f', 'tzst'], check=True)
        created = output / (name + '.pkg')
    elif system == 'openbsd':
        listing = stage / 'PLIST'
        directories = sorted(p for p in (payload / 'usr/local/share/doc/sibuna').rglob('*')
                             if p.is_dir())
        listing.write_text('@comment pkgpath=security/sibuna\n@mode 755\n@bin bin/sibuna\n'
                           'share/doc/sibuna/\n'
                           + ''.join(str(p.relative_to(payload / 'usr/local')) + '/\n'
                                     for p in directories)
                           + '@mode 644\n'
                           + ''.join(str(p.relative_to(payload / 'usr/local')) + '\n'
                                     for p in files if p != binary))
        description = stage / 'DESCR'
        description.write_text('Admission proxy with proof-of-work challenges and WAF inspection.\n'
                               'Upstream CLI package; not an official OpenBSD port.\n'
                               'No service/account/state is installed. See SECURITY.md for private reporting.\n')
        libraries = subprocess.check_output(['ldd', str(binary)], text=True)
        wanted = sorted(set(re.findall(r'/usr/lib/lib([\w]+)\.so\.(\d+)\.(\d+)', libraries)))
        if not wanted:
            raise ValueError('native OpenBSD library requirements were not identified')
        command = ['pkg_create', '-A', 'amd64', '-B', str(payload), '-p', '/usr/local',
                   '-d', str(description), '-f', str(listing),
                   '-D', 'COMMENT=Admission proxy with proof-of-work and WAF inspection',
                   '-D', 'FULLPKGPATH=security/sibuna', '-D', 'PORTSDIR=/usr/ports',
                   '-D', 'HOMEPAGE=https://github.com/insanai/sibuna',
                   '-D', 'MAINTAINER=' + metadata['contact']]
        for library in wanted:
            command += ['-W', '.'.join(library)]
        subprocess.run(command + [str(output / (name + '.tgz'))], check=True)
        created = output / (name + '.tgz')
    else:
        raise ValueError('unsupported package system')
    asset = output / f'{name}-{system}-{metadata["minimum_os"]}-amd64{created.suffix}'
    created.rename(asset)
    print(asset)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    package(args.stage.resolve(), args.output.resolve())
