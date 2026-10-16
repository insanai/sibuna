#!/usr/bin/env python3
"""Build, smoke-test, package and install-check Sibuna inside a disposable BSD VM.

Runs as root in a FreeBSD 15.1 or OpenBSD 7.9 guest (the release workflow's vmactions
step). It builds the release executable natively against the system's libc, with the
WebAssembly modules the workflow built once (SIBUNA_POW_WASM, SIBUNA_CONSOLE_WASM); runs
the smoke test as the unprivileged user `qualification`; stages the package payload
under /usr/local; creates the native package in dist/; then installs it, smoke-tests the
installed executable, reinstalls it and removes it. FreeBSD uses Rust from rustup at the
workflow's pinned version; OpenBSD, which rustup does not support, uses its own package.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

from package_release import stage
from release_version import ROOT, version

SYSTEMS = {'freebsd': '15.1', 'openbsd': '7.9'}
RUSTUP = 'https://static.rust-lang.org/rustup/dist/x86_64-unknown-freebsd/rustup-init'
USER = 'qualification'


def run(*command, **options):
    print('+', ' '.join(map(str, command)), flush=True)
    subprocess.run([str(part) for part in command], check=True, **options)


def as_user(*command):
    """Runs `command` as the unprivileged user, with that user's login limits."""
    quoted = ' '.join("'" + str(part).replace("'", "'\\''") + "'" for part in command)
    run('su', '-l', USER, '-c', quoted)


def install_rust(system):
    """Returns the cargo to build with."""
    if system == 'openbsd':
        run('pkg_add', '-I', 'rust')
        return Path('/usr/local/bin/cargo')
    toolchain = os.environ.get('RUST_TOOLCHAIN', 'stable')
    data = urllib.request.urlopen(RUSTUP, timeout=120).read()
    expected = urllib.request.urlopen(RUSTUP + '.sha256', timeout=120).read().split()[0]
    if hashlib.sha256(data).hexdigest().encode() != expected:
        raise SystemExit('qualify-bsd: rustup-init digest mismatch')
    installer = Path(tempfile.mkdtemp()) / 'rustup-init'
    installer.write_bytes(data)
    installer.chmod(0o755)
    run(installer, '-y', '--no-modify-path', '--profile', 'minimal',
        '--default-toolchain', toolchain)
    return Path.home() / '.cargo/bin/cargo'


def build(cargo):
    env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / 'target'))
    for variable in ('SIBUNA_POW_WASM', 'SIBUNA_CONSOLE_WASM'):
        if not Path(env.get(variable, '')).is_file():
            raise SystemExit(f'qualify-bsd: {variable} must name the prebuilt module')
    # package_release records `rustc --version`, so the toolchain must be on PATH.
    os.environ['PATH'] = f'{cargo.parent}{os.pathsep}{os.environ["PATH"]}'
    env['PATH'] = os.environ['PATH']
    run(cargo, '--version')
    run(cargo, 'build', '--release', '--locked', '-p', 'sibuna', cwd=ROOT, env=env)
    return ROOT / 'target/release/sibuna'


def open_to_user(path):
    """Lets the unprivileged user read `path` and traverse to it."""
    run('chmod', '-R', 'a+rX', path)
    for parent in Path(path).resolve().parents:
        parent.chmod(parent.stat().st_mode | 0o011)


def smoke(binary):
    as_user(sys.executable, ROOT / 'distribution/scripts/smoke_test.py', binary)


def payload(binary, system, stage_dir):
    """Stages /usr/local/bin/sibuna and /usr/local/share/doc/sibuna under `stage_dir`."""
    local = stage_dir / 'payload/usr/local'
    docs = local / 'share/doc/sibuna'
    docs.mkdir(parents=True)
    stage(binary, f'{system}-amd64', docs)
    (local / 'bin').mkdir()
    shutil.move(docs / 'sibuna', local / 'bin/sibuna')
    for file in docs.rglob('*'):
        file.chmod(0o755 if file.is_dir() else 0o644)
    (local / 'bin/sibuna').chmod(0o755)
    return stage_dir / 'payload'


def create_freebsd(root, output, release):
    abi = subprocess.check_output(['pkg', 'config', 'ABI'], text=True).strip()
    files = sorted(path for path in root.rglob('*') if path.is_file())
    manifest = {
        'name': 'sibuna', 'version': release.replace('-', '.'), 'origin': 'security/sibuna',
        'comment': 'Web firewall and anti-crawler proxy with proof-of-work admission',
        'desc': 'Upstream package of the Sibuna command; not an official FreeBSD port. '
                'No service, account or state is created.',
        'maintainer': os.environ.get('CONTACT') or 'packages@example.invalid',
        'www': 'https://insanai.github.io/sibuna/', 'prefix': '/usr/local',
        'abi': abi, 'arch': abi, 'licenselogic': 'single', 'licenses': ['LGPL3+'],
        'files': {'/' + str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in files},
    }
    definition = root.parent / 'manifest.json'
    definition.write_text(json.dumps(manifest, indent=2) + '\n')
    run('pkg', 'create', '-M', definition, '-r', root, '-o', output, '-f', 'tzst')
    created, = output.glob('sibuna-*.pkg')
    asset = output / f'sibuna-{release}-freebsd-{SYSTEMS["freebsd"]}-amd64.pkg'
    created.rename(asset)
    return asset


def create_openbsd(root, output, release):
    local = root / 'usr/local'
    binary = local / 'bin/sibuna'
    listing = root.parent / 'PLIST'
    directories = sorted(path for path in (local / 'share/doc/sibuna').rglob('*') if path.is_dir())
    files = sorted(path for path in local.rglob('*') if path.is_file() and path != binary)
    listing.write_text('@comment pkgpath=security/sibuna\n@mode 755\n@bin bin/sibuna\n'
                       'share/doc/sibuna/\n'
                       + ''.join(f'{path.relative_to(local)}/\n' for path in directories)
                       + '@mode 644\n'
                       + ''.join(f'{path.relative_to(local)}\n' for path in files))
    description = root.parent / 'DESCR'
    description.write_text('Web firewall and anti-crawler proxy with proof-of-work admission.\n'
                           'Upstream package of the Sibuna command; not an official OpenBSD\n'
                           'port. No service, account or state is created.\n')
    libraries = subprocess.check_output(['ldd', str(binary)], text=True)
    wanted = sorted(set(re.findall(r'/usr/lib/lib(\w+)\.so\.(\d+)\.(\d+)', libraries)))
    if not wanted:
        raise SystemExit('qualify-bsd: the OpenBSD library requirements were not found')
    asset = output / f'sibuna-{release}.tgz'
    command = ['pkg_create', '-A', 'amd64', '-B', root, '-p', '/usr/local',
               '-d', description, '-f', listing,
               '-D', 'COMMENT=Web firewall and anti-crawler proxy',
               '-D', 'FULLPKGPATH=security/sibuna', '-D', 'PORTSDIR=/usr/ports',
               '-D', 'HOMEPAGE=https://insanai.github.io/sibuna/',
               '-D', 'MAINTAINER=' + (os.environ.get('CONTACT') or 'packages@example.invalid')]
    for library in wanted:
        command += ['-W', '.'.join(library)]
    run(*command, asset)
    return asset


def lifecycle(system, package, expected_digest):
    """Installs, smoke-tests, reinstalls and removes the package."""
    binary = Path('/usr/local/bin/sibuna')
    if binary.exists():
        raise SystemExit('qualify-bsd: use a guest without an installed Sibuna')
    install = ['pkg', 'add'] if system == 'freebsd' else ['pkg_add', '-D', 'unsigned']
    reinstall = ['pkg', 'add', '-f'] if system == 'freebsd' else \
        ['pkg_add', '-D', 'unsigned', '-r', '-D', 'installed', '-D', 'donttie']
    run(*install, package)
    try:
        if hashlib.sha256(binary.read_bytes()).hexdigest() != expected_digest:
            raise SystemExit('qualify-bsd: the installed executable differs from the build')
        for name in ('LICENSE', 'NOTICE', 'SECURITY.md', 'sibuna.build.json',
                     'LICENSES/THIRD-PARTY-RUST.txt'):
            if not (Path('/usr/local/share/doc/sibuna') / name).is_file():
                raise SystemExit(f'qualify-bsd: the package lacks {name}')
        smoke(binary)
        run(*reinstall, package)
        as_user(binary, '--version')
    finally:
        run(*(['pkg', 'delete', '-y', 'sibuna'] if system == 'freebsd'
              else ['pkg_delete', 'sibuna']))
    if binary.exists():
        raise SystemExit('qualify-bsd: removal left /usr/local/bin/sibuna')


def main():
    system = platform.system().lower()
    if system not in SYSTEMS or os.getuid() != 0:
        raise SystemExit('qualify-bsd: run as root inside a disposable FreeBSD or OpenBSD guest')
    run('git', 'config', '--global', '--add', 'safe.directory', '*')
    binary = build(install_rust(system))
    run(sys.executable, ROOT / 'distribution/scripts/release_version.py', '--check',
        '--binary', binary)
    open_to_user(ROOT)
    smoke(binary)
    stage_dir = Path(tempfile.mkdtemp(prefix='sibuna-bsd-'))
    root = payload(binary, system, stage_dir)
    output = ROOT / 'dist'
    output.mkdir(exist_ok=True)
    create = create_freebsd if system == 'freebsd' else create_openbsd
    package = create(root, output, version())
    print(package)
    lifecycle(system, package, hashlib.sha256(binary.read_bytes()).hexdigest())
    print(f'qualify-bsd: {system} build, smoke test, package and lifecycle passed')


if __name__ == '__main__':
    main()
