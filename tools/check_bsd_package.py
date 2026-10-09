#!/usr/bin/env python3
"""Install, replace and remove an upstream CLI package on a disposable native BSD."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import shlex
import subprocess
import tempfile


def check(package, user):
    if os.getuid() != 0:
        raise ValueError('native package lifecycle qualification requires disposable guest root')
    system = platform.system().lower()
    if system not in ('freebsd', 'openbsd'):
        raise ValueError('native BSD required')
    identity = pwd.getpwnam(user)
    if identity.pw_uid == 0:
        raise ValueError('runtime qualification must be unprivileged')
    binary = Path('/usr/local/bin/sibuna')
    docs = Path('/usr/local/share/doc/sibuna')
    if binary.exists():
        raise ValueError('use a disposable guest without an existing Sibuna installation')
    before_users = Path('/etc/passwd').read_bytes()
    before_rc = {str(p) for directory in ('/usr/local/etc/rc.d', '/etc/rc.d')
                 for p in Path(directory).glob('*sibuna*')}

    def runtime(*command):
        # A login shell applies the platform's ordinary user resource limits.
        subprocess.run(['su', '-', user, '-c', shlex.join(map(str, command))], check=True)

    def install(replace=False):
        if system == 'freebsd':
            command = ['pkg', 'add'] + (['-f'] if replace else [])
        else:
            # Force real extraction for this same-version lifecycle fixture,
            # rather than accepting an already-installed update signature or
            # tying the old payload into the replacement.
            command = ['pkg_add', '-D', 'unsigned'] + (
                ['-r', '-D', 'installed', '-D', 'donttie'] if replace else [])
        subprocess.run(command + [str(package)], check=True)

    def remove():
        subprocess.run(['pkg', 'delete', '-y', 'sibuna'] if system == 'freebsd'
                       else ['pkg_delete', 'sibuna'], check=True)

    with tempfile.TemporaryDirectory(prefix='sibuna-bsd-package-') as temporary:
        root = Path(temporary)
        os.chown(root, identity.pw_uid, identity.pw_gid)
        root.chmod(0o700)
        seed = root / 'admission.seed'
        seed.write_bytes(os.urandom(32))
        seed.chmod(0o600)
        os.chown(seed, identity.pw_uid, identity.pw_gid)
        config = root / 'operator.conf'
        config.write_text('operator-owned configuration\n')
        os.chown(config, identity.pw_uid, identity.pw_gid)
        state = root / 'state'
        state.mkdir(mode=0o700)
        os.chown(state, identity.pw_uid, identity.pw_gid)
        marker = state / 'retained'
        marker.write_text('operator-owned state\n')
        os.chown(marker, identity.pw_uid, identity.pw_gid)
        retained = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (seed, config, marker)}
        install()
        try:
            manifest = json.loads((docs / 'sibuna.build.json').read_text())
            assert hashlib.sha256(binary.read_bytes()).hexdigest() == manifest['binary_sha256']
            assert binary.stat().st_mode & 0o777 == 0o755
            for name in ('LICENSE', 'NOTICE', 'SECURITY.md', 'SOURCE.txt'):
                assert (docs / name).is_file(), name
            runtime(binary, '--version')
            tools = Path(__file__).resolve().parent
            # Console authentication, persistent restart and clean shutdown through
            # the installed executable, using a normal user's login-class limits.
            runtime(os.sys.executable, tools / 'console_e2e.py', binary)
            runtime(os.sys.executable, tools / 'proxy_e2e.py', binary)
            runtime(os.sys.executable, tools / 'ingress_e2e.py', binary)
            install(replace=True)
            runtime(binary, '--version')
            assert hashlib.sha256(binary.read_bytes()).hexdigest() == manifest['binary_sha256']
        finally:
            remove()
        assert not binary.exists()
        for path, digest in retained.items():
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, path
        assert seed.stat().st_mode & 0o777 == 0o600
    assert Path('/etc/passwd').read_bytes() == before_users
    after_rc = {str(p) for directory in ('/usr/local/etc/rc.d', '/etc/rc.d')
                for p in Path(directory).glob('*sibuna*')}
    assert after_rc == before_rc
    print('native BSD CLI install/replace/remove, unprivileged runtime and retained operator files passed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('--user', default='qualification')
    args = parser.parse_args()
    check(args.package.resolve(), args.user)
