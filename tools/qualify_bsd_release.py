#!/usr/bin/env python3
"""Build against native BSD headers and gate packaging on unprivileged runtime."""
import os
from pathlib import Path
import platform
import pwd
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if sys.argv[1:] not in ([], ['--candidate']):
    raise SystemExit('usage: qualify_bsd_release.py [--candidate]')
candidate = sys.argv[1:] == ['--candidate']
system = platform.system().lower()
if system not in ('freebsd', 'openbsd') or os.getuid() != 0:
    raise SystemExit('run as root only inside a disposable native BSD guest')
identity = pwd.getpwnam('builder')
subprocess.run(['chown', '-R', f'{identity.pw_uid}:{identity.pw_gid}', str(ROOT)], check=True)


def user(*command):
    script = f'cd {shlex.quote(str(ROOT))} && ' + shlex.join(map(str, command))
    subprocess.run(['su', '-', identity.pw_name, '-c', script], check=True)


python = sys.executable
user(python, ROOT / 'tools/install_zig.py', ROOT / '.zig-cache/toolchain')
zig = ROOT / f'.zig-cache/toolchain/zig-x86_64-{system}-0.17.0/zig'
user(python, ROOT / 'tools/check_release_version.py')
user(python, ROOT / 'tools/console_assets.py', 'check')
user(zig, 'build', 'test', '-j2', '--summary', 'all')
# Deliberately no -Dtarget: use the running BSD's libc SDK, not bundled
# cross-compilation headers. The result is baseline amd64, safe and stripped.
user(zig, 'build', '-Dcpu=baseline', '-Doptimize=safe', '-Dstrip=true', '-j2',
     '--summary', 'all')
binary = ROOT / 'zig-out/bin/sibuna'
user(python, ROOT / 'tools/check_release_version.py', binary)
user(python, ROOT / 'tools/proxy_fixture_test.py')
stage = ROOT / '.zig-cache/bsd-package'
user(python, ROOT / 'tools/prepare_bsd_package.py', '--source', ROOT,
     '--binary', binary, '--system', system, '--destination', stage,
     '--contact', os.environ['CONTACT'], *(['--candidate'] if candidate else []))
subprocess.run([python, str(ROOT / 'tools/package_bsd.py'), str(stage), str(ROOT / 'dist')], check=True)
suffix = '*.pkg' if system == 'freebsd' else '*.tgz'
package, = (ROOT / 'dist').glob(suffix)
subprocess.run([python, str(ROOT / 'tools/check_bsd_package.py'), str(package)], check=True)
