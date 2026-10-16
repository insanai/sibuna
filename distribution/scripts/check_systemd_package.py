#!/usr/bin/env python3
"""Exercise the packaged service on the CI host: start, restart, reinstall and removal."""
from pathlib import Path
import subprocess
import sys
import time
import urllib.request


def run(*args):
    subprocess.run(['sudo', *args], check=True)


def seed_digest():
    return subprocess.check_output(['sudo', 'sha256sum', '/var/lib/sibuna/admission.seed']).split()[0]


def healthy():
    for _ in range(30):
        try:
            with urllib.request.urlopen('http://127.0.0.1:8080/__sibuna/health', timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(1)
    subprocess.run(['sudo', 'journalctl', '-u', 'sibuna', '--no-pager', '-n', '80'])
    raise SystemExit('check-systemd-package: the packaged service did not become healthy')


def inactive():
    return subprocess.run(['systemctl', 'is-active', '--quiet', 'sibuna']).returncode != 0


package = next(Path(sys.argv[1]).glob('*_amd64.deb')).resolve()
run('dpkg', '-i', str(package))
assert inactive(), 'installation must not start the service'
assert subprocess.run(['systemctl', 'is-enabled', '--quiet', 'sibuna']).returncode != 0
try:
    run('systemctl', 'start', 'sibuna')
    healthy()
    original = seed_digest()
    run('systemctl', 'restart', 'sibuna')
    healthy()
    assert seed_digest() == original, 'a restart must keep the seed'
    run('test', '-f', '/var/lib/sibuna/sibuna.db')
    run('systemctl', 'stop', 'sibuna')
    run('sh', '-c', 'echo "# operator-owned settings" >> /etc/sibuna/service.env')
    run('dpkg', '-i', str(package))
    assert 'operator-owned settings' in Path('/etc/sibuna/service.env').read_text()
    run('systemctl', 'start', 'sibuna')
    healthy()
    assert seed_digest() == original
    run('dpkg', '--remove', 'sibuna')
    assert seed_digest() == original, 'removal must keep the seed'
    assert inactive(), 'removal must stop the service'
finally:
    subprocess.run(['sudo', 'systemctl', 'stop', 'sibuna'])
print('check-systemd-package: start, restart, reinstall, seed and configuration checks passed')
