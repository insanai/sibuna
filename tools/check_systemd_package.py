#!/usr/bin/env python3
"""Exercise real service start/restart/reinstall/removal on a disposable CI host."""
import hashlib
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

package = next(Path(sys.argv[1]).glob('*.deb')).resolve()
def run(*args):
    subprocess.run(['sudo', *args], check=True)
def digest():
    return subprocess.check_output(['sudo', 'sha256sum', '/var/lib/sibuna/admission.seed']).split()[0]
def healthy():
    for _ in range(30):
        try:
            with urllib.request.urlopen('http://127.0.0.1:8080/__sibuna/health', timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(1)
    raise AssertionError('packaged systemd service did not become healthy')
run('dpkg', '-i', str(package))
assert subprocess.run(['systemctl', 'is-active', '--quiet', 'sibuna']).returncode != 0
assert subprocess.run(['systemctl', 'is-enabled', '--quiet', 'sibuna']).returncode != 0
try:
    run('systemctl', 'start', 'sibuna')
    healthy()
    original = digest()
    run('systemctl', 'restart', 'sibuna')
    healthy()
    assert digest() == original
    run('systemctl', 'stop', 'sibuna')
    run('sh', '-c', 'echo "# operator-owned settings" >> /etc/sibuna/service.env')
    run('dpkg', '-i', str(package))
    assert 'operator-owned settings' in Path('/etc/sibuna/service.env').read_text()
    run('systemctl', 'start', 'sibuna')
    healthy()
    assert digest() == original
    run('dpkg', '--remove', 'sibuna')
    assert digest() == original
    assert subprocess.run(['systemctl', 'is-active', '--quiet', 'sibuna']).returncode != 0
finally:
    subprocess.run(['sudo', 'systemctl', 'stop', 'sibuna'])
print('systemd lifecycle, seed preservation and configuration preservation passed')
