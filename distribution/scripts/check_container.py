#!/usr/bin/env python3
"""Run the image read-only and unprivileged with a seed and a state volume; restart it once."""
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

image = sys.argv[1]
inspect = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image]))[0]
assert inspect['Config']['User'] == '65532:65532', inspect['Config']['User']
fixture = subprocess.check_output(['docker', 'create', image, '--version'], text=True).strip()
try:
    exported = subprocess.check_output(['docker', 'export', fixture])
    with tarfile.open(fileobj=io.BytesIO(exported)) as archive:
        names = {entry.name.lstrip('./') for entry in archive.getmembers()}
    for required in ['etc/ssl/certs/ca-certificates.crt', 'usr/local/bin/sibuna',
                     'usr/share/doc/sibuna/LICENSES/THIRD-PARTY-RUST.txt']:
        assert required in names, required
    for tool in ['sh', 'bash', 'python3', 'apt', 'apt-get', 'rpm', 'pacman', 'curl', 'wget']:
        for directory in ['bin', 'usr/bin', 'usr/local/bin']:
            assert f'{directory}/{tool}' not in names, tool
finally:
    subprocess.run(['docker', 'rm', fixture], check=True)
version = subprocess.check_output(['docker', 'run', '--rm', image, '--version'], text=True)
print(version.strip())
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    root.chmod(0o755)
    seed = root / 'admission.seed'
    seed.write_text(secrets.token_hex(32))
    # Group-readable like a Kubernetes Secret projected with fsGroup.
    seed.chmod(0o440)
    volume = subprocess.check_output(['docker', 'volume', 'create'], text=True).strip()
    try:
        for _ in range(2):
            container = subprocess.check_output([
                'docker', 'run', '-d', '--read-only', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--group-add', str(os.getgid()),
                '--tmpfs', '/tmp:rw,noexec,nosuid', '-v', f'{seed}:/run/admission.seed:ro',
                '-v', f'{volume}:/var/lib/sibuna', '-p', '127.0.0.1::8080', image,
                '--host', '0.0.0.0', '--port', '8080', '--secret-file', '/run/admission.seed',
                '--data-dir', '/var/lib/sibuna/data', '--upstream-host', '127.0.0.1',
                '--upstream-port', '3000'], text=True).strip()
            try:
                port = subprocess.check_output(['docker', 'port', container, '8080'],
                                               text=True).strip().split(':')[-1]
                for _ in range(30):
                    try:
                        url = f'http://127.0.0.1:{port}/__sibuna/health'
                        with urllib.request.urlopen(url, timeout=1) as response:
                            assert response.status == 200
                        break
                    except OSError:
                        time.sleep(1)
                else:
                    raise AssertionError('the unprivileged container did not become healthy')
            finally:
                try:
                    subprocess.run(['docker', 'stop', '-t', '30', container], check=True)
                    state = json.loads(subprocess.check_output(['docker', 'inspect', container]))
                    code = state[0]['State']['ExitCode']
                    subprocess.run(['docker', 'logs', container], check=True)
                    assert code == 0, f'the container did not stop cleanly: {code}'
                finally:
                    subprocess.run(['docker', 'rm', '-f', container], check=True)
    finally:
        subprocess.run(['docker', 'volume', 'rm', volume], check=True)
print('check-container: read-only, unprivileged start, restart and clean stop passed')
