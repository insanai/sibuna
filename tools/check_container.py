#!/usr/bin/env python3
"""Run the shipped image with private Secret/state mounts and verify restart."""
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
assert inspect['Config']['User'] == '65532:65532'
fixture = subprocess.check_output(['docker', 'create', image, '--version'], text=True).strip()
try:
    exported = subprocess.check_output(['docker', 'export', fixture])
    with tarfile.open(fileobj=io.BytesIO(exported)) as archive:
        names = {entry.name.lstrip('./') for entry in archive.getmembers()}
    assert 'etc/ssl/certs/ca-certificates.crt' in names
    assert 'usr/local/bin/sibuna' in names
    for name in ['sh', 'bash', 'python3', 'zig', 'apt', 'apt-get', 'rpm', 'pacman', 'curl', 'wget']:
        assert not any(path in names for path in [f'bin/{name}', f'usr/bin/{name}', f'usr/local/bin/{name}']), name
finally:
    subprocess.run(['docker', 'rm', fixture], check=True)
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    root.chmod(0o755)
    seed = root / 'admission.seed'
    seed.write_bytes(secrets.token_bytes(32))
    seed.chmod(0o440)
    # Match Kubernetes fsGroup access without changing the host user's identity.
    volume = subprocess.check_output(['docker', 'volume', 'create'], text=True).strip()
    try:
        for _ in range(2):
            container = subprocess.check_output([
                'docker', 'run', '-d', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--group-add', str(os.getgid()), '--tmpfs', '/tmp:rw,noexec,nosuid',
                '-v', f'{seed}:/run/admission.seed:ro', '-v', f'{volume}:/var/lib/sibuna',
                '-p', '127.0.0.1::8080', image, '--host', '0.0.0.0', '--port', '8080',
                '--secret-file', '/run/admission.seed', '--data-dir', '/var/lib/sibuna',
                '--upstream-host', '127.0.0.1', '--upstream-port', '3000'], text=True).strip()
            try:
                port = subprocess.check_output(['docker', 'port', container, '8080'], text=True).strip().split(':')[-1]
                for attempt in range(30):
                    try:
                        with urllib.request.urlopen(f'http://127.0.0.1:{port}/__sibuna/health', timeout=1) as response:
                            assert response.status == 200
                        break
                    except OSError:
                        time.sleep(1)
                else:
                    raise AssertionError('unprivileged container failed to start')
            finally:
                try:
                    subprocess.run(['docker', 'stop', '-t', '30', container], check=True)
                    status = json.loads(subprocess.check_output(['docker', 'inspect', container]))[0]['State']
                    assert status['ExitCode'] == 0, f'container did not stop gracefully: {status["ExitCode"]}'
                    subprocess.run(['docker', 'logs', container], check=True)
                finally:
                    subprocess.run(['docker', 'rm', '-f', container], check=True)
    finally:
        subprocess.run(['docker', 'volume', 'rm', volume], check=True)
print('read-only, unprivileged container and persistent restart checks passed')
