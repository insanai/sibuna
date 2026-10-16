#!/usr/bin/env python3
"""Smoke-test a built sibuna executable on the platform it was built for.

Checks `--version`, bootstraps a console administrator, then twice starts the daemon in
front of a stub origin with a seed file, SQLite storage and the console, and checks the
health route, the challenge page, the embedded solver module and the console page. Each
run ends with the platform's stop request (SIGTERM, or CTRL_BREAK_EVENT on Windows) and
must exit 0. Only the standard library is used, so it runs on every release runner.
"""
import argparse
import http.server
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

from release_version import version

WINDOWS = sys.platform == 'win32'
BROWSER = ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
           'Chrome/130.0 Safari/537.36')


class Origin(http.server.BaseHTTPRequestHandler):
    """A stub origin that answers every GET with a fixed page."""

    def do_GET(self):
        body = b'origin ok\n'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def fetch(url, headers=None):
    """Returns (status, headers, body) of a GET, also for an error status."""
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()


def wait_healthy(url, daemon):
    for _ in range(150):
        if daemon.poll() is not None:
            raise SystemExit(f'smoke: the daemon exited early with {daemon.returncode}')
        try:
            if fetch(url)[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.2)
    raise SystemExit('smoke: the health route did not answer within 30 s')


def stop(daemon):
    if WINDOWS:
        daemon.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        daemon.send_signal(signal.SIGTERM)
    try:
        code = daemon.wait(timeout=30)
    except subprocess.TimeoutExpired:
        daemon.kill()
        raise SystemExit('smoke: the daemon did not stop within 30 s of the stop request')
    if code != 0:
        raise SystemExit(f'smoke: the daemon exited with {code} after the stop request')


def check_routes(proxy, console):
    status, _, body = fetch(proxy + '/', {'User-Agent': BROWSER, 'Accept': 'text/html',
                                         'Accept-Language': 'en'})
    if status != 200 or b'<!doctype html>' not in body[:256].lower():
        raise SystemExit(f'smoke: expected the challenge page, got {status}')
    status, _, body = fetch(proxy + '/__sibuna/wasm/sibuna-pow.wasm')
    if status != 200 or not body.startswith(b'\0asm'):
        raise SystemExit(f'smoke: expected the solver module, got {status}')
    status, _, body = fetch(console + '/console/')
    if status != 200 or b'<!doctype html>' not in body[:256].lower():
        raise SystemExit(f'smoke: expected the console page, got {status}')


def run_once(binary, work, origin_port, log):
    proxy_port, console_port = free_port(), free_port()
    command = [str(binary), '--host', '127.0.0.1', '--port', str(proxy_port),
               '--upstream-host', '127.0.0.1', '--upstream-port', str(origin_port),
               '--secret-file', str(work / 'admission.seed'), '--data-dir', str(work / 'data'),
               '--console', f'127.0.0.1:{console_port}']
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if WINDOWS else 0
    daemon = subprocess.Popen(command, stdout=log, stderr=log, creationflags=flags)
    try:
        proxy = f'http://127.0.0.1:{proxy_port}'
        wait_healthy(proxy + '/__sibuna/health', daemon)
        check_routes(proxy, f'http://127.0.0.1:{console_port}')
    except BaseException:
        daemon.kill()
        daemon.wait()
        raise
    stop(daemon)


def smoke(binary):
    expected = f'sibuna {version()}'
    reported = subprocess.run([str(binary), '--version'], capture_output=True, text=True,
                              check=True, timeout=30)
    if (reported.stdout + reported.stderr).strip() != expected:
        raise SystemExit(f'smoke: --version printed {reported.stdout!r}, expected {expected!r}')
    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='sibuna-smoke-') as temporary:
        work = Path(temporary)
        seed = work / 'admission.seed'
        seed.write_text(secrets.token_hex(32))
        os.chmod(seed, 0o600)
        log_path = work / 'daemon.log'
        try:
            subprocess.run([str(binary), 'init-admin', 'admin', '--data-dir', str(work / 'data')],
                           capture_output=True, check=True, timeout=60)
            with open(log_path, 'wb') as log:
                for _ in range(2):
                    run_once(binary, work, origin.server_address[1], log)
        finally:
            origin.shutdown()
            if log_path.exists():
                sys.stderr.write(log_path.read_text(errors='replace'))
    print(f'smoke: {expected} passed on {sys.platform}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    smoke(parser.parse_args().binary.resolve())
