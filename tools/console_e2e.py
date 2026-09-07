#!/usr/bin/env python3
"""Exercise the opt-in console through a real daemon and durable storage."""
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import console_ws_test


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(console_port, method, path, body=None, cookie=None, csrf=None, extra_headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", console_port, timeout=15)
    headers = {"Origin": f"http://127.0.0.1:{console_port}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    if csrf:
        headers["X-Console-CSRF"] = csrf
    headers.update(extra_headers or {})
    try:
        conn.request(method, path, json.dumps(body) if body is not None else None, headers)
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def start(binary, directory, console_port, logfile, key_file=None, proxy=False):
    proc = subprocess.Popen([
        binary, "--data-dir", directory, "--host", "127.0.0.1",
        "--port", str(port()), "--workers", "1", "--console", f"127.0.0.1:{console_port}",
    ] + (["--console-key-file", key_file] if key_file else []) + ([
        "--console-behind-proxy", "--console-origin", "https://console.test",
        "--console-trusted-proxy", "127.0.0.1/32",
    ] if proxy else []), stdout=logfile, stderr=logfile)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("daemon exited before console startup")
        try:
            if request(console_port, "GET", "/console/api/setup")[0] == (403 if proxy else 200):
                return proc
        except (OSError, http.client.HTTPException):
            time.sleep(0.05)
    stop(proc)
    raise RuntimeError("console startup deadline exceeded")


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def geo_import(console_port, cookie, csrf):
    source = {"source_version": "2026-09", "expected_revision": 0,
              "csv": "".join(f"8.8.{i}.0,8.8.{i}.255,US\n" for i in range(200))}
    assert request(console_port, "POST", "/console/api/geoip", source, cookie, csrf)[0] == 200
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        metadata = json.loads(request(console_port, "GET", "/console/api/geoip", cookie=cookie)[2])
        if metadata["status"] == "applied":
            assert metadata["ranges"] == 200 and metadata["revision"] == 1
            break
        assert metadata["status"] != "failed", metadata
        time.sleep(0.02)
    else:
        raise AssertionError("GeoIP import did not complete")
    source.update(expected_revision=1, csv="8.8.8.0,8.8.8.255,AA")
    assert request(console_port, "POST", "/console/api/geoip", source, cookie, csrf)[0] == 200
    while time.monotonic() < deadline:
        metadata = json.loads(request(console_port, "GET", "/console/api/geoip", cookie=cookie)[2])
        if metadata["status"] == "failed":
            assert metadata["ranges"] == 200 and metadata["revision"] == 1
            return
        time.sleep(0.02)
    raise AssertionError("Invalid GeoIP import did not fail")


def check(binary):
    with tempfile.TemporaryDirectory(prefix="sibuna-console-") as root:
        logpath = Path(root) / "daemon.log"
        with logpath.open("wb") as log:
            console_port = port()
            proc = start(binary, str(Path(root) / "data"), console_port, log)
            try:
                status, _, shell = request(console_port, "GET", "/console/")
                assert status == 200 and b"Sibuna Console" in shell
                assert b"world-110m" not in shell and b"WebSocket(" not in shell
                assert request(console_port, "GET", "/console/api/session")[0] == 401
                assert request(console_port, "GET", "/console/assets/world-110m.bin")[0] == 401
                key = re.search(r"Console setup key .*: ([0-9a-f]{64})", logpath.read_text())[1]
                credentials = {"username": "admin", "password": "first long test passphrase"}
                assert request(console_port, "POST", "/console/api/setup",
                               dict(credentials, setup_key=key))[0] == 200
                assert not json.loads(request(console_port, "GET", "/console/api/setup")[2])[
                    "setup_required"]
                assert request(console_port, "POST", "/console/api/login",
                               dict(credentials, password="wrong"))[0] == 401
                status, headers, body = request(console_port, "POST", "/console/api/login", credentials)
                assert status == 200, (status, body)
                cookie = headers["Set-Cookie"].split(";", 1)[0]
                assert "HttpOnly" in headers["Set-Cookie"]
                csrf = json.loads(body)["csrf"]
                assert request(console_port, "GET", "/console/api/session", cookie=cookie)[0] == 200
                geometry = request(console_port, "GET", "/console/assets/world-110m.bin",
                                   cookie=cookie)
                assert geometry[0] == 200 and geometry[2][:4] in (b"SBG1", b"SBG2")
                geo_import(console_port, cookie, csrf)
                console_ws_test.idle_delivery(console_port, cookie)
                stream = console_ws_test.delivery(console_port, cookie)
                assert request(console_port, "POST", "/console/api/logout", cookie=cookie)[0] == 400
                assert request(console_port, "POST", "/console/api/logout",
                               cookie=cookie, csrf=csrf)[0] == 200
                console_ws_test.revoked(stream)
                assert request(console_port, "GET", "/console/api/session", cookie=cookie)[0] == 401
            finally:
                stop(proc)
            proc = start(binary, str(Path(root) / "data"), console_port, log)
            try:
                assert not json.loads(request(console_port, "GET", "/console/api/setup")[2])[
                    "setup_required"]
                login = request(console_port, "POST", "/console/api/login", credentials)
                assert login[0] == 200
                cookie = login[1]["Set-Cookie"].split(";", 1)[0]
                metadata = request(console_port, "GET", "/console/api/geoip", cookie=cookie)
                assert json.loads(metadata[2])["ranges"] == 200
            finally:
                stop(proc)
    import console_totp_test
    console_totp_test.check(binary, sys.modules[__name__])
    console_totp_test.check_proxy(binary, sys.modules[__name__])
    print("console-e2e: bootstrap, login, CSRF, stream delivery/revocation, restart persistence passed")


if __name__ == "__main__":
    check(os.path.abspath(sys.argv[1]))
