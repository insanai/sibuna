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


def start(binary, directory, console_port, logfile, key_file=None, proxy=False,
          workers=1, extra=()):
    proc = subprocess.Popen([
        binary, "--data-dir", directory, "--host", "127.0.0.1",
        "--port", str(port()), "--workers", str(workers), "--console", f"127.0.0.1:{console_port}",
    ] + (["--console-key-file", key_file] if key_file else []) + ([
        "--console-behind-proxy", "--console-origin", "https://console.test",
        "--console-trusted-proxy", "127.0.0.1/32",
    ] if proxy else []) + list(extra), stdout=logfile, stderr=logfile)
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
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise AssertionError("daemon failed to shut down within ten seconds")
    assert proc.returncode == 0, f"daemon shutdown status {proc.returncode}"


def geo_import(console_port, cookie, csrf):
    before = json.loads(request(console_port, "GET", "/console/api/geoip", cookie=cookie)[2])
    # A build may embed a snapshot; it serves at revision 0 until the first durable import.
    assert before["revision"] == 0, before
    assert before["ranges"] == 0 or before["source"] == "embedded snapshot", before
    source = {"provider": "dbip", "source_version": "2026-09", "expected_revision": 0,
              "csv": "".join(f"8.8.{i}.0,8.8.{i}.255,US\n" for i in range(200))}
    assert request(console_port, "POST", "/console/api/geoip", source, cookie, csrf)[0] == 200
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        metadata = json.loads(request(console_port, "GET", "/console/api/geoip", cookie=cookie)[2])
        if metadata["status"] == "applied":
            assert metadata["ranges"] == 200 and metadata["revision"] == 1
            assert metadata["source"] == "DB-IP IP to Country Lite", metadata
            assert metadata["provider"] == "dbip" and metadata["license"] == "CC BY 4.0"
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
    import console_bootstrap_test
    with tempfile.TemporaryDirectory(prefix="sibuna-console-") as root:
        temporary = console_bootstrap_test.initialize(binary, str(Path(root) / "data"), "admin")
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
                credentials = console_bootstrap_test.change(
                    sys.modules[__name__], console_port, temporary, "first long test passphrase")
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
                endpoint = "/console/api/challenges"
                assert request(console_port, "POST", endpoint, {})[0] == 401
                assert request(console_port, "POST", endpoint, {}, cookie)[0] == 400
                status, _, snapshot = request(console_port, "POST", endpoint, {}, cookie, csrf)
                assert status == 200
                snapshot = json.loads(snapshot)
                assert snapshot["configured"]["difficulty"] == 16
                assert snapshot["configured"]["algorithm"] == "posw"
                assert snapshot["configured"]["parameter"] == 13
                assert len(snapshot["buckets"]) == 16 and len(snapshot["bin_accepted"]) == 256
                assert request(console_port, "POST", endpoint, {"bin": 256}, cookie, csrf)[0] == 400

                geometry = request(console_port, "GET", "/console/assets/world-110m.bin",
                                   cookie=cookie)
                assert geometry[0] == 200 and geometry[2][:4] in (b"SBG1", b"SBG2")
                geo_import(console_port, cookie, csrf)
                import console_timeline_test
                timeline_cursor = console_timeline_test.check(
                    sys.modules[__name__], proc, console_port, cookie, csrf)
                console_ws_test.idle_delivery(console_port, cookie)
                stream = console_ws_test.delivery(console_port, cookie)
                before_restart = json.loads(request(
                    console_port, "GET", "/console/api/stats", cookie=cookie)[2])
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
                after_restart = json.loads(request(
                    console_port, "GET", "/console/api/stats", cookie=cookie)[2])
                assert before_restart["boot"] != after_restart["boot"]
                assert any(after_restart["boot"]) and after_restart["requests"] == 0
                console_timeline_test.restarted(sys.modules[__name__], console_port, cookie,
                                               json.loads(login[2])["csrf"], timeline_cursor)
                metadata = request(console_port, "GET", "/console/api/geoip", cookie=cookie)
                assert json.loads(metadata[2])["ranges"] == 200
                import console_geo_cli_test
                console_geo_cli_test.live(binary, sys.modules[__name__], console_port,
                                          credentials, root)
            finally:
                stop(proc)
    import console_bootstrap_test
    console_bootstrap_test.check(binary, sys.modules[__name__])
    import console_events_test
    console_events_test.check(binary, sys.modules[__name__])
    import console_users_test
    import console_cli_test
    import console_client_test
    console_users_test.check(binary, sys.modules[__name__])
    console_cli_test.check(binary, sys.modules[__name__])
    console_client_test.check(binary)
    import console_geo_cli_test
    console_geo_cli_test.controlled(binary)
    import console_mutation_test
    console_mutation_test.check(binary, sys.modules[__name__])
    import console_token_test
    console_token_test.check(binary, sys.modules[__name__])
    import console_token_cli_test
    console_token_cli_test.check(binary, sys.modules[__name__])
    import console_nodes_test
    console_nodes_test.check(binary, sys.modules[__name__])
    import console_audit_test
    console_audit_test.check(binary, sys.modules[__name__])
    import console_shutdown_test
    console_shutdown_test.check(binary, sys.modules[__name__])
    import console_totp_test
    console_totp_test.check(binary, sys.modules[__name__])
    console_totp_test.check_proxy(binary, sys.modules[__name__])
    import console_kiosk_test
    console_kiosk_test.check(binary, sys.modules[__name__])
    import console_cluster_test
    console_cluster_test.check(binary, sys.modules[__name__])
    print("console-e2e: bootstrap, login, CSRF, stream delivery/revocation, restart persistence passed")


if __name__ == "__main__":
    check(os.path.abspath(sys.argv[1]))
