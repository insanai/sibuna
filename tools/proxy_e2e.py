#!/usr/bin/env python3
"""HTTP and WebSocket compatibility through a real Sibuna reverse proxy.

Pass --caddy /path/to/caddy to also test a certificate-validated HTTPS/WSS ingress.
The synthetic certificate is trusted by this test client only, never installed on the host.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import console_e2e as helper
import process_control
from proxy_fixture import WebSocket, frame, origin, receive

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
from distributed import headers, session  # noqa: E402


def exchange(port, path, hdrs, method="GET", body=None, tls=None):
    connection = (http.client.HTTPSConnection("localhost", port, timeout=8, context=tls)
                  if tls else http.client.HTTPConnection("127.0.0.1", port, timeout=8))
    try:
        connection.request(method, path, body, hdrs)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def websocket(port, hdrs, tls=None):
    client = WebSocket(port, hdrs, tls=tls)
    try:
        assert receive(client.reader, False) == (1, b"origin ready", True)
        for opcode, payload, final in ((1, b"frag", False), (9, b"ping", True),
                                       (0, b"mented", True), (2, bytes(range(256)) * 8192, True)):
            client.socket.sendall(frame(opcode, payload, masked=True, final=final))
            assert receive(client.reader, False) == (10 if opcode == 9 else opcode, payload, final)
        client.socket.sendall(frame(8, b"\x03\xe8", masked=True))
        assert receive(client.reader, False) == (8, b"\x03\xe8", True)
    finally:
        client.close()


def persistence(port, hdrs):
    client = WebSocket(port, hdrs)
    try:
        assert receive(client.reader, False)[1] == b"origin ready"
        # An idle upgrade survives the shorter HTTP deadline, then activity keeps it alive
        # beyond its separate three-second bound. Finally, silence must expire it.
        time.sleep(2.2)
        for index in range(12):
            client.socket.sendall(frame(9, str(index).encode(), masked=True))
            assert receive(client.reader, False)[0] == 10
            time.sleep(0.25)
        client.socket.settimeout(5)
        started = time.monotonic()
        assert client.reader.read(1) == b"", "idle upgrade exceeded its deadline"
        assert time.monotonic() - started >= 2.3, "HTTP timeout killed an upgraded connection"
    finally:
        client.close()
    client = WebSocket(port, hdrs, "/half", extra=b"prefetched client bytes")
    try:
        client.socket.sendall(b" and streamed bytes")
        client.socket.shutdown(socket.SHUT_WR)
        assert client.reader.read() == b"beforedone:prefetched client bytes and streamed bytes"
    finally:
        client.close()


def http_checks(port, hdrs):
    values = {**hdrs, "Host": "application.example", "X-App-Header": "unchanged",
              "Connection": "keep-alive, X-Hop-Only", "X-Hop-Only": "remove me"}
    status, _, body = exchange(port, "/inspect?encoded=%2Funchanged", values)
    actual = json.loads(body)
    assert status == 200 and actual["path"] == "/inspect?encoded=%2Funchanged"
    assert actual["headers"]["Host"] == "application.example"
    assert actual["headers"]["X-App-Header"] == "unchanged"
    assert "X-Hop-Only" not in actual["headers"]
    assert actual["headers"]["X-Forwarded-For"] == "203.0.113.30"
    body = b"ordinary application upload\n" * 10000
    status, _, received = exchange(port, "/upload", hdrs, "POST", body)
    assert status == 200 and received == body, (status, len(received), received[:96])
    status, reply, _ = exchange(port, "/redirect", hdrs)
    assert status == 302
    assert reply["Location"] == "https://application.example/login?next=%2Fprivate"
    assert reply["Set-Cookie"] == "application=opaque; HttpOnly; Secure; SameSite=Lax"
    # A connection serves a bounded number of requests; the last permitted response says
    # so, and a keep-alive client sees an announced close rather than a failed request.
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        for index in range(4096):
            connection.request("GET", "/keep", headers=hdrs)
            response = connection.getresponse()
            response.read()
            expected = "close" if index == 4095 else "keep-alive"
            assert response.status == 200 and response.getheader("Connection") == expected, (
                index, response.status, response.getheader("Connection"))
    finally:
        connection.close()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        head = "GET /early HTTP/1.1\r\nHost: example\r\nConnection: close\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        connection.sendall(head.encode())
        with connection.makefile("rb") as reader:
            result = reader.read()
        assert b"HTTP/1.1 103 Early Hints" in result and b"HTTP/1.1 200 OK" in result


def https_checks(caddy, root, backend):
    certificate, key = root / "localhost.crt", root / "localhost.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(certificate), "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    port = helper.port()
    config = {"admin": {"disabled": True}, "apps": {
        "tls": {"certificates": {"load_files": [
            {"certificate": str(certificate), "key": str(key)}]}},
        "http": {"servers": {"review": {"listen": [f"127.0.0.1:{port}"],
            "automatic_https": {"disable": True}, "tls_connection_policies": [{}],
            "routes": [{"handle": [{"handler": "reverse_proxy",
                                    "upstreams": [{"dial": f"127.0.0.1:{backend}"}]}]}]}}}}}
    path = root / "caddy.json"
    path.write_text(json.dumps(config))
    context = ssl.create_default_context(cafile=str(certificate))
    with (root / "caddy.log").open("w+") as log:
        proc = subprocess.Popen([caddy, "run", "--config", str(path)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                assert proc.poll() is None, "Caddy exited"
                try:
                    if exchange(port, "/__sibuna/health", {}, tls=context)[0] == 200:
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("TLS ingress did not start")
            # Caddy supplies the real peer address. Mint the fixture's admission token for
            # that address rather than spoofing a forwarded address through the ingress.
            cookie = session(backend, "127.0.0.1")[0]
            hdrs = {"Cookie": cookie, "User-Agent": headers()["User-Agent"]}
            code, _, body = exchange(port, "/inspect", hdrs, tls=context)
            assert code == 200 and json.loads(body)["headers"]["X-Forwarded-Proto"] == "https"
            websocket(port, hdrs, tls=context)
            print("proxy-e2e: certificate-validated HTTPS and WSS through Caddy passed")
        finally:
            helper.stop(proc)


def check(binary, caddy=None):
    server, worker = origin()
    try:
        with tempfile.TemporaryDirectory(prefix="sibuna-proxy-") as directory:
            root = Path(directory)
            (root / "secret").write_bytes(os.urandom(32))
            port = helper.port()
            with (root / "sibuna.log").open("w+") as log:
                proc = process_control.spawn([
                    binary, "--host", "127.0.0.1", "--port", str(port), "--workers", "1",
                    "--upstream-port", str(server.server_port), "--trust-forwarded",
                    "--algorithm", "hashcash", "--difficulty", "8", "--idle-timeout", "2",
                    "--websocket-idle-timeout", "3",
                    "--rate-limit", "100000", "--secret-file", str(root / "secret"),
                ], stdout=log, stderr=log)
                try:
                    from run import ready
                    ready(proc, port)
                    cookie = session(port)[0]
                    hdrs = headers(cookie=cookie)
                    http_checks(port, hdrs)
                    # The origin may commit before its reply is lost. A pooled socket
                    # failure must never cause Sibuna to send an unsafe request twice.
                    assert exchange(port, "/drop-after-post", hdrs, "POST", b"create")[0] == 502
                    assert sum(path == "/drop-after-post" for path, _ in server.requests) == 1
                    count = len(server.requests)
                    WebSocket(port, headers(), expected=401).close()
                    assert len(server.requests) == count, "unadmitted upgrade reached origin"
                    WebSocket(port, {**hdrs, "Connection": "not-upgrade"}, expected=400).close()
                    WebSocket(port, hdrs, "/bad-upgrade", expected=502).close()
                    websocket(port, hdrs)
                    persistence(port, hdrs)
                    if caddy:
                        https_checks(caddy, root, port)
                    held = WebSocket(port, hdrs)
                    try:
                        assert receive(held.reader, False)[1] == b"origin ready"
                        helper.stop(proc)
                        assert held.reader.read(1) == b"", "upgrade survived daemon shutdown"
                    finally:
                        held.close()
                finally:
                    if proc.poll() is None:
                        helper.stop(proc)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
    print("proxy-e2e: HTTP preservation, WebSocket frames, backpressure, idle and shutdown passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--caddy")
    args = parser.parse_args()
    check(str(Path(args.binary).resolve()), args.caddy)
    from forwarded_e2e import check as forwarded_check
    forwarded_check(str(Path(args.binary).resolve()))
    from proxy_upload_test import check as upload_check
    upload_check(str(Path(args.binary).resolve()))
