"""Multipart and MIME compatibility against an origin that actually parses uploaded parts."""
import base64
import hashlib
import http.client
import json
import os
import socket
from pathlib import Path
import subprocess
import tempfile
import console_e2e as helper

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=")
BOUNDARY = "Sibuna-Upload-Boundary"


def multipart(parts):
    output = bytearray()
    for name, filename, media_type, payload in parts:
        output.extend(f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"'.encode())
        if filename is not None:
            output.extend(f'; filename="{filename}"'.encode())
        output.extend(f'\r\nContent-Type: {media_type}\r\n\r\n'.encode())
        output.extend(payload)
        output.extend(b"\r\n")
    output.extend(f"--{BOUNDARY}--\r\n".encode())
    return bytes(output)


def uploads(port, exchange):
    parts = [("caption", None, "text/plain; charset=utf-8", "A résumé & photo".encode()),
             ("files", "photo.png", "image/png", PNG),
             ("files", "source.js", "text/javascript", b'<script>example source file</script>'),
             ("files", "archive.bin", "application/octet-stream", bytes(range(256)) * 8192),
             ("note", None, "text/plain", b"after the streamed file")]
    body = multipart(parts)
    for boundary in (BOUNDARY, f'"{BOUNDARY}"'):
        hdrs = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        code, _, reply = exchange(port, "/multipart", hdrs, "POST", body)
        assert code == 200, ("multipart", code, reply[:128])
        received = json.loads(reply)
        assert len(received) == len(parts)
        for actual, (name, filename, media_type, payload) in zip(received, parts):
            assert actual == {"name": name, "filename": filename,
                              "type": media_type.split(";")[0], "bytes": len(payload),
                              "sha256": hashlib.sha256(payload).hexdigest()}, actual


def types(port, exchange):
    binary = bytes(range(256)) * 1024
    for media, body in (("image/png", PNG), ("image/jpeg", binary), ("application/pdf", binary),
                        ("application/zip", binary), ("application/octet-stream", binary),
                        ("audio/wav", binary), ("video/mp4", binary),
                        ("application/json", b'{"description":"normal upload metadata"}'),
                        ("application/xml", b'<message>normal input</message>'),
                        ("application/x-www-form-urlencoded", b'name=Alice&caption=hello%20world'),
                        ("text/plain; charset=utf-8", "Unicode café".encode())):
        code, headers, result = exchange(port, "/upload", {"Content-Type": media}, "POST", body)
        assert code == 200 and result == body, (media, code)
        actual_type = next(value for key, value in headers.items()
                           if key.lower() == "content-type")
        assert actual_type == media, (media, headers)


def protection(port, exchange):
    hdrs = {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}
    file = ("file", "photo.png", "image/png", PNG)
    for parts in ([file, ("caption", None, "text/plain", b"' UNION SELECT password FROM users")],
                  [("file", "../private.txt", "text/plain", b"ordinary file")]):
        assert exchange(port, "/multipart", hdrs, "POST", multipart(parts))[0] == 403
    for media, body in (("application/json", b'{"query":"1 UNION SELECT password FROM users"}'),
                        ("application/xml", b'<script>alert(1)</script>'),
                        ("image/svg+xml", b'<svg onload="alert(1)"></svg>')):
        assert exchange(port, "/upload", {"Content-Type": media}, "POST", body)[0] == 403
    # A binary body does not turn off query, header, path, admission or rate-limit checks.
    assert exchange(port, "/upload?q=1%20UNION%20SELECT%20password", {
        "Content-Type": "application/octet-stream"}, "POST", PNG)[0] == 403


def keepalive(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        connection.request("GET", "/inspect")
        response = connection.getresponse()
        assert response.status == 200
        response.read()
        body = multipart([("file", "large.bin", "application/octet-stream",
                           bytes(range(256)) * 8192)])
        connection.request("POST", "/multipart", body, {
            "Content-Type": f"multipart/form-data; boundary={BOUNDARY}"})
        response = connection.getresponse()
        received = response.read()
        assert response.status == 200, ("keepalive upload", response.status, received[:128])
        assert json.loads(received)[0]["bytes"] == 2 * 1024 * 1024
    finally:
        connection.close()


def pipelined(port):
    from proxy_fixture import http_response
    body = bytes(range(256)) * 8192
    first = b"GET /inspect HTTP/1.1\r\nHost: example\r\n\r\n"
    second = ("POST /upload HTTP/1.1\r\nHost: example\r\n"
              "Content-Type: application/octet-stream\r\n"
              f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    with socket.create_connection(("127.0.0.1", port), timeout=8) as connection:
        with connection.makefile("rb") as reader:
            # Prefetch the second request behind the first, then force the daemon's input
            # buffer to compact while reading a body larger than its remaining capacity.
            connection.sendall(first + second + body[:1024])
            assert http_response(reader)[0] == 200
            connection.sendall(body[1024:])
            code, _, received = http_response(reader)
            assert code == 200 and received == body, ("pipelined body", code, received[:64])


def expect_continue(port):
    from proxy_fixture import http_response
    for expectation in ("100-continue", "unsupported"):
        body = multipart([("file", "photo.png", "image/png", PNG)])
        head = (f"POST /multipart HTTP/1.1\r\nHost: example\r\nExpect: {expectation}\r\n"
                f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
            with connection.makefile("rb") as reader:
                connection.sendall(head)
                status, _, _ = http_response(reader)
                if expectation == "unsupported":
                    assert status == 417
                    continue
                assert status == 100, ("continue handshake", status)
                connection.sendall(body)
                status, _, response = http_response(reader)
                assert status == 200, ("final upload response", status)
                assert json.loads(response)[0]["sha256"] == hashlib.sha256(PNG).hexdigest()


def check(binary):
    from proxy_e2e import exchange
    from proxy_fixture import origin
    from run import ready
    server, worker = origin()
    try:
        with tempfile.TemporaryDirectory(prefix="sibuna-uploads-") as directory:
            root = Path(directory)
            (root / "secret").write_bytes(os.urandom(32))
            (root / "policy.json").write_text(json.dumps({
                "default_action": "ALLOW", "waf": True, "rules": [],
            }))
            port = helper.port()
            with (root / "sibuna.log").open("w+") as log:
                proc = subprocess.Popen([
                    binary, "--host", "127.0.0.1", "--port", str(port), "--workers", "1",
                    "--upstream-port", str(server.server_port), "--rate-limit", "100000",
                    "--policy-file", str(root / "policy.json"),
                    "--secret-file", str(root / "secret"),
                ], stdout=log, stderr=log)
                try:
                    ready(proc, port)
                    uploads(port, exchange)
                    types(port, exchange)
                    protection(port, exchange)
                    keepalive(port)
                    pipelined(port)
                    expect_continue(port)
                finally:
                    helper.stop(proc)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
    print("proxy-e2e: multipart fields/files, MIME preservation and inspection protection passed")
