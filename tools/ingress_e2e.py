#!/usr/bin/env python3
"""Verify both CLI modes directly and optionally through actual Caddy/Nginx auth modules."""
import argparse
import json
import subprocess
from pathlib import Path
from ingress_fixture import stack
from proxy_e2e import exchange, websocket
from proxy_fixture import WebSocket
from proxy_upload_test import multipart
from distributed import headers, session


def denied_before_origin(fixture, expected):
    before = len(fixture.application.requests)
    status, reply, body = exchange(fixture.port, "/browser", {
        "Accept": "text/html", "User-Agent": headers()["User-Agent"],
    })
    assert status == expected, ("challenge", status, body[:128])
    assert b"new Worker(" in body and "Content-Security-Policy" in reply, reply
    assert len(fixture.application.requests) == before
    status, reply, body = exchange(fixture.port, "/inspect", {})
    assert status == 401 and json.loads(body)["error"] == "challenge_required", (status, body)


def admitted(fixture, mode, ingress):
    cookie = session(fixture.port, "127.0.0.1")[0]
    hdrs = headers(ip="127.0.0.1", cookie=cookie)
    hdrs["Host"] = f"127.0.0.1:{fixture.port}"
    target = "/inspect?preserve=%2F&unicode=caf%C3%A9"
    status, reply, body = exchange(fixture.port, target, hdrs)
    assert status == 200, (status, body)
    if mode == "forward_auth" and not ingress:
        assert body == b"OK" and not fixture.application.requests
        assert reply["X-Sibuna-Status"] == "PASS"
        return hdrs
    received = json.loads(body)
    assert received["path"] == target
    status, _, body = exchange(fixture.port, "/inspect", {
        **hdrs, "X-Sibuna-Status": "spoofed", "X-Sibuna-Rule": "spoofed"})
    received = json.loads(body)
    assert received["headers"]["X-Sibuna-Status"] == "PASS", received
    assert received["headers"]["X-Sibuna-Rule"] != "spoofed", received
    payload = multipart([("file", "large.bin", "application/octet-stream",
                          bytes(range(256)) * 8192)])
    from proxy_upload_test import BOUNDARY
    status, _, body = exchange(fixture.port, "/multipart", {
        **hdrs, "Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}, "POST", payload)
    assert status == 200 and json.loads(body)[0]["bytes"] == 2 * 1024 * 1024, (status, body[:128])
    websocket(fixture.port, hdrs)
    return hdrs


def refusals(fixture, hdrs, ingress):
    before = len(fixture.application.requests)
    for path in ("/restricted", "/inspect?q=1%20UNION%20SELECT%20password"):
        status, _, body = exchange(fixture.port, path, hdrs)
        assert status == 403, ("deny", path, status, body[:128])
    assert len(fixture.application.requests) == before
    # The ingress's authorization GET omits the application's body. This is an explicit
    # protection boundary: reverse proxy (or an auth caller supplying a body) inspects it.
    body = b'{"query":"1 UNION SELECT password FROM users"}'
    status, _, received = exchange(fixture.port, "/upload", {
        **hdrs, "Content-Type": "application/json"}, "POST", body)
    assert status == (200 if ingress else 403), ("body visibility", status)
    if ingress:
        assert received == body
    # A session must not bypass a terminal rule limit. Preserve Retry-After through ingress.
    assert exchange(fixture.port, "/limited", hdrs)[0] == 200
    status, reply, body = exchange(fixture.port, "/limited", hdrs)
    assert status == 429, ("limited", ingress, status, body[:128])
    assert int(reply["Retry-After"]) > 0, reply


def check(binary, kind=None, executable=None):
    if not kind:
        for args, marker in ((("--mode", "typo"), b"InvalidMode"), (("-m",), b"MissingMode"),
                             (("--mode=forward_auth",), b"InvalidMode"),
                             (("-m", "forward_auth", "--mode", "reverse_proxy"), b"DuplicateMode"),
                             (("--prot", "80"), b"UnknownOption"),
                             (("--port", "70000"), b"InvalidValue")):
            result = subprocess.run([binary, *args], capture_output=True, timeout=5)
            assert result.returncode != 0, result.stderr
            assert b"INVALID COMMAND LINE" in result.stderr and marker in result.stderr, result.stderr
    mode = "forward_auth" if kind else "reverse_proxy"
    scenarios = [(mode, (kind, executable) if kind else None)]
    if not kind:
        scenarios.append(("forward_auth", None))
    for mode, ingress in scenarios:
        with stack(binary, mode, ingress) as fixture:
            expected = 200 if mode == "reverse_proxy" or kind == "nginx" else 401
            denied_before_origin(fixture, expected)
            # A rejected upgrade must not contact the application before admission.
            if mode == "reverse_proxy" or ingress:
                before = len(fixture.application.requests)
                unsigned = {**headers(), "Host": f"127.0.0.1:{fixture.port}"}
                WebSocket(fixture.port, unsigned, expected=401).close()
                assert len(fixture.application.requests) == before
            hdrs = admitted(fixture, mode, ingress)
            refusals(fixture, hdrs, ingress)
            if ingress:
                from console_e2e import stop
                before = len(fixture.application.requests)
                stop(fixture.daemon)
                assert exchange(fixture.port, "/inspect", hdrs)[0] in (502, 503)
                assert len(fixture.application.requests) == before, "failed auth admitted traffic"
        print(f"mode-e2e: {mode} via {kind or 'direct listener'} passed", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--caddy")
    parser.add_argument("--nginx")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    check(binary)
    for kind in ("caddy", "nginx"):
        if executable := getattr(args, kind):
            check(binary, kind, str(Path(executable).resolve()))
