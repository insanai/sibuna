"""Trusted ingress metadata must select the original application policy and scheme."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import console_e2e as helper


def check(binary):
    # Import lazily: the proxy entry point runs this after its origin fixture has stopped.
    from proxy_e2e import exchange
    from proxy_fixture import origin
    from run import ready
    server, worker = origin()
    try:
        with tempfile.TemporaryDirectory(prefix="sibuna-forwarded-") as directory:
            root = Path(directory)
            (root / "secret").write_bytes(os.urandom(32))
            (root / "policy.json").write_text(json.dumps({
                "default_action": "ALLOW", "waf": False,
                "rules": [{"name": "restricted", "path": "/restricted*", "action": "DENY"}],
            }))
            for mode, trusted in (("forward_auth", True), ("forward_auth", False),
                                  ("reverse_proxy", False)):
                port = helper.port()
                with (root / "sibuna.log").open("w+") as log:
                    proc = subprocess.Popen([
                        binary, "--host", "127.0.0.1", "--port", str(port), "--workers", "1",
                        "--mode", mode, "--no-waf", "--rate-limit", "100000",
                        "--upstream-port", str(server.server_port),
                        "--trust-forwarded" if trusted else "--no-trust-forwarded",
                        "--policy-file", str(root / "policy.json"),
                        "--secret-file", str(root / "secret"),
                    ], stdout=log, stderr=log)
                    try:
                        ready(proc, port)
                        assert exchange(port, "/restricted", {})[0] == 403
                        if mode == "forward_auth":
                            authorization(port, trusted, exchange)
                        else:
                            scheme(port, exchange)
                    finally:
                        helper.stop(proc)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
    print("proxy-e2e: original authorization URI and forwarded metadata trust passed")


def authorization(port, trusted, exchange):
    for name in ("X-Forwarded-Uri", "X-Original-URI"):
        headers = {name: "/restricted?preserve=%2F", "X-Forwarded-Method": "POST"}
        assert exchange(port, "/auth", headers)[0] == (403 if trusted else 200)
        headers[name] = "/public"
        assert exchange(port, "/auth", headers)[0] == 200
    conflicts = {"X-Original-URI": "/public", "X-Forwarded-Uri": "/restricted"}
    assert exchange(port, "/auth", conflicts)[0] == (400 if trusted else 200)
    assert exchange(port, "/auth", {"X-Original-URI": "//evil.example/"})[0] == (
        400 if trusted else 200)
    # Routing stays on the actual daemon URI. An original internal-looking target must
    # not dispatch a honeypot or replace an authorization result with a health response.
    assert exchange(port, "/auth", {"X-Original-URI": "/__sibuna/honeypot"})[0] == 200
    assert exchange(port, "/public", {})[0] == 200
    assert exchange(port, "/__sibuna/health", conflicts)[0] == 200


def scheme(port, exchange):
    headers = {"Host": "application.example", "X-Forwarded-Proto": "https",
               "Forwarded": "proto=https;host=evil.example", "X-Forwarded-Host": "evil.example",
               "X-Forwarded-Port": "443", "X-Original-URI": "/restricted"}
    code, _, body = exchange(port, "/inspect", headers)
    result = json.loads(body)
    assert code == 200 and result["path"] == "/inspect"
    assert result["headers"]["Host"] == "application.example"
    assert result["headers"]["X-Forwarded-Proto"] == "http"
    for name in ("Forwarded", "X-Forwarded-Host", "X-Forwarded-Port"):
        assert name not in result["headers"]
