"""Opt-in head capture across both modes: redacted request heads, the origin response head
for audited admissions (HTTP and WebSocket), an explicit response state for every other
exit, an operator-added kept header, and secrets checked in the decoded bytes. Without the
flag an incident reports its heads as not recorded."""
import json
import sys
import time
from pathlib import Path
import tempfile
import console_bootstrap_test as bootstrap
from console_users_test import login
from proxy_fixture import WebSocket, origin

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
from distributed import UA, session  # noqa: E402

XSS = "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
SECRETS = ("verysecret", "topsecret", "hidden-value", "opaque-value")


def incident(h, port, console, path_prefix):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        status, _, body = h.request(port, "POST", "/console/api/events/query",
                                    {"path_prefix": path_prefix, "limit": 3}, *console)
        assert status == 200, (status, body)
        rows = json.loads(body)["rows"]
        if rows:
            return rows[0]
        time.sleep(0.5)
    raise AssertionError("no incident recorded for " + path_prefix)


def heads(h, port, console, row_id, expected=200):
    status, _, body = h.request(port, "POST", "/console/api/events/heads", {"id": row_id},
                                *console)
    assert status == expected, (status, body)
    if status != 200:
        return None
    page = json.loads(body)
    # Secrets are checked in the decoded bytes; hex never contains the plaintext.
    request = bytes.fromhex(page["request"]).decode("latin-1")
    response = bytes.fromhex(page["response"]).decode("latin-1")
    for secret in SECRETS:
        assert secret not in request and secret not in response, (secret, request, response)
    return page, request, response


def audit_xss(h, port, console):
    status, _, body = h.request(port, "POST", "/console/api/policies/query", {}, *console)
    assert status == 200, (status, body)
    original = json.loads(body)
    if original["inspection"]["xss"] == "audit":
        return
    modes = dict(original["inspection"], xss="audit")
    status, _, body = h.request(port, "POST", "/console/api/inspection/edit", {
        "expected_revision": original["committed"], "document": json.dumps(modes)}, *console)
    assert status == 200, (status, body)
    committed = int(json.loads(body)["committed"])
    for _ in range(50):
        time.sleep(0.1)
        status, _, body = h.request(port, "POST", "/console/api/policies/query", {}, *console)
        assert status == 200
        if int(json.loads(body)["applied"]) >= committed:
            return
    raise AssertionError("audit mode did not reach the live engine")


def client(cookie=None, **extra):
    hdrs = {"User-Agent": UA, "X-Forwarded-For": "203.0.113.30", **extra}
    if cookie:
        hdrs["Cookie"] = cookie
    return hdrs


def reverse_proxy(h, port, data_port, console):
    assert h.request(port, "POST", "/console/api/events/heads", {"id": "1"})[0] == 401
    # A local denial: credential headers and unlisted values keep only their names, the
    # operator-added header keeps its value, and the state names the local response.
    assert h.request(data_port, "GET", "/__sibuna/honeypot?token=hidden-value",
                     extra_headers={"X-Forwarded-For": "8.8.14.1", "Cookie": "sid=verysecret",
                                    "Authorization": "Bearer topsecret", "User-Agent": "curl/8",
                                    "X-Custom": "opaque-value", "X-Trace-Id": "trace-42",
                                    "Referer": "https://u:verysecret@r.example/p?k=hidden-value"
                                    })[0] == 403
    row = incident(h, port, console, "/__sibuna/")
    page, request, response = heads(h, port, console, row["id"])
    assert page["recorded"] and page["version"] == 1
    assert request.startswith("GET /__sibuna/honeypot?token=[redacted] HTTP/1.1\r\n"), request
    for line in ("Cookie: [redacted]", "Authorization: [redacted]", "X-Custom: [redacted]",
                 "X-Trace-Id: trace-42", "User-Agent: curl/8",
                 "Referer: https://[redacted]@r.example/p?k=[redacted]"):
        assert line + "\r\n" in request, (line, request)
    assert not page["request_truncated"] and response == ""
    assert page["response_state"] == "local"
    assert heads(h, port, console, "9007199254740991")[0]["recorded"] is False
    # An audited request that is then challenged still records its finding, with the
    # local response state, instead of waiting for an origin head that never comes.
    audit_xss(h, port, console)
    assert h.request(data_port, "GET", "/audit-challenged?" + XSS,
                     extra_headers=client())[0] == 401
    row = incident(h, port, console, "/audit-challenged")
    assert row["category"] == "audit:xss", row
    page, request, response = heads(h, port, console, row["id"])
    assert response == "" and page["response_state"] == "local", page
    # An audited admission captures the origin head once the relay validated it.
    cookie, _ = session(data_port)
    assert h.request(data_port, "GET", "/audit-admitted?" + XSS,
                     extra_headers=client(cookie, **{"X-Custom": "opaque-value"}))[0] == 200
    row = incident(h, port, console, "/audit-admitted")
    page, request, response = heads(h, port, console, row["id"])
    assert page["response_state"] == "captured", page
    assert response.startswith("HTTP/1.1 200 OK\r\n") and "Content-Type: application/json" in \
        response, response
    assert "X-Custom: [redacted]\r\n" in request and "Cookie: [redacted]\r\n" in request
    # An accepted WebSocket handshake head is captured through the same path.
    ws = WebSocket(data_port, client(cookie), path="/ws?" + XSS)
    ws.close()
    row = incident(h, port, console, "/ws")
    page, request, response = heads(h, port, console, row["id"])
    assert page["response_state"] == "captured", page
    assert response.startswith("HTTP/1.1 101 Switching Protocols\r\n"), response
    assert "Upgrade: websocket\r\n" in response and "Sec-WebSocket-Accept: [redacted]" in response


def origin_down(h, port, data_port, console):
    audit_xss(h, port, console)
    cookie, _ = session(data_port)
    assert h.request(data_port, "GET", "/audit-unreachable?" + XSS,
                     extra_headers=client(cookie))[0] == 502
    row = incident(h, port, console, "/audit-unreachable")
    page, request, response = heads(h, port, console, row["id"])
    assert response == "" and page["response_state"] == "unavailable", page


def forward_auth(h, port, data_port, console):
    audit_xss(h, port, console)
    cookie, _ = session(data_port)
    assert h.request(data_port, "GET", "/audit-forwarded?" + XSS,
                     extra_headers=client(cookie))[0] == 200
    row = incident(h, port, console, "/audit-forwarded")
    page, request, response = heads(h, port, console, row["id"])
    assert response == "" and page["response_state"] == "unobserved", page


def check(binary, h):
    application, _ = origin()
    try:
        with tempfile.TemporaryDirectory(prefix="sibuna-console-heads-") as directory:
            root = Path(directory)
            data = str(root / "data")
            temporary = bootstrap.initialize(binary, data, "admin")
            credentials = None
            runs = (
                ("reverse_proxy", application.server_port, reverse_proxy),
                ("reverse_proxy", h.port(), origin_down),
                ("forward_auth", application.server_port, forward_auth),
            )
            for mode, upstream, scenario in runs:
                port, data_port = h.port(), h.port()
                with (root / f"{scenario.__name__}.log").open("w+") as log:
                    proc = h.start(binary, data, port, log, extra=(
                        "-m", mode, "--port", str(data_port), "--trust-forwarded",
                        "--algorithm", "hashcash", "--difficulty", "8",
                        "--upstream-port", str(upstream), "--console-capture-heads",
                        "--console-capture-header", "X-Trace-Id"))
                    try:
                        if credentials is None:
                            credentials = bootstrap.change(h, port, temporary,
                                                           "heads test permanent passphrase")
                        console = login(h, port, credentials)[:2]
                        scenario(h, port, data_port, console)
                    finally:
                        h.stop(proc)
    finally:
        application.shutdown()
    print("console-e2e: opt-in redacted head capture, response states, kept headers and "
          "the not-recorded default passed")
