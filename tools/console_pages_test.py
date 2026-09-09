"""Page templates: an administrator edits the denial page, the data plane serves it to
browsers only, previews render under a sandbox policy, and audit records carry digests."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import time
import console_bootstrap_test as bootstrap
from console_users_test import login


def call(h, port, session, endpoint, body, expected=200):
    code, headers, reply = h.request(port, "POST", f"/console/api/pages/{endpoint}", body,
                                     *session)
    assert code == expected, (endpoint, code, reply)
    return json.loads(reply) if reply else None, headers


def checks(h, port, data_port, admin):
    page, _ = call(h, port, admin, "read", {"kind": "denied"})
    assert not page["customized"] and int(page["revision"]) == 0
    assert "{{ reason }}" in page["html"]
    call(h, port, admin, "edit", {"kind": "denied", "expected_revision": "0",
                                  "html": "<p>{{ reason }}</p><script>1</script>"}, 400)
    for unsafe in ('<img/src="/missing"onerror="alert(1)">',
                   '<img src="/missing"onerror="alert(1)">',
                   '<img\x0conerror="alert(1)">',
                   '<img src="/&#47;example.com/x">',
                   '<style>{{ challenge }}</style>'):
        call(h, port, admin, "edit", {"kind": "denied", "expected_revision": "0",
                                      "html": unsafe}, 400)
        result, _ = call(h, port, admin, "preview", {"kind": "denied", "html": unsafe})
        assert not result["accepted"], result
    custom = "<!doctype html><title>Custom</title><p>Blocked by {{ reason }} ({{ status }})</p>"
    call(h, port, admin, "edit", {"kind": "denied", "expected_revision": "0", "html": custom})
    call(h, port, admin, "edit", {"kind": "denied", "expected_revision": "0", "html": custom}, 409)
    page, _ = call(h, port, admin, "read", {"kind": "denied"})
    assert page["customized"] and int(page["revision"]) == 1 and page["html"] == custom
    # A deny rule so the data plane renders the page.
    code, _, body = h.request(port, "POST", "/console/api/policies/query", {}, *admin)
    assert code == 200
    rule = {"id": "pages-rule", "name": "Pages rule", "action": "deny", "path": "/pages-deny"}
    code, _, body = h.request(port, "POST", "/console/api/policies/edit",
                              {"expected_revision": json.loads(body)["committed"],
                               "document": json.dumps(rule)}, *admin)
    assert code == 200, body
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        code, headers, body = h.request(data_port, "GET", "/pages-deny", extra_headers={
            "X-Forwarded-For": "203.0.113.9", "User-Agent": "Mozilla/5.0",
            "Accept": "text/html"})
        if code == 403 and b"<title>Custom</title>" in body:
            break
        time.sleep(0.2)
    else:
        raise AssertionError((code, body))
    assert headers["Content-Type"].startswith("text/html")
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert "script-src" not in headers["Content-Security-Policy"]
    assert b"Blocked by pages-rule (403)" in body or b"Blocked by Pages rule (403)" in body, body
    assert int(headers["Content-Length"]) == len(body)
    code, headers, body = h.request(data_port, "GET", "/pages-deny", extra_headers={
        "X-Forwarded-For": "203.0.113.9", "User-Agent": "curl/8"})
    assert code == 403 and body == b"Forbidden: blocked by Sibuna policy", body
    # Preview: the draft renders in a sandboxed reply that never shares the console origin.
    draft = "<!doctype html><p>Draft {{ reason }} <b>{{ request_id }}</b></p>"
    accepted, _ = call(h, port, admin, "preview", {"kind": "banned", "html": draft})
    assert accepted["accepted"] and accepted["path"] == "/console/api/pages/preview/banned"
    code, headers, body = h.request(port, "GET", accepted["path"], cookie=admin[0])
    assert code == 200, body
    csp = headers.get("Content-Security-Policy", "")
    assert csp.startswith("sandbox;") and "default-src 'none'" in csp, csp
    assert b"Draft sample: blocked by rule example <b>0123456789abcdef</b>" in body, body
    rejected, _ = call(h, port, admin, "preview", {"kind": "banned",
                                                   "html": "<a href=\"//evil/\">x</a>"})
    assert not rejected["accepted"] and rejected["diagnostic"], rejected
    code, _, body = h.request(port, "GET", "/console/api/pages/preview/denied", cookie=admin[0])
    assert code == 200 and b"<title>Custom</title>" in body
    # The challenge's CSP must authorize exactly the embedded solver source.
    code, headers, body = h.request(data_port, "GET", "/pages-challenge", extra_headers={
        "X-Forwarded-For": "203.0.113.10", "User-Agent": "Mozilla/5.0", "Accept": "text/html"})
    assert code == 200, (code, body)
    source = body.split(b"<script>", 1)[1].split(b"</script>", 1)[0]
    digest = base64.b64encode(hashlib.sha256(source).digest()).decode()
    assert f"'sha256-{digest}'" in headers["Content-Security-Policy"]
    # Reset restores the default and every change is audited by digest only.
    call(h, port, admin, "edit", {"kind": "denied", "expected_revision": "1", "reset": True})
    page, _ = call(h, port, admin, "read", {"kind": "denied"})
    assert not page["customized"] and int(page["revision"]) == 0
    code, _, body = h.request(port, "POST", "/console/api/audit/query", {"action": "page.edit"},
                              *admin)
    assert code == 200 and len(json.loads(body)["rows"]) == 1
    row_id = json.loads(body)["rows"][0]["id"]
    code, _, body = h.request(port, "POST", "/console/api/audit/read", {"id": str(row_id)}, *admin)
    assert code == 200, body
    assert b"Custom" not in body and b"sha256" in body, body
    code, _, body = h.request(port, "POST", "/console/api/audit/query", {"action": "page.reset"},
                              *admin)
    assert code == 200 and len(json.loads(body)["rows"]) == 1


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-console-pages-") as directory:
        root = Path(directory)
        temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
        with (root / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, str(root / "data"), port, log, extra=("--trust-forwarded",))
            try:
                credentials = bootstrap.change(h, port, temporary,
                                               "pages admin private passphrase")
                cookie, csrf, _ = login(h, port, credentials)
                data_port = int(proc.args[proc.args.index("--port") + 1])
                checks(h, port, data_port, (cookie, csrf))
            finally:
                h.stop(proc)
    print("console-e2e: page template editing, browser rendering, sandboxed preview and reset passed")


if __name__ == "__main__":
    import sys
    import console_e2e
    check(sys.argv[1], console_e2e)
