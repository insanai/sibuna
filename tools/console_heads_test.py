"""Opt-in head capture: redacted request heads and, for audited admitted requests, the
origin response head; without the flag an incident reports its heads as not recorded."""
import json
import time
from pathlib import Path
import tempfile
import console_bootstrap_test as bootstrap
from console_users_test import login


def incident(h, port, session, path_prefix):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        status, _, body = h.request(port, "POST", "/console/api/events/query",
                                    {"path_prefix": path_prefix, "limit": 3}, *session)
        assert status == 200, (status, body)
        rows = json.loads(body)["rows"]
        if rows:
            return rows[0]
        time.sleep(0.5)
    raise AssertionError("no incident recorded for " + path_prefix)


def heads(h, port, session, row_id, expected=200):
    status, _, body = h.request(port, "POST", "/console/api/events/heads", {"id": row_id},
                                *session)
    assert status == expected, (status, body)
    return json.loads(body) if status == 200 else None


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-console-heads-") as directory:
        root = Path(directory)
        temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
        with (root / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, str(root / "data"), port, log,
                           extra=("--trust-forwarded", "--console-capture-heads"))
            try:
                credentials = bootstrap.change(h, port, temporary, "heads test permanent passphrase")
                session = login(h, port, credentials)[:2]
                data_port = int(proc.args[proc.args.index("--port") + 1])
                assert h.request(port, "POST", "/console/api/events/heads", {"id": "1"})[0] == 401
                assert h.request(data_port, "GET", "/__sibuna/honeypot?token=hidden-value",
                                 extra_headers={"X-Forwarded-For": "8.8.14.1",
                                                "Cookie": "sid=verysecret",
                                                "Authorization": "Bearer topsecret",
                                                "User-Agent": "curl/8"})[0] == 403
                row = incident(h, port, session, "/__sibuna/")
                page = heads(h, port, session, row["id"])
                assert page["recorded"] and page["version"] == 1
                head = bytes.fromhex(page["request"]).decode()
                assert head.startswith("GET /__sibuna/honeypot?token=[redacted] HTTP/1.1\r\n"), head
                assert "Cookie: [redacted]" in head and "Authorization: [redacted]" in head
                for secret in ("verysecret", "topsecret", "hidden-value"):
                    assert secret not in json.dumps(page)
                assert not page["request_truncated"] and page["response"] == ""
                assert heads(h, port, session, "9007199254740991")["recorded"] is False
            finally:
                h.stop(proc)
    print("console-e2e: opt-in redacted head capture, cURL inputs and not-recorded default passed")
