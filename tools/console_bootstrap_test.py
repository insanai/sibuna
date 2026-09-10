"""Local first-administrator provisioning and restricted temporary-password checks."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time


def initialize(binary, directory, username):
    result = subprocess.run([binary, "init-admin", username, "--data-dir", directory],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    match = re.search(r"Temporary console password .*: ([0-9a-f]{48})", result.stderr)
    assert match, "local initializer did not return a temporary credential"
    return {"username": username, "password": match[1]}


def change(h, port, temporary, permanent):
    status, headers, body = h.request(port, "POST", "/console/api/login", temporary)
    assert status == 200, body
    login = json.loads(body)
    assert login["must_change"]
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    for path in ("/console/api/stats", "/console/api/geoip", "/console/api/rankings",
                 "/console/assets/world-110m.bin", "/console/stream"):
        assert h.request(port, "GET", path, cookie=cookie)[0] == 403
    assert h.request(port, "POST", "/console/api/challenges", {},
                     cookie, login["csrf"])[0] == 403
    body = {"old_password": temporary["password"], "password": permanent}
    assert h.request(port, "POST", "/console/api/password", body, cookie)[0] == 400
    status, replacement_headers, result = h.request(port, "POST", "/console/api/password",
                                 body, cookie, login["csrf"])
    assert status == 200, result
    replacement = replacement_headers["Set-Cookie"].split(";", 1)[0]
    assert replacement != cookie
    assert json.loads(result)["csrf"] != login["csrf"]
    assert not json.loads(result)["must_change"]
    assert h.request(port, "GET", "/console/api/session", cookie=replacement)[0] == 200
    assert h.request(port, "GET", "/console/api/session", cookie=cookie)[0] == 401
    return {"username": temporary["username"], "password": permanent}


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-bootstrap-") as root:
        directory = str(Path(root) / "data")
        with (Path(root) / "empty.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, directory, port, log)
            try:
                assert json.loads(h.request(port, "GET", "/console/api/setup")[2])["setup_required"]
                assert h.request(port, "POST", "/console/api/setup", {})[0] == 404
                assert h.request(port, "GET", "/console/assets/world-110m.bin")[0] == 401
            finally:
                h.stop(proc)
        temporary = initialize(binary, directory, "local-admin")
        duplicate = subprocess.run([binary, "init-admin", "other-admin", "--data-dir", directory],
                                   capture_output=True, text=True, timeout=30)
        assert duplicate.returncode != 0 and "AlreadyInitialized" in duplicate.stderr
        assert "Temporary console password" not in duplicate.stderr
        with (Path(root) / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, directory, port, log)
            try:
                credentials = change(h, port, temporary, "permanent local test passphrase")
                assert h.request(port, "POST", "/console/api/login", temporary)[0] == 401
                status, headers, body = h.request(port, "POST", "/console/api/login", credentials)
                assert status == 200 and not json.loads(body)["must_change"]
                cookie = headers["Set-Cookie"].split(";", 1)[0]
                csrf = json.loads(body)["csrf"]
                assert h.request(port, "GET", "/console/api/stats", cookie=cookie)[0] == 200
                refused(h, port, cookie, csrf)
            finally:
                h.stop(proc)
    print("console-e2e: local initialization, required change and temporary credential removal passed")


def refused(h, port, cookie, csrf):
    """Wrong passwords and unknown accounts are audited; the address limit answers 429."""
    wrong = {"username": "local-admin", "password": "not the permanent passphrase"}
    unknown = {"username": "nobody-here", "password": "not the permanent passphrase"}
    statuses = [h.request(port, "POST", "/console/api/login", body)[0]
                for body in (wrong, unknown, wrong, unknown, wrong, wrong)]
    assert 401 in statuses and statuses[-1] == 429, statuses
    assert all(status in (401, 429) for status in statuses), statuses
    # The expired temporary credential above was refused too; refusals are recorded
    # in the background, so allow a few polls within the per-session query budget.
    for attempt in range(20):
        status, _, body = h.request(port, "POST", "/console/api/audit/query",
                                    {"action": "session.denied"}, cookie, csrf)
        assert status == 200, body
        rows = json.loads(body)["rows"]
        if len(rows) >= statuses.count(401) + 1:
            break
        time.sleep(0.1)
    else:
        raise AssertionError(rows)
    assert {row["subject"] for row in rows} <= {1, 0} and 1 in {row["subject"] for row in rows}
    assert all(row["actor"] == 0 for row in rows)
    detail = json.loads(h.request(port, "POST", "/console/api/audit/read",
                                  {"id": str(rows[0]["id"])}, cookie, csrf)[2])
    assert detail["row"]["target"] in ("local-admin", "nobody-here"), detail
    assert "passphrase" not in json.dumps(detail)
