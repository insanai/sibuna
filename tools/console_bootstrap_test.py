"""Local first-administrator provisioning and restricted temporary-password checks."""
import json
from pathlib import Path
import re
import subprocess
import tempfile


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
                assert h.request(port, "GET", "/console/api/stats", cookie=cookie)[0] == 200
            finally:
                h.stop(proc)
    print("console-e2e: local initialization, required change and temporary credential removal passed")
