"""Native token lifecycle and private-file bearer commands against the running daemon."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import console_bootstrap_test as bootstrap
from console_cli_test import invoke, private
from console_client_test import peer


def automation(binary, port, path, command, expected=None, extra=()):
    result = subprocess.run([
        binary, "console", *command, "--origin", f"http://127.0.0.1:{port}",
        "--token-file", str(path), *extra,
    ], capture_output=True, text=True, timeout=26)
    assert path.read_text().strip() not in result.stdout + result.stderr
    assert len(result.stdout) <= 16385
    if expected:
        assert result.returncode == 1 and expected in result.stderr, result.stderr
        assert not result.stdout
        return None
    assert result.returncode == 0 and not result.stderr, result.stderr
    return json.loads(result.stdout)


def transport(binary, root):
    token = private(root / "controlled-token", "c" * 64)
    for mode, failure in (("normal", None), ("private", "InvalidResponse"),
                          ("redirect", "Transport"), ("oversize", "ResponseTooLarge"),
                          ("deadline", "Deadline")):
        with peer(mode) as server:
            start = time.monotonic()
            automation(binary, server.server_port, token, ["users"], failure)
            assert len(server.requests) == 1, "bearer command unexpectedly logged in or out"
            path, headers, _ = server.requests[0]
            assert path == "/console/api/users/query"
            assert headers["Authorization"] == "Bearer " + token.read_text().strip()
            assert "Cookie" not in headers and "X-Console-CSRF" not in headers
            if mode == "deadline":
                assert 19 <= time.monotonic() - start < 25


def lifecycle(binary, port, password, root, restart):
    expiry = int(time.time()) + 3600
    reader = invoke(binary, port, password, [
        "mint-token", "CLI observer 日本", "--scope", "users_read", "--scope", "geoip_read",
        "--expires", str(expiry),
    ])
    assert reader["saved"] and re.fullmatch("[0-9a-f]{64}", reader["token"])
    assert int(reader["expires"]) == expiry
    read_file = private(root / "reader", reader["token"])
    read_file.chmod(0o644)
    automation(binary, port, read_file, ["users"], "CredentialPermissions")
    read_file.chmod(0o600)
    assert automation(binary, port, read_file, ["users"])["rows"][0]["username"] == "admin"
    assert automation(binary, port, read_file, ["geoip", "status"])["status"] == "idle"
    automation(binary, port, read_file, ["add-user", "forbidden"], "Forbidden")
    automation(binary, port, read_file, ["tokens"], "UnexpectedOption")
    automation(binary, port, read_file, ["users"], "UnexpectedOption",
               extra=("--username", "admin", "--password-file", str(password)))
    writer = invoke(binary, port, password, [
        "mint-token", "account maintenance", "--role", "admin",
        "--scope", "users_write", "--scope", "users_read",
    ])
    assert writer["expires"] is None
    write_file = private(root / "writer", writer["token"])
    created = automation(binary, port, write_file, ["add-user", "automated"])
    assert re.fullmatch("[0-9a-f]{64}", created["temporary_password"])
    page = invoke(binary, port, password, ["tokens"])
    assert len(page["rows"]) == 2 and page["next"] is None
    assert all(row["active"] for row in page["rows"])
    assert all("token" not in row and "digest" not in row for row in page["rows"])
    target = str(reader["id"])
    invoke(binary, port, password, ["remove-token", target, "--revision", "1"], "Conflict")
    restart()
    assert automation(binary, port, read_file, ["users"])["rows"]
    assert invoke(binary, port, password, ["revoke-token", target, "--revision", "1"])["saved"]
    invoke(binary, port, password, ["revoke-token", target, "--revision", "1"], "Conflict")
    automation(binary, port, read_file, ["users"], "Unauthorized")
    page = invoke(binary, port, password, ["tokens"])
    row = next(row for row in page["rows"] if str(row["id"]) == target)
    assert row["disabled"] and not row["active"] and int(row["revision"]) == 2
    assert invoke(binary, port, password, ["remove-token", target, "--revision", "2"])["saved"]
    restart()
    page = invoke(binary, port, password, ["tokens", "--after", target])
    assert len(page["rows"]) == 1 and page["rows"][0]["id"] == writer["id"]
    owner = automation(binary, port, write_file, ["users"])["rows"][0]
    assert automation(binary, port, write_file, [
        "revoke-sessions", str(owner["id"]), "--revision", str(owner["revision"]),
    ])["saved"]
    automation(binary, port, write_file, ["users"], "Unauthorized")
    restart()
    assert not invoke(binary, port, password, ["tokens"])["rows"][0]["active"]


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-token-cli-") as directory:
        root = Path(directory)
        transport(binary, root)
        temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
        password = private(root / "password", "token CLI administrator private passphrase")
        port = h.port()
        with (root / "daemon.log").open("w+") as log:
            proc = [h.start(binary, str(root / "data"), port, log)]

            def restart():
                h.stop(proc[0])
                proc[0] = None
                proc[0] = h.start(binary, str(root / "data"), port, log)

            try:
                bootstrap.change(h, port, temporary, password.read_text().strip())
                restart()
                lifecycle(binary, port, password, root, restart)
            finally:
                if proc[0] is not None:
                    h.stop(proc[0])
    print("console-e2e: native token lifecycle, bearer headers, bounds and restart passed")
