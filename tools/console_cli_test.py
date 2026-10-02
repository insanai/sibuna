"""Native account commands against a real daemon; no direct database connection."""
import private_file
import json
from pathlib import Path
import re
import subprocess
import tempfile
import console_bootstrap_test as bootstrap
import console_users_test as users


def invoke(binary, port, password_file, command, expected=None, username="admin", extra=()):
    result = subprocess.run([
        binary, "console", *command, "--origin", f"http://127.0.0.1:{port}",
        "--username", username, "--password-file", str(password_file), *extra,
    ], capture_output=True, text=True, timeout=45)
    assert password_file.read_text().strip() not in result.stdout + result.stderr
    if "--factor-file" in extra:
        factor = Path(extra[extra.index("--factor-file") + 1]).read_text().strip()
        assert factor not in result.stdout + result.stderr
    assert "CONSOLECLICLOSE" not in result.stderr, result.stderr
    if expected:
        assert result.returncode == 1 and expected in result.stderr, result.stderr
        assert not result.stdout
        return None
    assert result.returncode == 0 and not result.stderr, result.stderr
    assert len(result.stdout) <= 16 * 1024 + 1
    return json.loads(result.stdout)


def private(path, value):
    path.write_text(value + "\n")
    private_file.permissions(path)
    return path


def factor_input(binary, port, credentials, recovery, root):
    root = Path(root)
    password = private(root / "cli-password", credentials["password"])
    factor = private(root / "cli-factor", recovery)
    invoke(binary, port, password, ["users"], "Unauthorized", username=credentials["username"])
    options = ("--factor-file", str(factor))
    page = invoke(binary, port, password, ["users"], username=credentials["username"], extra=options)
    assert page["rows"][0]["totp_enabled"]
    invoke(binary, port, password, ["users"], "Unauthorized",
           username=credentials["username"], extra=options)


def exercise(binary, h, port, password_file, root, temporary, restart):
    bootstrap.change(h, port, temporary, password_file.read_text().strip())
    private_file.permissions(password_file, private=False)
    invoke(binary, port, password_file, ["users"], "CredentialPermissions")
    private_file.permissions(password_file)
    page = invoke(binary, port, password_file, ["users"])
    assert page["version"] == 1 and page["rows"][0]["username"] == "admin"
    created = invoke(binary, port, password_file, ["add-user", "cli-viewer"])
    assert re.fullmatch("[0-9a-f]{64}", created["temporary_password"])
    restricted = private(root / "restricted", created["temporary_password"])
    # The five-verification limit also counts bootstrap rotation. Start the
    # next persistence phase without weakening production rate limits.
    restart()
    invoke(binary, port, restricted, ["users"], "PasswordChangeRequired",
           username="cli-viewer")
    viewer_password = "CLI viewer permanent passphrase"
    viewer = users.rotate(h, port, {"username": "cli-viewer",
                                   "password": created["temporary_password"]},
                          viewer_password)
    rows = users.accounts(h, port, viewer)
    row = rows["cli-viewer"]
    private(restricted, viewer_password)
    invoke(binary, port, restricted, ["add-user", "forbidden"], "Forbidden",
           username="cli-viewer")
    restart()
    changed = invoke(binary, port, password_file, [
        "set-user", str(row["id"]), "--revision", str(row["revision"]),
        "--role", "operator", "--disabled", "false",
    ])
    assert changed["saved"] and changed["temporary_password"] is None
    invoke(binary, port, password_file, [
        "revoke-sessions", str(row["id"]), "--revision", str(row["revision"]),
    ], "Conflict")
    page = invoke(binary, port, password_file, ["users"])
    current = next(r for r in page["rows"] if r["username"] == "cli-viewer")
    assert current["role"] == "operator" and current["last_login"] is not None
    revoked = invoke(binary, port, password_file, [
        "revoke-sessions", str(current["id"]), "--revision", str(current["revision"]),
    ])
    assert revoked["saved"]
    reset = invoke(binary, port, password_file, [
        "reset-password", str(current["id"]),
        "--revision", str(int(current["revision"]) + 1),
    ])
    assert re.fullmatch("[0-9a-f]{64}", reset["temporary_password"])
    restart()
    page = invoke(binary, port, password_file, ["users", "--after", str(current["id"])])
    assert page["rows"] == [] and page["next"] is None


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-account-cli-") as root:
        root = Path(root)
        directory = str(root / "data")
        initialized = subprocess.run([
            binary, "console", "init-admin", "admin", "--data-dir", directory,
        ], capture_output=True, text=True, timeout=30)
        assert initialized.returncode == 0, "console bootstrap alias failed"
        match = re.search(r"Temporary console password .*: ([0-9a-f]{48})", initialized.stderr)
        assert match, "console bootstrap alias did not return the temporary credential"
        temporary = {"username": "admin", "password": match[1]}
        password_file = private(root / "password", "CLI administrator permanent passphrase")
        port = h.port()
        with (root / "daemon.log").open("w+") as log:
            proc = [h.start(binary, directory, port, log)]

            def restart():
                h.stop(proc[0])
                proc[0] = None
                proc[0] = h.start(binary, directory, port, log)

            try:
                exercise(binary, h, port, password_file, root, temporary, restart)
            finally:
                if proc[0] is not None:
                    h.stop(proc[0])
    print("console-e2e: native account CLI, permissions, revisions and restart passed")
