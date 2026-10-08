"""The shipped Wasm keeps one-time codes visible after session revocation."""
import json
import os
from pathlib import Path
import re
import tempfile
import time
import console_bootstrap_test as bootstrap
import console_e2e as h
import console_totp_test as totp
from console_users_test import login
from console_ui_live_test import Interface
import private_file


def codes(ui):
    values = re.findall(r"<li><code>([0-9a-f]{32})</code></li>", ui.html)
    assert len(set(values)) == 10, "one-time recovery screen missing"
    return values


def account(ui):
    ui.event(init=True)
    ui.event(1, {"action": "account", "fields": {}})
    ui.event(1, {"action": "security", "fields": {}})


def enrollment(ui, credentials):
    assert "Set up authenticator" in ui.html
    ui.event(1, {"action": "totp-enroll", "fields": {
        "password": credentials["password"]}})
    secret = re.search(r'<code[^>]*>([A-Z2-7]{32})</code>', ui.html)[1]
    assert "Authenticator enrollment QR code" in ui.html
    ui.event(1, {"action": "totp-confirm", "fields": {
        "password": credentials["password"],
        "code": totp.code(secret, int(time.time()) // 30)}})
    assert ui.stream is None, "revoked enrollment retained telemetry"
    assert "console-navigation" not in ui.html
    recovery = codes(ui)
    ui.event(4, {"state": "message", "body": {"error": "unauthorized"}})
    assert codes(ui) == recovery, "late revocation erased new recovery codes"
    ui.event(1, {"action": "recovery-saved", "fields": {}})
    assert "Welcome back" in ui.html and 'name="code"' in ui.html
    assert recovery[0] not in ui.html
    return recovery


def management(ui, credentials, recovery):
    assert "Replace recovery codes" in ui.html and "Turn off two-factor" in ui.html
    ui.event(1, {"action": "totp-recovery", "fields": {
        "totp-recovery-password": credentials["password"],
        "totp-recovery-code": recovery[1]}})
    replacement = codes(ui)
    assert not set(replacement) & set(recovery)
    ui.event(1, {"action": "recovery-saved", "fields": {}})
    assert "Turn off two-factor" in ui.html and replacement[0] not in ui.html
    ui.event(1, {"action": "totp-disable", "fields": {
        "totp-disable-password": credentials["password"],
        "totp-disable-code": replacement[0]}})
    assert ui.stream is None and "Welcome back" in ui.html
    assert "Two-factor authentication is off" in ui.html
    assert h.request(ui.port, "GET", "/console/api/stats", cookie=ui.cookie)[0] == 401


def check(binary):
    with tempfile.TemporaryDirectory(prefix="sibuna-factor-ui-") as directory:
        root = Path(directory)
        key = root / "console.key"
        key.write_text(os.urandom(32).hex() + "\n")
        private_file.permissions(key)
        temporary = bootstrap.initialize(binary, str(root / "data"), "factor-ui")
        with (root / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, str(root / "data"), port, log, str(key))
            ui = None
            try:
                credentials = bootstrap.change(h, port, temporary, "factor UI test passphrase")
                cookie, _, _ = login(h, port, credentials)
                shell = h.request(port, "GET", "/console/")[2]
                path = re.search(rb'name="sibuna-console-wasm" content="([^"]+)"', shell)[1]
                wasm = root / "console.wasm"
                wasm.write_bytes(h.request(port, "GET", path.decode())[2])
                ui = Interface(port, cookie, wasm)
                account(ui)
                recovery = enrollment(ui, credentials)
            finally:
                if ui:
                    ui.close()
                h.stop(proc)
            proc = h.start(binary, str(root / "data"), port, log, str(key))
            ui = None
            try:
                cookie, _, _ = login(h, port, dict(credentials, code=recovery[0]))
                ui = Interface(port, cookie, wasm)
                account(ui)
                management(ui, credentials, recovery)
            finally:
                if ui:
                    ui.close()
                h.stop(proc)
    print("console-ui-e2e: recovery save screen, revocation fencing, replacement and disable passed")
