"""Exercise encrypted enrollment, factor boundaries and durable single-use recovery."""
import private_file
import base64
import console_bootstrap_test
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import struct
import tempfile
import time


def code(secret, step):
    digest = hmac.new(base64.b32decode(secret), struct.pack("!Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('!I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000:06d}"


def enroll(h, port, temporary, restricted=False):
    credentials = console_bootstrap_test.change(h, port, temporary, "factor test long passphrase")
    status, headers, body = h.request(port, "POST", "/console/api/login", credentials)
    assert status == 200, body
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    csrf = json.loads(body)["csrf"]
    if restricted:
        assert "Secure" in headers["Set-Cookie"]
        assert json.loads(body)["totp_required"]
        for path in ("/console/api/stats", "/console/api/geoip",
                     "/console/assets/world-110m.bin", "/console/stream"):
            assert h.request(port, "GET", path, cookie=cookie)[0] == 403
        assert h.request(port, "POST", "/console/api/geoip", {}, cookie, csrf)[0] == 403
    body = {"password": credentials["password"], "revision": 0}
    status, _, response = h.request(port, "POST", "/console/api/totp/enroll", body, cookie, csrf)
    assert status == 200, response
    enrollment = json.loads(response)
    step = int(time.time()) // 30
    body.update(revision=enrollment["revision"], code=code(enrollment["secret"], step))
    status, _, response = h.request(port, "POST", "/console/api/totp/confirm", body, cookie, csrf)
    assert status == 200, response
    recovery = json.loads(response)["recovery_codes"]
    assert len(recovery) == len(set(recovery)) == 10
    assert h.request(port, "GET", "/console/api/stats", cookie=cookie)[0] == 401
    assert h.request(port, "GET", "/console/assets/world-110m.bin", cookie=cookie)[0] == 401
    return credentials, enrollment["secret"], step, recovery


def login_checks(h, port, credentials, secret, enrolled, recovery):
    login = lambda fields: h.request(port, "POST", "/console/api/login", fields)
    assert login(credentials)[0] == 401
    assert login(dict(credentials, code="not-a-code"))[0] == 401
    # Exercise the accepted +1 skew without waiting for the enrollment step to expire.
    step = max(enrolled + 1, int(time.time()) // 30)
    fields = dict(credentials, code=code(secret, step))
    status, headers, body = login(fields)
    assert status == 200, body
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    assert h.request(port, "GET", "/console/api/stats", cookie=cookie)[0] == 200
    assert login(fields)[0] == 401
    assert login(dict(credentials, code=recovery[0]))[0] == 200


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-factor-") as root:
        keypath = Path(root) / "console.key"
        keypath.write_text(os.urandom(32).hex() + "\n")
        private_file.permissions(keypath)
        temporary = console_bootstrap_test.initialize(
            binary, str(Path(root) / "data"), "factor-admin")
        logpath = Path(root) / "daemon.log"
        port = h.port()
        with logpath.open("w+") as log:
            args = binary, str(Path(root) / "data"), port, log, str(keypath)
            proc = h.start(*args)
            try:
                credentials, secret, step, recovery = enroll(h, port, temporary)
            except BaseException:
                print(re.sub(r"[0-9a-f]{64}", "<redacted>", logpath.read_text())[-6000:])
                raise
            finally:
                h.stop(proc)
            proc = h.start(*args)
            try:
                login_checks(h, port, credentials, secret, step, recovery)
            finally:
                h.stop(proc)
            proc = h.start(*args)
            try:
                login = lambda value: h.request(port, "POST", "/console/api/login",
                                                dict(credentials, code=value))
                assert login(recovery[0])[0] == 401
                assert login(recovery[1])[0] == 200
                import console_cli_test
                console_cli_test.factor_input(binary, port, credentials, recovery[2], root)
            finally:
                h.stop(proc)
    print("console-e2e: encrypted TOTP, session revocation, replay and recovery persistence passed")


def check_proxy(binary, h):
    from types import SimpleNamespace
    headers = {"Origin": "https://console.test", "X-Forwarded-Proto": "https"}
    trusted = SimpleNamespace(request=lambda *a, **kw: h.request(*a, **kw, extra_headers=headers))
    with tempfile.TemporaryDirectory(prefix="sibuna-proxy-") as root:
        keypath = Path(root) / "console.key"
        keypath.write_text(os.urandom(32).hex() + "\n")
        private_file.permissions(keypath)
        temporary = console_bootstrap_test.initialize(
            binary, str(Path(root) / "data"), "factor-admin")
        logpath = Path(root) / "daemon.log"
        port = h.port()
        with logpath.open("w+") as log:
            args = binary, str(Path(root) / "data"), port, log, str(keypath), True
            proc = h.start(*args)
            try:
                assert h.request(port, "GET", "/console/")[0] == 403
                assert h.request(port, "GET", "/console/", extra_headers={
                    "X-Forwarded-Proto": "http"})[0] == 403
                assert h.request(port, "POST", "/console/api/login", {}, extra_headers={
                    "Origin": "https://wrong.test", "X-Forwarded-Proto": "https"})[0] == 400
                credentials, secret, step, recovery = enroll(trusted, port, temporary, True)
            finally:
                h.stop(proc)
            proc = h.start(*args)
            try:
                login_checks(trusted, port, credentials, secret, step, recovery)
            finally:
                h.stop(proc)
    print("console-e2e: trusted HTTPS ingress and mandatory administrator TOTP passed")
