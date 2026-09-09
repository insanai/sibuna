"""Kiosk sessions: minting needs an operator, the exchange is one-time and rate limited, and
the resulting cookie reaches statistics only."""
import json
from pathlib import Path
import tempfile
import time
import console_bootstrap_test as bootstrap
from console_users_test import login, rotate
from console_ws_test import Stream


def mint(h, port, session, expected=200):
    code, _, body = h.request(port, "POST", "/console/api/kiosk/token", {"label": "lobby"},
                              *session)
    assert code == expected, (code, body)
    return json.loads(body) if code == 200 else None


def exchange(h, port, code):
    return h.request(port, "POST", "/console/api/kiosk/exchange", {"code": code})


def checks(h, port, admin):
    code, _, body = h.request(port, "POST", "/console/api/users/create",
                              {"username": "wall-viewer", "role": "viewer"}, *admin)
    assert code == 200
    viewer = rotate(h, port, {"username": "wall-viewer",
                              "password": json.loads(body)["temporary_password"]},
                    "wall viewer replacement passphrase")
    mint(h, port, viewer, 403)
    assert h.request(port, "POST", "/console/api/kiosk/token", {}, cookie=admin[0])[0] == 400
    granted = mint(h, port, admin)
    assert len(granted["code"]) == 64 and int(granted["use_by"]) < int(granted["expires"])
    status, headers, body = exchange(h, port, granted["code"])
    assert status == 200, body
    cookie_header = headers["Set-Cookie"]
    assert "HttpOnly" in cookie_header and "SameSite=Strict" in cookie_header
    assert "Path=/console" in cookie_header
    kiosk = cookie_header.split(";", 1)[0]
    reply = json.loads(body)
    assert reply["kiosk"] and reply["role"] == "viewer"
    assert exchange(h, port, granted["code"])[0] == 401
    status, _, body = h.request(port, "GET", "/console/api/session", cookie=kiosk)
    assert status == 200 and json.loads(body)["kiosk"]
    assert h.request(port, "GET", "/console/api/stats", cookie=kiosk)[0] == 200
    assert h.request(port, "GET", "/console/assets/world-110m.bin", cookie=kiosk)[0] == 200
    for method, path in (("POST", "/console/api/events/query"), ("POST", "/console/api/policies/query"),
                         ("POST", "/console/api/users/query"), ("POST", "/console/api/tokens/create"),
                         ("GET", "/console/api/nodes/local"), ("GET", "/console/api/geoip"),
                         ("GET", "/console/api/rankings"), ("POST", "/console/api/minutes"),
                         ("POST", "/console/api/kiosk/token"), ("POST", "/console/api/audit/query")):
        assert h.request(port, method, path, {} if method == "POST" else None, kiosk,
                         reply["csrf"])[0] == 403, path
    stream = Stream(port, kiosk)
    try:
        stream.send(1, b'{"op":"subscribe","topics":["stats"]}')
        opcode, frame = stream.receive()
        assert opcode == 1 and json.loads(frame)["op"] == "snapshot"
    finally:
        stream.close()
    for _ in range(4):
        exchange(h, port, "0" * 64)
    assert exchange(h, port, "0" * 64)[0] == 429
    assert h.request(port, "POST", "/console/api/logout", {}, kiosk, reply["csrf"])[0] == 200
    assert h.request(port, "GET", "/console/api/session", cookie=kiosk)[0] == 401
    code, _, body = h.request(port, "POST", "/console/api/audit/query", {"action": "kiosk.grant"},
                              *admin)
    assert code == 200 and len(json.loads(body)["rows"]) == 1
    assert granted["code"].encode() not in body
    code, _, body = h.request(port, "POST", "/console/api/audit/query",
                              {"action": "kiosk.exchange"}, *admin)
    assert code == 200 and len(json.loads(body)["rows"]) == 1
    return granted


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-console-kiosk-") as directory:
        root = Path(directory)
        temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
        with (root / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, str(root / "data"), port, log)
            try:
                credentials = bootstrap.change(h, port, temporary, "kiosk admin private passphrase")
                cookie, csrf, _ = login(h, port, credentials)
                granted = checks(h, port, (cookie, csrf))
            finally:
                h.stop(proc)
            proc = h.start(binary, str(root / "data"), port, log)
            try:
                # A grant survives restart; a consumed one stays consumed.
                assert exchange(h, port, granted["code"])[0] == 401
            finally:
                h.stop(proc)
    print("console-e2e: kiosk minting, one-time exchange, scope, replay and expiry passed")


if __name__ == "__main__":
    import sys
    import console_e2e
    check(sys.argv[1], console_e2e)
