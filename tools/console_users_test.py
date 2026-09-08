"""Live account administration, required password rotation, role refusal and revocation."""
import json
from pathlib import Path
import re
import tempfile
import time
import console_bootstrap_test as bootstrap
from console_ws_test import Stream, revoked


def login(h, port, credentials):
    status, headers, body = h.request(port, "POST", "/console/api/login", credentials)
    assert status == 200, status
    result = json.loads(body)
    return headers["Set-Cookie"].split(";", 1)[0], result["csrf"], result


def accounts(h, port, session):
    status, _, body = h.request(port, "POST", "/console/api/users/query", {}, *session)
    assert status == 200 and b"password_hash" not in body
    page = json.loads(body)
    assert page["version"] == 1 and len(page["rows"]) <= 8
    return {row["username"]: row for row in page["rows"]}


def edit(h, port, session, row, operation, expected=200, **fields):
    body = dict(target=str(row["id"]), expected_revision=str(row["revision"]),
                operation=operation, **fields)
    status, _, result = h.request(port, "POST", "/console/api/users/change", body, *session)
    assert status == expected, status
    return json.loads(result)


def rotate(h, port, credentials, replacement):
    cookie, csrf, result = login(h, port, credentials)
    assert result["must_change"]
    assert h.request(port, "POST", "/console/api/users/query", {}, cookie, csrf)[0] == 403
    status, headers, body = h.request(port, "POST", "/console/api/password",
                                    {"old_password": credentials["password"],
                                     "password": replacement}, cookie, csrf)
    assert status == 200
    assert h.request(port, "GET", "/console/api/session", cookie=cookie)[0] == 401
    return headers["Set-Cookie"].split(";", 1)[0], json.loads(body)["csrf"]


def exercise(h, port, admin, restart):
    query = "/console/api/users/query"
    create = "/console/api/users/create"
    assert h.request(port, "POST", query, {})[0] == 401
    assert h.request(port, "POST", query, {}, admin[0])[0] == 400
    for invalid in ({"limit": 9}, {"after": "-1"}, {"unknown": True}):
        assert h.request(port, "POST", query, invalid, *admin)[0] == 400
    status, _, body = h.request(port, "POST", create,
                                {"username": "viewer", "role": "viewer"}, *admin)
    assert status == 200
    created = json.loads(body)
    assert re.fullmatch("[0-9a-f]{64}", created["temporary_password"])
    assert time.time() < int(created["password_expires"]) <= time.time() + 3600
    assert h.request(port, "POST", create, {"username": "viewer"}, *admin)[0] == 409
    rows = accounts(h, port, admin)
    assert rows["viewer"]["last_login"] is None and rows["viewer"]["must_change"]
    permanent = "viewer permanent account passphrase"
    viewer = rotate(h, port, {"username": "viewer", "password": created["temporary_password"]},
                    permanent)
    rows = accounts(h, port, viewer)
    assert rows["viewer"]["last_login"] is not None
    assert h.request(port, "POST", create, {"username": "forbidden"}, *viewer)[0] == 403
    edit(h, port, viewer, rows["admin"], "revoke", expected=403)
    edit(h, port, admin, rows["admin"], "access", expected=403, role="viewer", disabled=True)
    before = rows["viewer"]
    edit(h, port, admin, before, "access", role="operator", disabled=False)
    assert h.request(port, "GET", "/console/api/session", cookie=viewer[0])[0] == 401
    edit(h, port, admin, before, "access", expected=409, role="viewer", disabled=True)
    # Password changes share the five-verification address limit with login. Begin a
    # second restart-persistence phase instead of weakening that production limit.
    restart()
    cookie, csrf, _ = login(h, port, {"username": "viewer", "password": permanent})
    operator = cookie, csrf
    stream = Stream(port, cookie)
    stream.send(1, b'{"op":"subscribe","topics":["stats"]}')
    assert stream.receive()[0] == 1
    edit(h, port, admin, accounts(h, port, admin)["viewer"], "revoke")
    revoked(stream)
    assert h.request(port, "POST", query, {}, *operator)[0] == 401
    reset = edit(h, port, admin, accounts(h, port, admin)["viewer"], "password")
    replacement = "replacement viewer account passphrase"
    changed = rotate(h, port, {"username": "viewer", "password": reset["temporary_password"]},
                     replacement)
    edit(h, port, admin, accounts(h, port, admin)["viewer"], "access",
         role="viewer", disabled=True)
    assert h.request(port, "GET", "/console/api/session", cookie=changed[0])[0] == 401
    return {"username": "viewer", "password": replacement}


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-users-") as root:
        directory = str(Path(root) / "data")
        temporary = bootstrap.initialize(binary, directory, "admin")
        with (Path(root) / "daemon.log").open("w+") as log:
            port = h.port()
            proc = [h.start(binary, directory, port, log)]

            def restart():
                h.stop(proc[0])
                proc[0] = None
                proc[0] = h.start(binary, directory, port, log)

            try:
                credentials = bootstrap.change(h, port, temporary, "administrator user passphrase")
                cookie, csrf, _ = login(h, port, credentials)
                admin = cookie, csrf
                viewer = exercise(h, port, admin, restart)
            finally:
                if proc[0] is not None:
                    h.stop(proc[0])
            proc[0] = h.start(binary, directory, port, log)
            try:
                assert h.request(port, "POST", "/console/api/login", viewer)[0] == 401
                row = accounts(h, port, admin)["viewer"]
                assert row["disabled"] and row["last_login"] is not None
                edit(h, port, admin, row, "access", role="viewer", disabled=False)
                cookie, _, result = login(h, port, viewer)
                assert result["role"] == "viewer" and not result["must_change"]
                assert h.request(port, "GET", "/console/api/stats", cookie=cookie)[0] == 200
            finally:
                h.stop(proc[0])
    print("console-e2e: account creation, rotation, roles, revocation and restart passed")
