"""Real-daemon token issuance, endpoint capabilities, credential kinds and revocation."""
import http.client
import json
from pathlib import Path
import re
import tempfile
import time
import console_bootstrap_test as bootstrap
from console_users_test import login


def bearer(port, method, path, value, body=None, extra=()):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    payload = json.dumps(body) if body is not None else None
    headers = {"Authorization": "Bearer " + value}
    if body is not None:
        headers["Content-Type"] = "application/json"
    headers.update(extra)
    try:
        conn.request(method, path, payload, headers)
        response = conn.getresponse()
        result = response.read(16385)
        assert len(result) <= 16384
        assert not response.getheader("Set-Cookie")
        if value:
            assert value.encode() not in result
        return response.status, result
    finally:
        conn.close()


def mint(h, port, admin, scopes, role="viewer", label="automation", expires=None, expected=200):
    body = {"label": label, "role": role, "scopes": scopes, "expires": expires}
    status, _, result = h.request(port, "POST", "/console/api/tokens/create", body, *admin)
    assert status == expected, status
    result = json.loads(result)
    if status != 200:
        assert "token" not in result
        return None
    assert result["saved"] and re.fullmatch("[0-9a-f]{64}", result["token"])
    assert int(result["id"]) > 0
    assert result["expires"] == (int(expires) if expires is not None else None)
    return result


def catalog(h, port, admin, after=None):
    body = {"after": str(after)} if after is not None else {}
    status, _, result = h.request(port, "POST", "/console/api/tokens/query", body, *admin)
    assert status == 200 and b"digest" not in result
    parsed = json.loads(result)
    assert parsed["version"] == 1 and len(parsed["rows"]) <= 8
    assert all("token" not in row for row in parsed["rows"])
    return parsed


def change(h, port, admin, row, remove=False, expected=200):
    status, _, body = h.request(port, "POST", "/console/api/tokens/revoke", {
        "target": str(row["id"]), "expected_revision": str(row["revision"]), "remove": remove,
    }, *admin)
    assert status == expected, status
    assert "token" not in json.loads(body)


def boundaries(h, port, admin, tokens):
    stats = tokens["stats_read"]["token"]
    assert bearer(port, "GET", "/console/api/stats", stats)[0] == 200
    assert bearer(port, "POST", "/console/api/events/query", stats, {})[0] == 403
    cookie_value = admin[0].split("=", 1)[1]
    assert bearer(port, "GET", "/console/api/stats", cookie_value)[0] == 401
    assert bearer(port, "GET", "/console/api/stats", stats,
                  extra={"Cookie": admin[0]})[0] == 401
    assert h.request(port, "GET", "/console/api/stats",
                     cookie="__sibuna_console=" + stats)[0] == 401
    for path in ("session", "totp", "tokens/query"):
        method = "POST" if path == "tokens/query" else "GET"
        body = {} if method == "POST" else None
        assert bearer(port, method, "/console/api/" + path, stats, body)[0] == 403
    for path in ("/console/stream", "/console/assets/world-110m.bin"):
        assert bearer(port, "GET", path, stats)[0] == 403
    for malformed in ("", "a" * 63, "z" * 64):
        assert bearer(port, "GET", "/console/api/stats", malformed)[0] == 401
    value = tokens["users_read"]["token"]
    assert bearer(port, "POST", "/console/api/users/query", value, {})[0] == 200
    assert bearer(port, "POST", "/console/api/users/query", value, {},
                  extra={"Origin": "https://wrong.test"})[0] == 400
    assert bearer(port, "POST", "/console/api/users/create", value,
                  {"username": "forbidden"})[0] == 403


def scopes(h, port, admin, tokens):
    for scope, endpoint in (("events_read", "events/query"), ("policy_read", "policies/query")):
        assert bearer(port, "POST", "/console/api/" + endpoint,
                      tokens[scope]["token"], {})[0] == 200
        assert bearer(port, "GET", "/console/api/stats", tokens[scope]["token"])[0] == 403
    writer = tokens["policy_write"]["token"]
    document = {"id": "automation", "name": "Automation", "action": "deny", "path": "/token"}
    status, result = bearer(port, "POST", "/console/api/policies/edit", writer, {
        "expected_revision": "0", "document": json.dumps(document),
    })
    assert status == 200, status
    committed = json.loads(result)["committed"]
    assert bearer(port, "POST", "/console/api/policies/query", writer, {})[0] == 403
    modes = dict(path_traversal="enforce", sqli="audit", xss="enforce", rce="enforce")
    assert bearer(port, "POST", "/console/api/inspection/edit", writer, {
        "expected_revision": str(committed), "document": json.dumps(modes),
    })[0] == 200
    status, result = bearer(port, "POST", "/console/api/users/create",
                            tokens["users_write"]["token"], {"username": "automation-viewer"})
    assert status == 200 and json.loads(result)["saved"]
    # Even an administrator bearer with all available capabilities cannot manage tokens.
    all_scopes = list(tokens)
    full = mint(h, port, admin, all_scopes, role="admin", label="full automation")
    assert bearer(port, "POST", "/console/api/tokens/create", full["token"], {
        "label": "delegated", "role": "viewer", "scopes": ["stats_read"],
    })[0] == 403


def geography(port, tokens):
    reader = tokens["geoip_read"]["token"]
    writer = tokens["geoip_write"]["token"]
    assert bearer(port, "GET", "/console/api/geoip", reader)[0] == 200
    assert bearer(port, "GET", "/console/api/geoip", writer)[0] == 403
    source = {"source_version": "2026-09", "expected_revision": 0,
              "csv": "8.8.8.0,8.8.8.255,US\n"}
    assert bearer(port, "POST", "/console/api/geoip", reader, source)[0] == 403
    assert bearer(port, "POST", "/console/api/geoip", writer, source)[0] == 200
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        status, body = bearer(port, "GET", "/console/api/geoip", reader)
        metadata = json.loads(body)
        assert status == 200 and metadata["status"] != "failed"
        if metadata["status"] == "applied":
            assert metadata["ranges"] == 1 and metadata["revision"] == 1
            return
        time.sleep(0.02)
    raise AssertionError("bearer GeoIP import did not activate")


def lifecycle(h, port, admin, tokens):
    first = catalog(h, port, admin)
    assert len(first["rows"]) == 8 and first["next"] is not None
    assert len(catalog(h, port, admin, first["next"])["rows"]) == 1
    row = next(row for row in first["rows"] if row["id"] == tokens["stats_read"]["id"])
    change(h, port, admin, row, remove=True, expected=409)
    change(h, port, admin, row)
    change(h, port, admin, row, expected=409)
    assert bearer(port, "GET", "/console/api/stats", tokens["stats_read"]["token"])[0] == 401
    revoked = next(r for r in catalog(h, port, admin)["rows"] if r["id"] == row["id"])
    assert revoked["disabled"] and not revoked["active"]
    change(h, port, admin, revoked, remove=True)
    expiry = int(time.time()) + 3
    temporary = mint(h, port, admin, ["stats_read"], expires=str(expiry))
    assert bearer(port, "GET", "/console/api/stats", temporary["token"])[0] == 200
    time.sleep(max(0, expiry - time.time()) + 0.05)
    assert bearer(port, "GET", "/console/api/stats", temporary["token"])[0] == 401


def issue(h, port, admin):
    for scopes_value, role in (([], "admin"), (["stats_read", "stats_read"], "admin"),
                               (["unknown"], "admin"), (["policy_write"], "viewer")):
        mint(h, port, admin, scopes_value, role=role, expected=400)
    mint(h, port, admin, ["stats_read"], expires="1", expected=400)
    mint(h, port, admin, ["stats_read"], label="bad\nlabel", expected=400)
    result = {}
    for scope in ("stats_read", "events_read", "policy_read", "policy_write",
                  "geoip_read", "geoip_write", "users_read", "users_write"):
        role = "admin" if scope in ("geoip_write", "users_write") else (
            "operator" if scope == "policy_write" else "viewer")
        result[scope] = mint(h, port, admin, [scope], role=role, label=scope)
    return result


def revoke_creator(h, port, admin, tokens):
    status, _, body = h.request(port, "POST", "/console/api/users/query", {}, *admin)
    assert status == 200
    owner = next(row for row in json.loads(body)["rows"] if row["username"] == "admin")
    assert h.request(port, "POST", "/console/api/users/change", {
        "target": str(owner["id"]), "expected_revision": str(owner["revision"]),
        "operation": "revoke",
    }, *admin)[0] == 200
    for scope, result in tokens.items():
        path = "/console/api/geoip" if scope == "geoip_read" else "/console/api/stats"
        assert bearer(port, "GET", path, result["token"])[0] == 401


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-token-api-") as root:
        root = Path(root)
        temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
        with (root / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, str(root / "data"), port, log)
            try:
                credentials = bootstrap.change(h, port, temporary, "token API private passphrase")
                cookie, csrf, _ = login(h, port, credentials)
                admin = (cookie, csrf)
                tokens = issue(h, port, admin)
                boundaries(h, port, admin, tokens)
                scopes(h, port, admin, tokens)
                geography(port, tokens)
                lifecycle(h, port, admin, tokens)
                revoke_creator(h, port, admin, tokens)
            finally:
                h.stop(proc)
            proc = h.start(binary, str(root / "data"), port, log)
            try:
                assert bearer(port, "GET", "/console/api/geoip",
                              tokens["geoip_read"]["token"])[0] == 401
                cookie, csrf, _ = login(h, port, credentials)
                assert all(not row["active"] for row in catalog(h, port, (cookie, csrf))["rows"])
            finally:
                h.stop(proc)
    print("console-e2e: bearer scopes, GeoIP, policy writes, expiry and revocation passed")
