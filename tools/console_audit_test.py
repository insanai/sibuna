"""Live audit authorization, filtering, detail, export and restart persistence."""
import json
from pathlib import Path
import tempfile
import console_bootstrap_test as bootstrap
from console_users_test import login, rotate
from console_token_test import mint, bearer


def call(h, port, session, operation, fields=None, expected=200):
    status, _, body = h.request(port, "POST", "/console/api/audit/" + operation,
                                fields or {}, *session)
    assert status == expected, (operation, status)
    result = json.loads(body)
    if status == 200:
        assert result["version"] == 1
        assert all(secret not in body for secret in
                   (b"password_hash", b"csrf_digest", b"recovery_hashes", b"session_digest"))
    return result


def checks(h, port, admin):
    query = "/console/api/audit/query"
    assert h.request(port, "POST", query, {})[0] == 401
    assert h.request(port, "POST", query, {}, cookie=admin[0])[0] == 400
    for fields in ({"before": "-1"}, {"actor": "1 OR 1=1"}, {"since": "9", "until": "8"},
                   {"action": "user.%"}, {"before": "9223372036854775808"}):
        call(h, port, admin, "query", fields, expected=400)
    call(h, port, admin, "read", {"id": "9223372036854775807"}, expected=404)
    token = mint(h, port, admin, ["users_read"], label="audit automation fixture")
    assert bearer(port, "POST", query, token["token"], {})[0] == 403
    for index in range(10):
        status, _, result = h.request(port, "POST", "/console/api/users/create", {
            "username": "audit-viewer-" + str(index), "role": "viewer",
        }, *admin)
        assert status == 200
        if index == 0:
            temporary = json.loads(result)["temporary_password"]
    first = call(h, port, admin, "query", {"action": "user.create"})
    assert len(first["rows"]) == 8 and first["next"] is not None
    second = call(h, port, admin, "query", {
        "action": "user.create", "before": str(first["next"]),
    })
    assert len(second["rows"]) >= 2 and second["next"] is None
    assert min(int(row["id"]) for row in first["rows"]) > int(second["rows"][0]["id"])
    selected = first["rows"][0]
    detail = call(h, port, admin, "read", {"id": str(selected["id"])})
    assert detail["before"] is None and detail["row"]["actor_role"] == "admin"
    # Management mutations record the address presenting the credential.
    assert detail["row"]["client_ip"] == "127.0.0.1", detail["row"]
    summary = json.loads(detail["after"])
    assert summary["role"] == "viewer" and summary["must_change"] == 1
    assert not detail["after_truncated"] and not detail["after_redacted"]
    filtered = call(h, port, admin, "query", {"actor": "0", "action": "user.create"})
    assert all(int(row["actor"]) == 0 for row in filtered["rows"])
    exported = call(h, port, admin, "export", {"action": "token.create"})
    assert len(exported["rows"]) == 1 and exported["rows"][0]["client_ip"] == "127.0.0.1"
    receipt = call(h, port, admin, "query", {"action": "audit.export"})
    assert len(receipt["rows"]) == 1 and int(receipt["rows"][0]["subject"]) == 1
    assert receipt["rows"][0]["client_ip"] == "127.0.0.1"
    for _ in range(5):
        call(h, port, admin, "export", {"action": "token.create"})
    call(h, port, admin, "export", expected=429)
    assert call(h, port, admin, "query")["rows"]
    viewer = rotate(h, port, {"username": "audit-viewer-0", "password": temporary},
                    "audit viewer permanent passphrase")
    assert call(h, port, viewer, "read", {"id": str(selected["id"])}) == detail
    assert call(h, port, viewer, "query")["rows"]
    status, _, body = h.request(port, "POST", "/console/api/users/query", {}, *admin)
    assert status == 200
    row = next(row for row in json.loads(body)["rows"] if row["username"] == "audit-viewer-0")
    assert h.request(port, "POST", "/console/api/users/change", {
        "target": str(row["id"]), "expected_revision": str(row["revision"]),
        "operation": "revoke",
    }, *admin)[0] == 200
    call(h, port, viewer, "query", expected=401)
    revoked = call(h, port, admin, "query", {"action": "user.revoke"})
    assert revoked["rows"] and revoked["rows"][0]["client_ip"] == "127.0.0.1"
    return detail


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-audit-api-") as directory:
        root = Path(directory)
        temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
        with (root / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, str(root / "data"), port, log)
            try:
                credentials = bootstrap.change(h, port, temporary, "audit admin private passphrase")
                cookie, csrf, _ = login(h, port, credentials)
                detail = checks(h, port, (cookie, csrf))
            finally:
                h.stop(proc)
            proc = h.start(binary, str(root / "data"), port, log)
            try:
                cookie, csrf, _ = login(h, port, credentials)
                restored = call(h, port, (cookie, csrf), "read", {"id": str(detail["row"]["id"])})
                assert restored == detail
            finally:
                h.stop(proc)
    print("console-e2e: audit filters, ownership, redaction, export and restart passed")


if __name__ == "__main__":
    import sys
    import console_e2e
    check(sys.argv[1], console_e2e)
