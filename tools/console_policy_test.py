"""Compare bounded console policy evaluation with real denied requests."""
import json
import time


def check(h, port, data_port, cookie, csrf):
    query = "/console/api/policies/query"
    test = "/console/api/policies/test"
    assert h.request(port, "POST", query, {})[0] == 401
    assert h.request(port, "POST", query, {}, cookie)[0] == 400
    status, _, body = h.request(port, "POST", query, {}, cookie, csrf)
    assert status == 200 and len(body) <= 4096
    page = json.loads(body)
    applied = page["applied"]
    assert isinstance(applied, str) and isinstance(page["committed"], str)
    names = {row["name"] for row in page["rows"]}
    while page["next"] is not None:
        status, _, body = h.request(port, "POST", query,
                                    {"offset": page["next"], "applied": applied}, cookie, csrf)
        assert status == 200 and len(body) <= 4096
        page = json.loads(body)
        names.update(row["name"] for row in page["rows"])
    assert "amazonbot" in names and "robots-txt" in names
    source = {"path": "/policy-review", "ip": "8.8.9.1", "applied": applied,
              "user_agent": "Amazonbot"}
    assert h.request(port, "POST", test, source)[0] == 401
    assert h.request(port, "POST", test, source, cookie)[0] == 400
    status, _, body = h.request(port, "POST", test, source, cookie, csrf)
    assert status == 200
    decision = json.loads(body)
    assert decision["action"] == "deny" and decision["rule"] == "amazonbot"
    # A denial carries no rule name to the client; X-Sibuna-Rule travels upstream only.
    status, live_headers, _ = h.request(data_port, "GET", source["path"], extra_headers={
        "User-Agent": source["user_agent"], "X-Forwarded-For": source["ip"]})
    assert status == 403 and "X-Sibuna-Rule" not in live_headers, live_headers
    source.update(user_agent="Mozilla", query="q=<script>alert(1)</script>", ip="8.8.9.2")
    status, _, body = h.request(port, "POST", test, source, cookie, csrf)
    assert status == 200 and json.loads(body)["rule"] == "waf:xss"
    assert h.request(data_port, "GET", "/policy-review?q=%3Cscript%3Ealert(1)%3C/script%3E",
                     extra_headers={"User-Agent": "Mozilla",
                                    "X-Forwarded-For": source["ip"]})[0] == 403
    source["applied"] = "9223372036854775807"
    assert h.request(port, "POST", test, source, cookie, csrf)[0] == 409
    source.update(applied=None, ip="invalid address")
    assert h.request(port, "POST", test, source, cookie, csrf)[0] == 400
    check_preview(h, port, cookie, csrf)
    check_edit(h, port, data_port, cookie, csrf)


def check_preview(h, port, cookie, csrf):
    query = "/console/api/policies/query"
    test = "/console/api/policies/test"
    status, _, body = h.request(port, "POST", query, {}, cookie, csrf)
    assert status == 200
    page = json.loads(body)
    source = {"path": "/robots.txt", "ip": "8.8.9.4", "user_agent": "Mozilla"}
    status, _, body = h.request(port, "POST", test, source, cookie, csrf)
    assert status == 200 and json.loads(body)["action"] == "allow"
    source.update(committed=page["committed"], draft=json.dumps({
        "id": "preview-only", "name": "Preview denial", "action": "deny", "path": "/robots.txt"}))
    status, _, body = h.request(port, "POST", test, source, cookie, csrf)
    assert status == 200, (status, body)
    result = json.loads(body)
    assert result["preview"] and result["action"] == "deny"
    assert result["committed"] == page["committed"]
    source["committed"] = "9223372036854775807"
    assert h.request(port, "POST", test, source, cookie, csrf)[0] == 409
    source["committed"] = page["committed"]
    source["draft"] = '{"id":"invalid","name":"Invalid","action":"allow","cidrs":["bad"]}'
    assert h.request(port, "POST", test, source, cookie, csrf)[0] == 400
    del source["committed"]
    assert h.request(port, "POST", test, source, cookie, csrf)[0] == 400
    del source["draft"]
    status, _, body = h.request(port, "POST", test, source, cookie, csrf)
    assert status == 200 and json.loads(body)["action"] == "allow"
    assert not json.loads(body)["preview"]


def check_edit(h, port, data_port, cookie, csrf):
    query = "/console/api/policies/query"
    edit = "/console/api/policies/edit"
    test = "/console/api/policies/test"
    status, _, body = h.request(port, "POST", query, {}, cookie, csrf)
    assert status == 200
    page = json.loads(body)
    document = {"id": "live-edit", "name": "Live edit", "action": "deny",
                "path": "/console-policy-edit-review"}
    source = {"expected_revision": page["committed"], "document": json.dumps(document)}
    assert h.request(port, "POST", edit, source)[0] == 401
    assert h.request(port, "POST", edit, source, cookie)[0] == 400
    status, _, body = h.request(port, "POST", edit, source, cookie, csrf)
    assert status == 200, (status, body)
    saved = json.loads(body)
    assert int(saved["committed"]) == int(page["committed"]) + 1
    assert h.request(port, "POST", edit, source, cookie, csrf)[0] == 409
    for _ in range(30):
        status, _, body = h.request(port, "POST", query, {}, cookie, csrf)
        assert status == 200
        page = json.loads(body)
        if int(page["applied"]) >= int(saved["committed"]):
            break
        time.sleep(0.1)
    assert int(page["applied"]) >= int(saved["committed"])
    request = {"path": document["path"], "ip": "8.8.9.5", "user_agent": "Mozilla"}
    status, _, body = h.request(port, "POST", test, request, cookie, csrf)
    assert status == 200 and json.loads(body)["rule"] == "Live edit"
    assert h.request(data_port, "GET", document["path"], extra_headers={
        "User-Agent": "Mozilla", "X-Forwarded-For": request["ip"]})[0] == 403
    document["enabled"] = False
    source.update(expected_revision=page["committed"], document=json.dumps(document))
    status, _, body = h.request(port, "POST", edit, source, cookie, csrf)
    assert status == 200, (status, body)
    check_audit(h, port, cookie, csrf)
    check_history(h, port, cookie, csrf)


def check_history(h, port, cookie, csrf):
    read = "/console/api/policies/read"
    assert h.request(port, "POST", read, {})[0] == 401
    assert h.request(port, "POST", read, {}, cookie)[0] == 400
    status, _, body = h.request(port, "POST", read, {}, cookie, csrf)
    assert status == 200 and len(body) <= 4096
    catalog = json.loads(body)
    assert any(row["id"] == "live-edit" for row in catalog["rows"])
    request = {"kind": "document", "id": "live-edit", "committed": catalog["committed"]}
    status, _, body = h.request(port, "POST", read, request, cookie, csrf)
    assert status == 200
    current = json.loads(json.loads(body)["document"])
    request["kind"] = "history"
    status, _, body = h.request(port, "POST", read, request, cookie, csrf)
    assert status == 200 and len(body) <= 4096
    history = json.loads(body)
    assert history["rows"] and history["rows"][0]["kind"] == "edit"
    request.update(kind="document", revision=history["rows"][-1]["revision"])
    status, _, body = h.request(port, "POST", read, request, cookie, csrf)
    assert status == 200
    historical = json.loads(json.loads(body)["document"])
    assert historical["id"] == current["id"] and historical["name"] == current["name"]
    request["committed"] = "9223372036854775807"
    assert h.request(port, "POST", read, request, cookie, csrf)[0] == 409
    status, _, body = h.request(port, "POST", "/console/api/policies/edit", {
        "expected_revision": catalog["committed"], "document": json.dumps(historical)}, cookie, csrf)
    assert status == 200, (status, body)
    reverted = json.loads(body)
    assert int(reverted["committed"]) == int(catalog["committed"]) + 1
    status, _, body = h.request(port, "POST", "/console/api/policies/edit", {
        "expected_revision": reverted["committed"], "document": json.dumps(current)}, cookie, csrf)
    assert status == 200, (status, body)


def check_audit(h, port, cookie, csrf):
    from console_audit_test import call
    session = (cookie, csrf)
    page = call(h, port, session, "query", {"action": "policy.edit"})
    assert len(page["rows"]) == 2
    updated = call(h, port, session, "read", {"id": str(page["rows"][0]["id"])})
    created = call(h, port, session, "read", {"id": str(page["rows"][1]["id"])})
    assert updated["row"]["actor_role"] == created["row"]["actor_role"] == "admin"
    assert created["before"] is None
    assert json.loads(updated["before"])["enabled"] == 1
    assert json.loads(updated["after"])["enabled"] == 0
    assert updated["before_redacted"] and updated["after_redacted"]
    assert not updated["before_truncated"] and not updated["after_truncated"]
    assert "/console-policy-edit-review" not in json.dumps(updated)
