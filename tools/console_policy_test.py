"""Compare bounded console policy evaluation with real denied requests."""
import json


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
    assert h.request(data_port, "GET", source["path"], extra_headers={
        "User-Agent": source["user_agent"], "X-Forwarded-For": source["ip"]})[0] == 403
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
