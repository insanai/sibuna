"""Real console edits must change inspection while preserving unrelated denials."""
import json
import time


def check(h, port, data_port, cookie, csrf):
    query = "/console/api/policies/query"
    edit = "/console/api/inspection/edit"
    status, _, body = h.request(port, "POST", query, {}, cookie, csrf)
    assert status == 200
    original = json.loads(body)
    modes = dict(original["inspection"], sqli="audit", rce="disabled")
    source = {"expected_revision": original["committed"], "document": json.dumps(modes)}
    assert h.request(port, "POST", edit, source)[0] == 401
    assert h.request(port, "POST", edit, source, cookie)[0] == 400
    invalid = dict(source, document='{"sqli":"audit"}')
    assert h.request(port, "POST", edit, invalid, cookie, csrf)[0] == 400
    status, _, body = h.request(port, "POST", edit, source, cookie, csrf)
    assert status == 200, (status, body)
    committed = json.loads(body)["committed"]
    assert int(committed) == int(original["committed"]) + 1
    assert h.request(port, "POST", edit, source, cookie, csrf)[0] == 409
    applied(h, port, cookie, csrf, committed)
    for index, (query_text, agent, action, expected) in enumerate([
            ("union%20select", "curl", "challenge", 401),
            ("union%20select%20%3Cscript%3E", "curl", "deny", 403),
            ("union%20select", "Amazonbot", "deny", 403)]):
        request = {"path": "/inspection-review", "query": query_text,
                   "ip": f"8.8.10.{index+1}", "user_agent": agent}
        status, _, body = h.request(port, "POST", "/console/api/policies/test",
                                    request, cookie, csrf)
        decision = json.loads(body)
        assert status == 200 and decision["action"] == action
        assert decision["audited_categories"] == 2
        assert h.request(data_port, "GET", request["path"] + "?" + query_text,
                         extra_headers={"User-Agent": agent,
                                        "X-Forwarded-For": request["ip"]})[0] == expected
    source.update(expected_revision=committed, document=json.dumps(original["inspection"]))
    status, _, body = h.request(port, "POST", edit, source, cookie, csrf)
    assert status == 200, (status, body)
    applied(h, port, cookie, csrf, json.loads(body)["committed"])


def applied(h, port, cookie, csrf, revision):
    for _ in range(10):
        time.sleep(0.1)
        status, _, body = h.request(port, "POST", "/console/api/policies/query", {}, cookie, csrf)
        assert status == 200
        if int(json.loads(body)["applied"]) >= int(revision):
            return
    raise AssertionError("inspection revision did not reach the live engine")
