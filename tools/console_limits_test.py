"""Console quota edits must reach the real daemon without preview consuming its budget."""
import json
from console_inspection_test import applied


def check(h, port, data_port, cookie, csrf):
    def api(route, source):
        status, _, body = h.request(port, "POST", "/console/api/policies/" + route,
                                    source, cookie, csrf)
        assert status == 200, (route, status, body)
        return json.loads(body)

    page = api("query", {})
    document = {"id": "live-quota", "name": "Live quota", "action": "challenge",
                "path": "/console-quota-review",
                "limits": {"rate": 1, "window_seconds": 60, "ban_seconds": 0}}
    source = {"expected_revision": page["committed"], "document": json.dumps(document)}
    invalid = dict(source, document=json.dumps(dict(document, action="weigh")))
    assert h.request(port, "POST", "/console/api/policies/edit", invalid, cookie, csrf)[0] == 400
    saved = api("edit", source)
    applied(h, port, cookie, csrf, saved["committed"])
    request = {"path": document["path"], "ip": "8.8.11.1", "user_agent": "curl"}
    for _ in range(3):
        result = api("test", request)
        assert result["limits"] == document["limits"] and result["action"] == "challenge"
    read = api("read", {"kind": "document", "id": document["id"],
                        "committed": saved["committed"]})
    assert json.loads(read["document"])["limits"] == document["limits"]

    def traffic(ip="8.8.11.1"):
        return h.request(data_port, "GET", document["path"], extra_headers={
            "User-Agent": "curl", "X-Forwarded-For": ip})

    assert traffic()[0] == 401
    status, headers, _ = traffic()
    assert status == 429 and int(headers["Retry-After"]) > 0
    assert traffic("8.8.11.2")[0] == 401
    unrelated = {"id": "quota-neighbor", "name": "Neighbor", "action": "deny",
                 "path": "/quota-neighbor", "enabled": False}
    saved = api("edit", {"expected_revision": saved["committed"],
                         "document": json.dumps(unrelated)})
    applied(h, port, cookie, csrf, saved["committed"])
    assert traffic()[0] == 429
    document["enabled"] = False
    saved = api("edit", {"expected_revision": saved["committed"],
                         "document": json.dumps(document)})
    applied(h, port, cookie, csrf, saved["committed"])
    assert traffic()[0] == 401
