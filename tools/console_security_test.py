"""Recorded Security summaries and drill-down filters use real committed incidents."""
import json
import time


def check(h, port, cookie, csrf):
    endpoint = "/console/api/security/query"
    end = int(time.time()) + 1
    query = {"from": end - 3600, "until": end, "node": 1}
    assert h.request(port, "POST", endpoint, query)[0] == 401
    assert h.request(port, "POST", endpoint, query, cookie)[0] == 400
    assert h.request(port, "POST", endpoint, dict(query, until=query["from"]),
                     cookie, csrf)[0] == 400
    pages = {}
    for view in ("modules", "categories", "paths"):
        status, _, body = h.request(port, "POST", endpoint, dict(query, view=view), cookie, csrf)
        assert status == 200 and len(body) <= 4096, (status, body)
        assert b"hidden-value" not in body
        pages[view] = json.loads(body)
        assert pages[view]["total"] == 20
    modules = pages["modules"]["modules"]
    assert modules[0]["total"] == modules[2]["total"] == 0
    assert modules[1]["total"] == sum(modules[1]["trend"]) == 20
    assert all(row["count"] == 1 for row in modules[1]["sources"])
    assert pages["categories"]["rows"][0]["label"] == "honeypot"
    assert pages["categories"]["rows"][0]["count"] == 20
    assert pages["paths"]["rows"][0]["label"] == "/__sibuna/honeypot"
    assert pages["paths"]["rows"][0]["count"] == 20
    empty = h.request(port, "POST", endpoint, dict(query, node=2), cookie, csrf)
    assert empty[0] == 200 and json.loads(empty[2])["total"] == 0
    from console_topics_client import Client
    client = Client(port, cookie)
    try:
        client.command("sub", "events", {"module": "honeypot"})
        client.until(lambda: "events" in client.states and
                     len(client.states["events"]["rows"]) >= 20)
        assert all(row["category"] == "honeypot" for row in client.states["events"]["rows"])
        epoch = client.epochs["events"]
        client.command("filter", "events", {"module": "inspection"})
        client.until(lambda: client.epochs["events"] != epoch and "events" not in client.pending)
        assert client.states["events"]["rows"] == []
    finally:
        client.close()
    for module, expected in (("inspection", 0), ("honeypot", 1)):
        result = h.request(port, "POST", "/console/api/events/query",
                           {"module": module, "limit": 1}, cookie, csrf)
        assert result[0] == 200
        assert len(json.loads(result[2])["rows"]) == expected
