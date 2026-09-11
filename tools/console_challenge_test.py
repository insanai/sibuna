"""Challenge observations survive the minute roll: issuance and a malformed submission
become durable per-minute counters that the summary endpoint sums for a window."""
import json
import time
from console_inspection_test import applied


def check(h, port, data_port, cookie, csrf):
    def api(route, source):
        status, _, body = h.request(port, "POST", "/console/api/policies/" + route,
                                    source, cookie, csrf)
        assert status == 200, (route, status, body)
        return json.loads(body)

    page = api("query", {})
    document = {"id": "challenge-minutes", "name": "Challenge minutes",
                "action": "challenge", "path": "/challenge-minutes"}
    saved = api("edit", {"expected_revision": page["committed"],
                         "document": json.dumps(document)})
    applied(h, port, cookie, csrf, saved["committed"])
    assert h.request(data_port, "GET", document["path"], extra_headers={
        "User-Agent": "curl", "X-Forwarded-For": "8.8.12.1"})[0] == 401
    status, _, body = h.request(data_port, "GET",
                                "/__sibuna/challenge.json?path=" + document["path"],
                                extra_headers={"User-Agent": "curl",
                                               "X-Forwarded-For": "8.8.12.1"})
    assert status == 200, (status, body[:120])
    issued_at = int(time.time())
    status, _, _ = h.request(data_port, "POST", "/__sibuna/verify", {"solution": "garbage"},
                             extra_headers={"User-Agent": "curl",
                                            "X-Forwarded-For": "8.8.12.1"})
    assert status in (400, 401, 403), status
    endpoint = "/console/api/challenges/summary"
    assert h.request(port, "POST", endpoint, {})[0] == 401
    assert h.request(port, "POST", endpoint, {"hours": 5}, cookie, csrf)[0] == 400
    # The issuing minute must roll and be journaled before the window includes it; the
    # summary shares the session's query allowance, so poll sparingly.
    while int(time.time()) // 60 <= issued_at // 60:
        time.sleep(1)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status, _, body = h.request(port, "POST", endpoint, {"hours": 1, "node": 1},
                                    cookie, csrf)
        assert status == 200, (status, body)
        reply = json.loads(body)
        assert reply["version"] == 1
        totals = reply["totals"]
        if int(time.time()) // 60 > issued_at // 60 and int(totals["issued"]) >= 1 \
                and int(totals["submitted"]) >= 1:
            coverage = reply["coverage"]
            assert int(coverage["rows"]) >= 1 and coverage["finished"]
            assert coverage["retention_days"] == 90
            assert int(totals["rejected"]) >= 1
            assert sum(int(count) for count in totals["bin_accepted"]) == int(totals["accepted"])
            return
        time.sleep(5)
    raise AssertionError("challenge observations did not survive in durable minute history")
