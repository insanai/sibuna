"""Challenge observations survive the minute roll: issuance and a malformed submission
become durable per-minute counters that the summary endpoint sums for a window."""
import json
import time
from concurrent.futures import ThreadPoolExecutor
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


def budgeted(h, port, path, body, cookie, csrf):
    """Reads share the session's query allowance; a 429 means wait for the next window."""
    for _ in range(12):
        status, headers, result = h.request(port, "POST", path, body, cookie, csrf)
        if status != 429:
            return status, headers, result
        time.sleep(10)
    raise AssertionError("the query allowance did not recover")


def records(h, port, data_port, cookie, csrf):
    """Per-address records name the address and cause; a burst records a difficulty bump."""
    endpoint = "/console/api/challenges/records"
    assert h.request(port, "POST", endpoint, {"hours": 3}, cookie, csrf)[0] == 400
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status, _, body = budgeted(h, port, endpoint,
                                   {"hours": 1, "outcome": "rejected", "address": "8.8.12.1"},
                                   cookie, csrf)
        assert status == 200, (status, body)
        page = json.loads(body)
        rows = page["rows"]
        if rows:
            # A body without a challenge id is rejected as "missing id" (cause 2).
            assert all(row["ip"] == "8.8.12.1" and row["outcome"] == "rejected" for row in rows)
            assert rows[0]["cause"] == 2 and rows[0]["duration_ms"] is None, rows[0]
            break
        time.sleep(5)
    else:
        raise AssertionError("the malformed submission left no per-address record")
    status, _, body = budgeted(h, port, endpoint, {"hours": 1, "address": "8.8.12.1"},
                               cookie, csrf)
    assert status == 200 and all(row["ip"] == "8.8.12.1" for row in json.loads(body)["rows"])
    # Issue well above the 50/s baseline from several senders so the smoothed rate climbs even
    # on a loaded host, then keep issuing for two seconds so the one-second bucket rolls and
    # the bump is observed by later issues.
    def issue(index):
        return h.request(data_port, "GET", "/__sibuna/challenge.json?path=/challenge-minutes",
                         extra_headers={"User-Agent": "curl",
                                        "X-Forwarded-For": f"8.8.13.{index % 250}"})[0]

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert all(status == 200 for status in pool.map(issue, range(800)))
    settle = time.monotonic() + 2.5
    index = 0
    while time.monotonic() < settle:
        issue(index)
        index += 1
        time.sleep(0.05)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status, _, body = budgeted(h, port, "/console/api/challenges/difficulty",
                                   {"hours": 1}, cookie, csrf)
        assert status == 200, (status, body)
        page = json.loads(body)
        if any(int(row["bits"]) > int(row["previous_bits"]) for row in page["rows"]):
            assert page["current_bits"] is not None
            return
        time.sleep(5)
    raise AssertionError("the issue burst recorded no adaptive-difficulty transition")
