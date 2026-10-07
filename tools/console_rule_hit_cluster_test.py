"""Rule observations survive replication, leader loss and producer restarts."""
import json
import time
from console_reads import budgeted
import console_rule_hit_sampling as sampling


def capture(cluster, harness, session, revision):
    first = sampling.begin(lambda: time.sleep(0.25))
    for index in range(20):
        status, _, _ = harness.request(cluster.data[2], "GET", "/cluster-rule", extra_headers={
            "X-Forwarded-For": f"8.8.10.{index + 1}", "User-Agent": "Mozilla/5.0"})
        assert status == 403, status
    last = sampling.finish(first)
    deadline = time.monotonic() + 75
    while time.time() < (last + 1) * 60 + 2 and time.monotonic() < deadline:
        time.sleep(0.25)
    assert time.time() >= (last + 1) * 60 + 2, "replicated rule observation seal deadline"
    query = {"key": "m:cluster-rule", "node": 3, "from_minute": first,
             "until_minute": last, "revision": revision}
    expected = cluster.wait(lambda: read(harness, cluster.consoles[0], session, query, 20),
                            30, "node 3 observations readable on node 1")
    return query, expected


def read(harness, port, session, query, minimum):
    code, _, body = budgeted(harness, port, "POST", "/console/api/policies/hits", query, *session)
    assert code == 200, (code, body)
    window = json.loads(body)["window"]
    assert window["request"]["node"] == 3 and window["request"]["key"] == query["key"]
    assert window["finished"] and window["next"] is None, window
    hits = window["hits"]
    return int(hits) if hits is not None and int(hits) >= minimum else None


def recovered(cluster, harness, node, session, captured):
    query, expected = captured
    actual = cluster.wait(lambda: read(harness, cluster.consoles[node], session, query, expected),
                          30, "rule observations retained after failover and restart")
    assert actual == expected, (actual, expected)
    print("console-e2e: replicated rule history survives failover and restart without duplicates")
