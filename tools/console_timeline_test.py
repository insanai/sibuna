"""Live retained history is produced without any connected statistics subscriber."""
import json
import time


def check(h, proc, port, cookie, csrf):
    endpoint = "/console/api/timeline"
    assert h.request(port, "POST", endpoint, {})[0] == 401
    assert h.request(port, "POST", endpoint, {}, cookie)[0] == 400
    for query in ({"limit": 0}, {"limit": 17}, {"before": 1}, {"unknown": 1}):
        assert h.request(port, "POST", endpoint, query, cookie, csrf)[0] == 400
    data_port = int(proc.args[proc.args.index("--port") + 1])
    for _ in range(5):
        assert h.request(data_port, "GET", "/timeline-observation")[0] in (401, 403, 502)
    names = ("admitted", "challenged", "denied", "banned", "rate_limited", "other")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status, _, body = h.request(port, "POST", endpoint, {"limit": 16}, cookie, csrf)
        assert status == 200, (status, body)
        page = json.loads(body)
        if sum(int(row["counts"][name]) for row in page["rows"] for name in names) == 5:
            break
        time.sleep(0.25)
    else:
        raise AssertionError("collector did not retain external outcomes without subscribers")
    assert page["version"] == 1 and page["retention_seconds"] == 3600
    assert len(page["boot"]) == 32 and int(page["boot"], 16) != 0
    for row in page["rows"]:
        assert row["end_ms"] - row["start_ms"] == row["observed_ms"] > 0
    cursor = {"before": page["rows"][0]["sequence"], "boot": page["boot"],
              "epoch": page["epoch"], "limit": 1}
    next_page = h.request(port, "POST", endpoint, cursor, cookie, csrf)
    assert next_page[0] == 200
    for row in json.loads(next_page[2])["rows"]:
        assert row["sequence"] < cursor["before"]
    wrong = dict(cursor, boot="f" * 32)
    assert h.request(port, "POST", endpoint, wrong, cookie, csrf)[0] == 409
    saved(h, port, cookie, csrf, cursor["boot"])
    return cursor


def restarted(h, port, cookie, csrf, cursor):
    assert h.request(port, "POST", "/console/api/timeline", cursor, cookie, csrf)[0] == 409
    status, _, body = h.request(port, "POST", "/console/api/timeline", {}, cookie, csrf)
    assert status == 200
    for row in json.loads(body)["rows"]:
        assert all(value == 0 for value in row["counts"].values())
    saved(h, port, cookie, csrf, cursor["boot"])


def saved(h, port, cookie, csrf, boot):
    endpoint = "/console/api/minutes"
    assert h.request(port, "POST", endpoint, {})[0] == 401
    assert h.request(port, "POST", endpoint, {}, cookie)[0] == 400
    assert h.request(port, "POST", endpoint, {"limit": 9}, cookie, csrf)[0] == 400
    names = ("admitted", "challenged", "denied", "banned", "rate_limited", "other")
    expected_boot = list(bytes.fromhex(boot))
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        status, _, body = h.request(port, "POST", endpoint, {}, cookie, csrf)
        assert status == 200, (status, body)
        reply = json.loads(body)
        assert reply["version"] == 1 and reply["retention_days"] == 90
        own = [row for row in reply["rows"] if row["boot"] == expected_boot]
        if sum(int(row["counts"][name]) for row in own for name in names) == 5:
            for row in own:
                assert row["end_ms"] - row["start_ms"] == row["observed_ms"] > 0
                assert not row["complete"] or (row["sealed"] and not row["gap"])
            return
        time.sleep(0.25)
    raise AssertionError("the five external outcomes did not survive in durable minute history")
