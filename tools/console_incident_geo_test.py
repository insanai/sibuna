"""Real incident commits drive geography without a subscriber or a traffic sampling draw."""
import json
import time
from console_ws_test import Stream


def snapshot(h, port, cookie, expected_country=None, expected_samples=5):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        status, _, body = h.request(port, "GET", "/console/api/stats", cookie=cookie)
        assert status == 200
        stats = json.loads(body)
        geo = stats["incident_geo"]
        assert geo["version"] == 1 and geo["started_at"] > 0
        assert stats["node"] == 1
        assert geo["dropped"] == geo["expired"] == geo["future"] == 0
        if expected_country is None and geo["unknown"] == 15:
            return stats
        if expected_country is not None and any(
                row["code"] == expected_country and row["samples"] == expected_samples
                for row in geo["countries"]):
            return stats
        time.sleep(0.05)
    raise AssertionError("acknowledged findings did not reach the incident geography collector")


def check(h, port, data_port, cookie, csrf):
    geoip = json.loads(h.request(port, "GET", "/console/api/geoip", cookie=cookie)[2])
    embedded = geoip["source"] == "embedded snapshot"
    # The preceding incident scenario generated fifteen findings from 8.8.8.0/24. Without a
    # generation they stay Unknown; a build with an embedded snapshot already resolves them.
    if embedded:
        before = snapshot(h, port, cookie, 0x5553, 15)
        assert before["geoip_available"]
    else:
        before = snapshot(h, port, cookie)
        assert not before["geoip_available"]
    h.geo_import(port, cookie, csrf)
    for index in range(5):
        status, _, _ = h.request(data_port, "GET", "/__sibuna/honeypot",
                                 extra_headers={"X-Forwarded-For": f"8.8.18.{index+1}",
                                                "User-Agent": "Mozilla/5.0"})
        assert status == 403
    after = snapshot(h, port, cookie, 0x5553, 20 if embedded else 5)
    assert after["geoip_available"] and after["incidents"] == 20
    # Earlier findings keep their original attribution: an import never relocates them.
    assert after["incident_geo"]["unknown"] == (0 if embedded else 15)
    check_events(h, port, cookie, csrf)
    stream = Stream(port, cookie)
    try:
        stream.send(1, b'{"op":"subscribe","topics":["stats"]}')
        opcode, body = stream.receive()
        assert opcode == 1
        message = json.loads(body)
        assert message["op"] == "snapshot"
        expected = 20 if embedded else 5
        assert message["data"]["incident_geo"]["countries"][0]["samples"] == expected
    finally:
        stream.close()


def check_events(h, port, cookie, csrf):
    from console_topics_client import Client
    endpoint = "/console/api/events/query"
    assert h.request(port, "POST", endpoint, {"country": "us"}, cookie, csrf)[0] == 400
    query = {"country": "US", "ip": "8.8.18.1"}
    status, _, body = h.request(port, "POST", endpoint, query, cookie, csrf)
    assert status == 200
    row, = json.loads(body)["rows"]
    assert row["country"] == row["geography"]["code"] == "US"
    assert row["geography"]["recorded"] and len(row["geography"]["generation"]) == 64
    query["country"] = "DE"
    assert json.loads(h.request(port, "POST", endpoint, query, cookie, csrf)[2])["rows"] == []
    client = Client(port, cookie)
    try:
        client.command("sub", "events", {"country": "US"})
        client.until(lambda: "events" in client.states and len(client.states["events"]["rows"]) >= 5)
        assert all(row["geography"]["code"] == "US" for row in client.states["events"]["rows"])
        epoch = client.epochs["events"]
        client.command("filter", "events", {"country": "DE"})
        client.until(lambda: client.epochs["events"] != epoch and "events" not in client.pending)
        assert client.states["events"]["rows"] == []
    finally:
        client.close()
