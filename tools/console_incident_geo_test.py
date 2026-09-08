"""Real incident commits drive geography without a subscriber or a traffic sampling draw."""
import json
import time
from console_ws_test import Stream


def snapshot(h, port, cookie, expected_country=None):
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
                row["code"] == expected_country and row["samples"] == 5
                for row in geo["countries"]):
            return stats
        time.sleep(0.05)
    raise AssertionError("acknowledged findings did not reach the incident geography collector")


def check(h, port, data_port, cookie, csrf):
    # The preceding incident scenario generated fifteen findings with no GeoIP generation.
    before = snapshot(h, port, cookie)
    assert not before["geoip_available"]
    h.geo_import(port, cookie, csrf)
    for index in range(5):
        status, _, _ = h.request(data_port, "GET", "/__sibuna/honeypot",
                                 extra_headers={"X-Forwarded-For": f"8.8.18.{index+1}",
                                                "User-Agent": "Mozilla/5.0"})
        assert status == 403
    after = snapshot(h, port, cookie, 0x5553)
    assert after["geoip_available"] and after["incidents"] == 20
    # Earlier unknown findings are not retrospectively assigned a location after an import.
    assert after["incident_geo"]["unknown"] == 15
    stream = Stream(port, cookie)
    try:
        stream.send(1, b'{"op":"subscribe","topics":["stats"]}')
        opcode, body = stream.receive()
        assert opcode == 1
        message = json.loads(body)
        assert message["op"] == "snapshot"
        assert message["data"]["incident_geo"]["countries"][0]["samples"] == 5
    finally:
        stream.close()
