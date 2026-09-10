"""Full SBR1 envelopes exercise the shipped Wasm memory and stack, independently of the DOM."""
from console_ui_forms import FormValues
import hashlib
import struct
import time


def archive(minute):
    header = b"SBR1" + struct.pack("<I", 1) + b"\x01" * 16
    header += struct.pack("<8QHH", minute, minute * 60, minute * 60,
                          0, 0, 0, 0, 256, 64, 256)
    records = b"".join(struct.pack("<H", 128) + f"/path-{i:03}-".encode().ljust(128, b"p")
                       + struct.pack("<QQ", 1, 0) for i in range(256))
    result = header + records
    assert len(result) == 37468
    return result


def check(ui):
    original = ui.command
    calls = []

    def command(value):
        if value["op"] != "request" or not value["id"].startswith("rank-history-"):
            return original(value)
        calls.append(value)
        query = value["body"]
        minute = int(query["until_minute"]) - (1 if query.get("before") else 0)
        payload = archive(minute)
        cursor = {"minute": str(minute), "digest": hashlib.sha256(payload).hexdigest()}
        body = {"version": 1, "metadata": {
            "from_minute": query["from_minute"], "until_minute": query["until_minute"],
            "retention_days": 7, "observed_at": int(time.time()), "cursor": cursor,
            "next": None if query.get("before") else cursor}, "archive": payload.hex()}
        ui.event(2, {"id": value["id"], "status": 200, "body": body})

    ui.command = command
    try:
        ui.event(1, {"action": "rank-history-toggle", "fields": {}})
        ui.event(1, {"action": "rank-history-start", "fields": {
            "minutes": "5", "offset": "0", "node": "1", "other_node": "1",
            "mode": "yesterday"}})
        assert len(calls) == 4, calls
        fields = FormValues("rank-history-start")
        fields.feed(ui.html)
        assert fields.values == {"mode": "yesterday", "minutes": "5", "offset": "0",
                                 "node": "1", "other_node": "1"}, fields.values
        assert ui.html.count("512 retained samples") == 2, ui.html
        assert "2–2" in ui.html and "RANKHISTORY003" not in ui.html
        ui.event(1, {"action": "rank-history-toggle", "fields": {}})
    finally:
        ui.command = original
