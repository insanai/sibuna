"""Strict bounded test client for the console's chunked multi-topic protocol."""
import json
import time
from console_ws_test import Stream


class Client:
    def __init__(self, port, cookie, record_messages=True):
        self.stream = Stream(port, cookie, "/console/ws")
        self.states = {}
        self.epochs = {}
        self.sequences = {}
        self.pending = {}
        self.gaps = []
        self.messages = []
        self.record_messages = record_messages

    def command(self, op, topic=None, args=None):
        message = {"op": op}
        if topic is not None:
            message["topic"] = topic
        if args is not None:
            message["args"] = args
        self.stream.send(1, json.dumps(message).encode())

    def receive(self):
        opcode, body = self.stream.receive()
        if opcode == 9:
            self.stream.send(10, body)
            return None
        if opcode == 8:
            return {"closed": True, "code": int.from_bytes(body[:2], "big")}
        assert opcode == 1 and len(body) <= 2048, (opcode, body)
        message = json.loads(body)
        if self.record_messages:
            self.messages.append(message)
            assert len(self.messages) <= 10000, "fixture received an unbounded message flood"
        op = message.get("op")
        if op == "pong" or "error" in message:
            return message
        topic = message["topic"]
        if op == "gap":
            assert message["epoch"] == self.epochs[topic]
            self.gaps.append(message)
            self.pending.pop(topic, None)
            self.epochs.pop(topic)
            return message
        sequence = int(message["seq"])
        if op == "snapshot_begin":
            assert sequence == 0 and message["snapshot"]
            assert message["epoch"] != self.epochs.get(topic)
            self.epochs[topic] = message["epoch"]
            self.sequences[topic] = 0
            self.pending[topic] = {"snapshot": True, "watermark": message["watermark"],
                                   "parts": message["parts"], "part": 0, "text": ""}
            return message
        assert message["epoch"] == self.epochs[topic], message
        assert sequence == self.sequences[topic] + 1, message
        self.sequences[topic] = sequence
        if op == "snapshot_end":
            pending = self.pending.pop(topic)
            assert pending["snapshot"] and pending["part"] == pending["parts"]
            assert message["watermark"] == pending["watermark"]
            self.states[topic] = json.loads(pending["text"])
            return message
        assert op in ("snapshot_chunk", "delta"), message
        if op == "delta" and message["part"] == 0:
            assert topic not in self.pending
            self.pending[topic] = {"snapshot": False, "update": message["update"],
                                   "parts": message["parts"], "part": 0, "text": "",
                                   "kind": message["kind"]}
        pending = self.pending[topic]
        assert message["part"] == pending["part"] and message["parts"] == pending["parts"]
        if op == "delta":
            assert not pending["snapshot"] and message["update"] == pending["update"]
        else:
            assert pending["snapshot"] and message["watermark"] == pending["watermark"]
        pending["text"] += message["data"]
        assert len(pending["text"].encode()) <= 65536
        pending["part"] += 1
        if op == "delta" and pending["part"] == pending["parts"]:
            self.pending.pop(topic)
            self.apply(topic, pending["kind"], json.loads(pending["text"]))
        return message

    def apply(self, topic, kind, data):
        if kind == "row":
            assert topic in ("events", "audit")
            rows = self.states[topic]["rows"]
            assert all(row["id"] != data["id"] for row in rows), "duplicate committed event"
            rows.insert(0, data)
            del rows[64:]
            return
        assert kind == "patch" and set(data) == {"set", "remove"}
        assert not set(data["set"]).intersection(data["remove"])
        for key in data["remove"]:
            self.states[topic].pop(key, None)
        self.states[topic].update(data["set"])

    def until(self, predicate, seconds=20):
        deadline = time.monotonic() + seconds
        while not predicate():
            assert time.monotonic() < deadline, self.states
            result = self.receive()
            assert not result or not result.get("closed"), result
            assert not result or "error" not in result, result

    def close(self):
        self.stream.close()
