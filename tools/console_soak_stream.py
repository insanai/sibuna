"""Bounded subscription observer; close interrupts and joins its only reader."""
import json
import socket
import threading
import time
from console_ws_test import Stream
from console_topics_client import Client


class Observer:
    def __init__(self, port, cookie, node, proxy=False):
        self.stream = Stream(port, cookie, "/console/ws",
                             "https://console.test" if proxy else None,
                             {"X-Forwarded-Proto": "https"} if proxy else None)
        self.stream.sock.settimeout(60)
        self.client = Client.from_stream(self.stream, record_messages=False)
        self.stopping = threading.Event()
        self.error = None
        self.messages = 0
        self.snapshots = 0
        self.completed_topics = set()
        self.born = time.monotonic()
        for topic, args in (("stats", {"node": node}), ("nodes", {})):
            self.stream.send(1, json.dumps({"op": "sub", "topic": topic,
                                            "args": args}).encode())
        self.worker = threading.Thread(target=self.read, name="soak-subscription")
        self.worker.start()

    def read(self):
        try:
            while not self.stopping.is_set():
                value = self.client.receive()
                if value is None:
                    continue
                assert "error" not in value and not value.get("closed"), "subscription refused"
                self.messages += 1
                assert not self.client.gaps, "subscription delivery gap"
                complete = value.get("op") == "snapshot_end" or (value.get("op") == "delta" and
                    value.get("part", -1) + 1 == value.get("parts", 0))
                if complete:
                    self.snapshots += 1
                    self.completed_topics.add(value["topic"])
        except BaseException as error:
            if not self.stopping.is_set():
                self.error = type(error).__name__ + ": " + str(error)[:200]

    def summary(self):
        assert self.error is None, self.error
        if time.monotonic() - self.born > 15:
            assert self.completed_topics == {"stats", "nodes"}, "initial snapshots did not complete"
        return {"messages": self.messages, "completed_updates": self.snapshots}

    def close(self):
        self.stopping.set()
        try:
            self.stream.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.worker.join(timeout=5)
        assert not self.worker.is_alive(), "subscription reader did not stop"
        self.stream.close()
