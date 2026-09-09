"""The signed-in dashboard's network workload, with independent subscriber coverage.

This measures server work, not browser rendering. The visible rankings and open timeline
each refresh every ten seconds, matching the Wasm controllers. Geometry loads once.
"""
import json
import math
import socket
import threading
import time
from console_topics_client import Client


class Dashboard:
    def __init__(self, helper, port, cookie, csrf):
        self.helper, self.port, self.cookie, self.csrf = helper, port, cookie, csrf
        self.stopping, self.lock = threading.Event(), threading.Lock()
        self.stream, self.threads = None, []
        self.totals = {"frames": 0, "rankings": 0, "timeline": 0,
                       "http_errors": 0, "stream_errors": 0, "reconnects": 0}
        self.closes = {}

    def increment(self, key):
        with self.lock:
            self.totals[key] += 1

    def snapshot(self):
        with self.lock:
            return dict(self.totals)

    def connect(self):
        self.client = Client(self.port, self.cookie, record_messages=False)
        self.client.command("sub", "stats")
        self.client.stream.sock.settimeout(None)
        return self.client.stream

    def start(self):
        code, _, body = self.helper.request(self.port, "GET", "/console/assets/world-110m.bin",
                                            cookie=self.cookie)
        assert code == 200 and body, ("geometry", code)
        self.stream = self.connect()
        for target in (self.read, self.poll):
            thread = threading.Thread(target=target, daemon=True)
            self.threads.append(thread)
            thread.start()

    def read(self):
        while not self.stopping.is_set():
            try:
                value = self.client.receive()
                if value is None:
                    continue
                if value.get("closed"):
                    code = value["code"]
                    with self.lock:
                        self.closes[code] = self.closes.get(code, 0) + 1
                    raise ConnectionError("stream closed")
                if value.get("op") == "gap" or "error" in value:
                    raise ConnectionError("subscription requires a fresh snapshot")
                complete = value.get("op") == "snapshot_end" or (
                    value.get("op") == "delta" and value["part"] + 1 == value["parts"])
                if value.get("topic") == "stats" and complete:
                    assert "timestamp" in self.client.states["stats"]
                    self.increment("frames")
            except (OSError, ValueError, AssertionError):
                if self.stopping.is_set():
                    return
                self.increment("stream_errors")
                close(self.stream)
                while not self.stopping.wait(1):
                    try:
                        replacement = self.connect()
                        with self.lock:
                            if self.stopping.is_set():
                                close(replacement)
                                return
                            self.stream = replacement
                            self.totals["reconnects"] += 1
                        break
                    except (OSError, AssertionError):
                        continue

    def poll(self):
        while not self.stopping.is_set():
            started = time.monotonic()
            for kind, method, body in (("rankings", "GET", None),
                                       ("timeline", "POST", {"limit": 10})):
                if self.stopping.is_set():
                    return
                try:
                    code, _, result = self.helper.request(
                        self.port, method, f"/console/api/{kind}", body, self.cookie, self.csrf)
                    assert code == 200 and isinstance(json.loads(result), dict), (kind, code)
                    self.increment(kind)
                except (OSError, ValueError, AssertionError):
                    self.increment("http_errors")
            self.stopping.wait(max(0, 10 - (time.monotonic() - started)))

    def stop(self):
        with self.lock:
            self.stopping.set()
            stream = self.stream
        if stream is not None:
            close(stream)
        for thread in self.threads:
            # The shared HTTP helper has a 15-second socket deadline. Let its one
            # outstanding request finish; stopping prevents the next request starting.
            thread.join(timeout=17)
            if thread.is_alive():
                raise RuntimeError("dashboard client failed to stop")


def close(stream):
    # Wake a blocked buffered read before closing the file; no timeout corrupts framing.
    try:
        stream.sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    stream.close()


def difference(before, after):
    assert len(before) == len(after)
    return [{key: current[key] - previous[key] for key in current}
            for previous, current in zip(before, after)]


def covered(samples, subscribers):
    """Never infer an individual dashboard's health by dividing an aggregate count."""
    for sample in samples:
        if not math.isfinite(sample["wall_seconds"]) or sample["wall_seconds"] <= 0:
            return False
        clients = sample["dashboards"]
        if len(clients) != subscribers:
            return False
        for client in clients:
            if (client["frames"] / sample["wall_seconds"] < 0.8 or
                    client["rankings"] == 0 or client["timeline"] == 0 or
                    client["http_errors"] != 0 or client["stream_errors"] != 0):
                return False
    return bool(samples)
