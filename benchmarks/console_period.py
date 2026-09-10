"""Mirror the dashboard's retained-period reads, separately from its live stream."""
import json
import threading
import time


class Period:
    def __init__(self, helper, port, cookie, csrf, stopping, increment):
        self.helper, self.port, self.cookie, self.csrf = helper, port, cookie, csrf
        self.stopping, self.increment = stopping, increment
        self.lock = threading.Lock()
        self.scope, self.completed_at = None, None

    def observe(self, value):
        scope = value.get("scope", {})
        selected = scope.get("selected", 0)
        nodes = tuple(row["node"] for row in scope.get("sources", []) if row and
                      (not selected or row["node"] == selected))
        if not nodes and value.get("node"):
            nodes = (value["node"],)
        assert len(nodes) <= 9 and len(set(nodes)) == len(nodes)
        with self.lock:
            self.scope = (int(value["timestamp"]) // 60 - 1, nodes)

    def snapshot(self):
        with self.lock:
            age = None if self.completed_at is None else time.monotonic() - self.completed_at
            details = self.scope is None or len(self.scope[1]) == 1
            return {"period_age_seconds": age, "single_node_details": details}

    def run(self):
        while not self.stopping.is_set():
            with self.lock:
                scope = self.scope
            if scope is None or not scope[1]:
                self.stopping.wait(0.1)
                continue
            try:
                if not self.scan(*scope):
                    return
                with self.lock:
                    self.completed_at = time.monotonic()
                self.increment("period_scans")
                self.stopping.wait(60)
            except (OSError, ValueError, AssertionError, KeyError, TypeError):
                if self.stopping.is_set():
                    return
                self.increment("http_errors")
                self.stopping.wait(60)

    def scan(self, until, nodes):
        for node in nodes:
            for shift in (0, 1440):
                if not self.window(node, until - shift):
                    return False
        return True

    def window(self, node, until):
        query = {"node": node, "from_minute": until - 1439, "until_minute": until,
                 "limit": 96, "before": None}
        # Fixtures have one boot per measured configuration. Sixteen pages cover its
        # full day; reject a broken continuation rather than generating unbounded load.
        for _ in range(16):
            if self.stopping.is_set():
                return False
            code, _, body = self.helper.request(
                self.port, "POST", "/console/api/minutes/summary", query, self.cookie, self.csrf)
            assert code == 200, ("period", code)
            part = json.loads(body)
            assert part["version"] == 1
            window = part["window"]
            assert (window["node"], int(window["from"]), int(window["until"])) == (
                node, query["from_minute"], until)
            assert 0 <= int(window["rows"]) <= 96
            self.increment("period_pages")
            cursor = window["next"]
            assert window["finished"] == (cursor is None)
            if cursor is None:
                return True
            assert cursor == window["last"] and int(window["rows"]) > 0
            if query["before"] is not None:
                assert order(cursor) < order(query["before"]), "period cursor did not advance"
            query["before"] = cursor
        raise AssertionError("period fixture exceeded its bounded day")


def order(cursor):
    return (int(cursor["minute"]), cursor["node"], tuple(cursor["boot"]), cursor["epoch"])
