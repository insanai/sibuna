"""Live durable scheduling: independent cooldowns, bounded retries and stable identities."""
import collections
import http.server
import json
from pathlib import Path
import tempfile
import threading
import time
import console_bootstrap_test as bootstrap
from console_notify_test import call
from console_users_test import login


class Receiver(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with self.server.lock:
            self.server.received.append((self.path, self.headers.get("Idempotency-Key"),
                                         json.loads(body), time.monotonic()))
        self.send_response(500 if self.path == "/retry" else 204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def receipts(server):
    with server.lock:
        return list(server.received)


def wait_for(server, expected):
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        rows = receipts(server)
        counts = collections.Counter(row[0] for row in rows)
        if all(counts[path] >= count for path, count in expected.items()):
            return rows
        time.sleep(0.1)
    raise AssertionError((expected, receipts(server)))


def ban(h, port, suffix):
    code, _, body = h.request(port, "GET", "/__sibuna/honeypot", extra_headers={
        "X-Forwarded-For": f"203.0.113.{suffix}", "User-Agent": "Mozilla/5.0"})
    assert code == 403, (code, body)


def checks(h, port, data_port, admin, server):
    for path, cooldown in (("/fast", 0), ("/slow", 10), ("/retry", 0)):
        call(h, port, admin, "save", {
            "kind": "webhook", "label": path[1:], "events": 2,
            "target": f"http://127.0.0.1:{server.server_port}{path}",
            "cooldown_seconds": cooldown})
    ban(h, data_port, 171)
    # Wait for the first collector observation before raising a distinct second event.
    wait_for(server, {"/fast": 1, "/slow": 1})
    ban(h, data_port, 172)
    rows = wait_for(server, {"/fast": 2, "/slow": 2, "/retry": 6})
    # Exceed the old event-wide retry interval to catch unintended extra sends.
    time.sleep(3)
    rows = receipts(server)
    assert collections.Counter(row[0] for row in rows) == {
        "/fast": 2, "/slow": 2, "/retry": 6}, rows
    for path in ("/fast", "/slow", "/retry"):
        selected = [row for row in rows if row[0] == path]
        identities = collections.Counter(row[1] for row in selected)
        assert None not in identities and len(identities) == 2, identities
        assert set(identities.values()) == ({3} if path == "/retry" else {1}), identities
    slow = [row for row in rows if row[0] == "/slow"]
    # Storage uses second-granularity timestamps; allow the fractional boundary.
    assert slow[1][3] - slow[0][3] >= 9, slow
    query, audited = {"action": "notification.delivery"}, []
    for _ in range(3):
        code, _, body = h.request(port, "POST", "/console/api/audit/query", query, *admin)
        assert code == 200, (code, body)
        page = json.loads(body)
        audited.extend(page["rows"])
        if page["next"] is None:
            break
        query["before"] = str(page["next"])
    assert len(audited) == 10 and len({row["id"] for row in audited}) == 10, audited


def check(binary, h):
    server = http.server.HTTPServer(("127.0.0.1", 0), Receiver)
    server.lock, server.received = threading.Lock(), []
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix="sibuna-deliveries-") as directory:
            root = Path(directory)
            temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
            with (root / "daemon.log").open("w+") as log:
                port = h.port()
                proc = h.start(binary, str(root / "data"), port, log,
                               extra=("--trust-forwarded",))
                try:
                    credentials = bootstrap.change(h, port, temporary,
                                                   "delivery regression private passphrase")
                    cookie, csrf, _ = login(h, port, credentials)
                    data_port = int(proc.args[proc.args.index("--port") + 1])
                    checks(h, port, data_port, (cookie, csrf), server)
                finally:
                    h.stop(proc)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
    print("console-e2e: independent cooldowns, durable bounded retries and delivery audit passed")


if __name__ == "__main__":
    import sys
    import console_e2e
    check(sys.argv[1], console_e2e)
