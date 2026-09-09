"""Notifications: destination validation, sealed secrets, a real webhook delivery with an
HMAC signature, a UDP syslog line, and audit records without secret bytes."""
import hashlib
import hmac
import http.server
import json
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import time
import console_bootstrap_test as bootstrap
from console_users_test import login


class Receiver(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.deliveries.append((dict(self.headers), body))
        response = b"error" * (1800 if self.path == "/large-error" else 1)
        failed = self.path in ("/small-error", "/large-error")
        self.send_response(500 if failed else 204)
        if failed:
            self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        if failed:
            self.wfile.write(response)

    def log_message(self, *args):
        pass


class SyslogReceiver(socketserver.StreamRequestHandler):
    def handle(self):
        size = bytearray()
        while len(size) < 8:
            byte = self.rfile.read(1)
            if byte == b" ":
                break
            assert byte.isdigit(), byte
            size.extend(byte)
        length = int(size)
        assert 0 < length <= 1024
        line = self.rfile.read(length)
        assert len(line) == length
        self.server.lines.append(line)
        self.server.received.set()


def call(h, port, session, endpoint, body, expected=200):
    code, _, reply = h.request(port, "POST", f"/console/api/notifications/{endpoint}", body,
                               *session)
    assert code == expected, (endpoint, code, reply)
    return json.loads(reply) if reply else None


def test_receipts(h, port, admin):
    receipts = {}
    for action in ("notification.test", "notification.test_result"):
        code, _, body = h.request(port, "POST", "/console/api/audit/query",
                                  {"action": action}, *admin)
        rows = json.loads(body)["rows"]
        assert code == 200 and len(rows) == 3, (code, body)
        entries = {}
        for row in rows:
            code, _, body = h.request(port, "POST", "/console/api/audit/read",
                                      {"id": str(row["id"])}, *admin)
            detail = json.loads(body)
            assert code == 200 and not detail["after_redacted"], (code, body)
            summary = json.loads(detail["after"])
            assert summary["revision"] == 1
            entries[summary["operation"]] = summary["outcome"]
        receipts[action] = entries
    assert receipts["notification.test"].keys() == receipts["notification.test_result"].keys()
    assert set(receipts["notification.test"].values()) == {"started"}
    assert sorted(receipts["notification.test_result"].values()) == ["delivered", "failed", "failed"]


def checks(h, port, data_port, admin, key_file):
    for target in ("https://10.0.0.1/hook", "https://user@hooks.example/x", "ftp://x/y",
                   "http://hooks.example/x", "https://169.254.169.254/latest",
                   "https://hooks.example:9443/x", "http://127.0.0.1:80/hook"):
        call(h, port, admin, "save", {"kind": "webhook", "label": "bad", "target": target,
                                      "events": 15, "cooldown_seconds": 0}, 400)
    server = http.server.HTTPServer(("127.0.0.1", 0), Receiver)
    server.deliveries = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(15)
    tcp = socketserver.TCPServer(("127.0.0.1", 0), SyslogReceiver)
    tcp.lines, tcp.received = [], threading.Event()
    tcp_worker = threading.Thread(target=tcp.serve_forever, daemon=True)
    tcp_worker.start()
    try:
        hook = f"http://127.0.0.1:{server.server_port}/hook"
        saved = call(h, port, admin, "save", {"kind": "webhook", "label": "lobby", "target": hook,
                                              "secret": "shared hook secret", "events": 15,
                                              "cooldown_seconds": 0})
        webhook_id = int(saved["id"])
        syslog = call(h, port, admin, "save", {"kind": "syslog", "label": "collector-tcp",
                                               "transport": "udp",
                                               "target": f"127.0.0.1:{udp.getsockname()[1]}",
                                               "events": 2, "cooldown_seconds": 0})
        stream = call(h, port, admin, "save", {
            "kind": "syslog", "label": "framed collector", "transport": "tcp",
            "target": f"127.0.0.1:{tcp.server_address[1]}", "events": 2, "cooldown_seconds": 0})
        page = call(h, port, admin, "query", {})
        rows = {int(r["id"]): r for r in page["rows"]}
        assert rows[webhook_id]["secret_set"] and not rows[int(syslog["id"])]["secret_set"]
        assert rows[int(syslog["id"])]["transport"] == "udp"
        assert rows[int(stream["id"])]["transport"] == "tcp"
        assert "shared hook secret" not in json.dumps(page)
        result = call(h, port, admin, "test", {"id": webhook_id})
        assert result["delivered"] and result["audit_recorded"], result
        headers, body = server.deliveries[-1]
        digest = hmac.new(b"shared hook secret", body, hashlib.sha256).hexdigest()
        assert headers.get("X-Sibuna-Signature") == f"sha256={digest}", headers
        assert json.loads(body)["event"] == "denial_spike"
        # Neither a small nor oversized 500 response is a successful delivery.
        for path in ("/small-error", "/large-error"):
            error_hook = call(h, port, admin, "save", {
                "kind": "webhook", "label": "failure probe",
                "target": f"http://127.0.0.1:{server.server_port}{path}",
                "events": 1, "cooldown_seconds": 0})
            result = call(h, port, admin, "test", {"id": int(error_hook["id"])})
            assert not result["delivered"] and result["detail"] == "status 500", result
            assert result["audit_recorded"], result
            call(h, port, admin, "remove", {"id": int(error_hook["id"]),
                                             "expected_revision": 1})
        test_receipts(h, port, admin)
        # A real ban raises an event that the notifier delivers to both destinations.
        assert h.request(data_port, "GET", "/__sibuna/honeypot", extra_headers={
            "X-Forwarded-For": "203.0.113.77", "User-Agent": "Mozilla/5.0"})[0] == 403
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if any(json.loads(b)["event"] == "ban" for _, b in server.deliveries):
                break
            time.sleep(0.5)
        else:
            raise AssertionError("ban event never reached the webhook")
        line, _ = udp.recvfrom(2048)
        assert line.startswith(b"<132>1 ") and b" sibuna - ban - " in line, line
        assert tcp.received.wait(15), "framed TCP syslog was not delivered"
        assert b" sibuna - ban - " in tcp.lines[0], tcp.lines
        call(h, port, admin, "remove", {"id": webhook_id, "expected_revision": 99}, 409)
        call(h, port, admin, "remove", {"id": webhook_id, "expected_revision": 1})
        code, _, body = h.request(port, "POST", "/console/api/audit/query",
                                  {"action": "notification.create"}, *admin)
        assert code == 200 and len(json.loads(body)["rows"]) == 5
        assert b"shared hook secret" not in body and b"hook" not in body.lower().replace(b"webhook", b"")
    finally:
        server.shutdown()
        server.server_close()
        udp.close()
        tcp.shutdown()
        tcp.server_close()
        tcp_worker.join(timeout=5)


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-console-notify-") as directory:
        root = Path(directory)
        key_file = root / "console.key"
        key_file.write_text("0f" * 32)
        key_file.chmod(0o600)
        temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
        with (root / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, str(root / "data"), port, log, key_file=str(key_file),
                           extra=("--trust-forwarded",))
            try:
                credentials = bootstrap.change(h, port, temporary,
                                               "notify admin private passphrase")
                cookie, csrf, _ = login(h, port, credentials)
                data_port = int(proc.args[proc.args.index("--port") + 1])
                checks(h, port, data_port, (cookie, csrf), key_file)
            finally:
                h.stop(proc)
    print("console-e2e: notification targets, sealed secrets, webhook HMAC and syslog passed")


if __name__ == "__main__":
    import sys
    import console_e2e
    check(sys.argv[1], console_e2e)
