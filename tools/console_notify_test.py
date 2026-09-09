"""Notifications: destination validation, sealed secrets, a real webhook delivery with an
HMAC signature, a UDP syslog line, and audit records without secret bytes."""
import hashlib
import hmac
import http.server
import json
from pathlib import Path
import socket
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


def call(h, port, session, endpoint, body, expected=200):
    code, _, reply = h.request(port, "POST", f"/console/api/notifications/{endpoint}", body,
                               *session)
    assert code == expected, (endpoint, code, reply)
    return json.loads(reply) if reply else None


def checks(h, port, data_port, admin, key_file):
    for target in ("https://10.0.0.1/hook", "https://user@hooks.example/x", "ftp://x/y",
                   "http://hooks.example/x", "https://169.254.169.254/latest"):
        call(h, port, admin, "save", {"kind": "webhook", "label": "bad", "target": target,
                                      "events": 15, "cooldown_seconds": 0}, 400)
    server = http.server.HTTPServer(("127.0.0.1", 0), Receiver)
    server.deliveries = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(15)
    try:
        hook = f"http://127.0.0.1:{server.server_port}/hook"
        saved = call(h, port, admin, "save", {"kind": "webhook", "label": "lobby", "target": hook,
                                              "secret": "shared hook secret", "events": 15,
                                              "cooldown_seconds": 0})
        webhook_id = int(saved["id"])
        syslog = call(h, port, admin, "save", {"kind": "syslog", "label": "collector-udp",
                                               "target": f"127.0.0.1:{udp.getsockname()[1]}",
                                               "events": 2, "cooldown_seconds": 0})
        page = call(h, port, admin, "query", {})
        rows = {int(r["id"]): r for r in page["rows"]}
        assert rows[webhook_id]["secret_set"] and not rows[int(syslog["id"])]["secret_set"]
        assert "shared hook secret" not in json.dumps(page)
        result = call(h, port, admin, "test", {"id": webhook_id})
        assert result["delivered"], result
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
            call(h, port, admin, "remove", {"id": int(error_hook["id"]),
                                             "expected_revision": 1})
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
        call(h, port, admin, "remove", {"id": webhook_id, "expected_revision": 99}, 409)
        call(h, port, admin, "remove", {"id": webhook_id, "expected_revision": 1})
        code, _, body = h.request(port, "POST", "/console/api/audit/query",
                                  {"action": "notification.create"}, *admin)
        assert code == 200 and len(json.loads(body)["rows"]) == 4
        assert b"shared hook secret" not in body and b"hook" not in body.lower().replace(b"webhook", b"")
    finally:
        server.shutdown()
        udp.close()


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
