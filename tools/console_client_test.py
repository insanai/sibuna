"""Exercise native HTTP client boundaries and session cleanup against a controlled peer."""
import contextlib
import http.server
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from console_cli_test import private


class Peer(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        assert 0 <= length <= 2048
        body = json.loads(self.rfile.read(length)) if length else None
        self.server.requests.append((self.path, dict(self.headers), body))
        mode = self.server.mode
        if mode == "deadline":
            self.server.release.wait(30)
            return
        if mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "/credential-trap")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/console/api/login":
            result = {"user": "9007199254740993", "role": "admin", "must_change": False,
                      "totp_required": False, "csrf": "b" * 64}
        elif self.path == "/console/api/users/query":
            result = {"version": 1, "rows": [], "next": None}
            if mode == "private":
                result["internal_trace"] = "must not reach command output"
        else:
            assert self.path == "/console/api/logout"
            result = {"signed_out": True}
        payload = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if self.path == "/console/api/login":
            self.send_header("Set-Cookie", "__sibuna_console=" + "a" * 64 + "; HttpOnly")
        self.send_header("Content-Length", str(16385 if mode == "oversize" else len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@contextlib.contextmanager
def peer(mode, handler=Peer):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.mode = mode
    server.requests = []
    server.release = threading.Event()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def check(binary):
    with tempfile.TemporaryDirectory(prefix="sibuna-client-") as directory:
        password_file = private(Path(directory) / "credential", "client boundary test password")
        for mode, failure in (("normal", None), ("private", "InvalidResponse"),
                              ("redirect", "Transport"), ("oversize", "ResponseTooLarge"),
                              ("deadline", "Deadline")):
            with peer(mode) as server:
                started = time.monotonic()
                result = subprocess.run([
                    binary, "console", "users", "--origin",
                    f"http://127.0.0.1:{server.server_port}", "--username", "admin",
                    "--password-file", str(password_file),
                ], capture_output=True, text=True, timeout=26)
                elapsed = time.monotonic() - started
                if failure:
                    assert result.returncode == 1 and failure in result.stderr, result.stderr
                    assert not result.stdout
                else:
                    assert result.returncode == 0 and not result.stderr, result.stderr
                    assert json.loads(result.stdout) == {"version": 1, "rows": [], "next": None}
                assert "client boundary test password" not in result.stdout + result.stderr
                assert "must not reach command output" not in result.stdout + result.stderr
                paths = [row[0] for row in server.requests]
                if mode in ("normal", "private"):
                    assert paths == ["/console/api/login", "/console/api/users/query",
                                     "/console/api/logout"], paths
                    for _, headers, _ in server.requests[1:]:
                        assert headers["Cookie"] == "__sibuna_console=" + "a" * 64
                        assert headers["X-Console-CSRF"] == "b" * 64
                else:
                    assert paths == ["/console/api/login"], paths
                if mode == "deadline":
                    assert 19 <= elapsed < 25, elapsed
    print("console-e2e: native client bounds, redirect refusal, deadline and logout passed")
