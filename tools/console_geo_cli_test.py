"""Native GeoIP orchestration uses HTTP contracts, including uncertain import outcomes."""
import json
from pathlib import Path
import subprocess
import tempfile
import time
from console_client_test import Peer, peer
from console_cli_test import private, invoke


class GeoPeer(Peer):
    def send(self, result):
        payload = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        assert self.path == "/console/api/geoip"
        assert int(self.headers.get("Content-Length", "0")) == 0
        self.server.requests.append((self.path, dict(self.headers), None))
        mode = self.server.mode
        revision = 9007199254740993
        submitted = any(r[2] and "source_version" in r[2] for r in self.server.requests)
        result = {"revision": str(revision), "digest": "a" * 64, "source_version": "2026-08",
                  "ranges": 200, "loaded_at": 100, "status": "idle", "processed_ranges": 0,
                  "source": "DB-IP IP to Country Lite", "license": "CC BY 4.0",
                  "attribution": "https://db-ip.com"}
        if mode in ("noop", "checksum"):
            result["source_version"] = "2026-09"
        if mode == "private":
            result["internal_trace"] = "must not reach command output"
        if submitted:
            result.update(revision=str(revision + 1), source_version="2026-09",
                          status="applied", processed_ranges=200)
            if mode == "race":
                result["revision"] = str(revision + 2)
            if mode == "failed":
                result.update(revision=str(revision), source_version="2026-08", status="failed")
            if mode == "poll-timeout":
                self.server.release.wait(3)
                return
        self.send(result)

    def do_POST(self):
        if self.path != "/console/api/geoip":
            return super().do_POST()
        length = int(self.headers["Content-Length"])
        assert 0 < length <= 2048
        body = json.loads(self.rfile.read(length))
        self.server.requests.append((self.path, dict(self.headers), body))
        assert body == {"source_version": "2026-09", "expected_revision": "9007199254740993",
                        "checksum": "a" * 64}
        self.send({"accepted": True})


def controlled(binary):
    with tempfile.TemporaryDirectory(prefix="sibuna-geo-cli-") as directory:
        password = private(Path(directory) / "password", "geo CLI private credential")
        for mode, failure in (("applied", None), ("noop", None), ("race", "Conflict"),
                              ("checksum", "Conflict"), ("failed", "ImportFailed"),
                              ("private", "InvalidResponse"), ("poll-timeout", "Deadline")):
            with peer(mode, GeoPeer) as server:
                checksum = ("b" if mode == "checksum" else "a") * 64
                started = time.monotonic()
                result = subprocess.run([
                    binary, "console", "geoip", "update", "--month", "2026-09",
                    "--checksum", checksum, "--timeout", "1", "--origin",
                    f"http://127.0.0.1:{server.server_port}", "--username", "admin",
                    "--password-file", str(password),
                ], capture_output=True, text=True, timeout=8)
                elapsed = time.monotonic() - started
                if failure:
                    assert result.returncode == 1 and failure in result.stderr, result.stderr
                    assert not result.stdout
                else:
                    assert result.returncode == 0, result.stderr
                    assert json.loads(result.stdout)["source_version"] == "2026-09"
                assert "geo CLI private credential" not in result.stdout + result.stderr
                assert "must not reach command output" not in result.stdout + result.stderr
                assert "CONSOLECLICLOSE" not in result.stderr, result.stderr
                assert server.requests[-1][0] == "/console/api/logout"
                for _, headers, _ in server.requests[1:]:
                    assert headers["Cookie"] == "__sibuna_console=" + "a" * 64
                    assert headers["X-Console-CSRF"] == "b" * 64
                if mode in ("noop", "checksum", "private"):
                    assert len(server.requests) == 3
                if mode == "poll-timeout":
                    assert 0.9 <= elapsed < 4, elapsed
    print("console-e2e: native GeoIP CAS, no-op, failure, reply bounds and deadline passed")


def live(binary, h, port, credentials, root):
    password = private(Path(root) / "geo-cli-password", credentials["password"])
    args = {"username": credentials["username"]}
    before = invoke(binary, port, password, ["geoip", "status"], **args)
    assert before["ranges"] == 200 and before["revision"] == 1
    after = invoke(binary, port, password, [
        "geoip", "update", "--month", "2026-09", "--checksum", before["digest"].upper(),
    ], **args)
    assert before == after
    invoke(binary, port, password, [
        "geoip", "update", "--month", "2026-09", "--checksum", "0" * 64,
    ], "Conflict", **args)
