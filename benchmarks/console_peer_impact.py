"""Real TLS management mesh for impact measurements; no peer observations are fabricated."""
import json
import os
import time
import console_e2e as h
import console_peer_fixture as fixture
import console_totp_test as totp
from console_tls_ingress import Ingress
from console_ws_test import Stream


class Mesh:
    def __init__(self, root, ports):
        self.ports = ports
        self.tls_ports = [h.port() for _ in ports]
        self.cert, tls_key = fixture.certificate(root)
        self.peer_key, self.console_key = root / "peer.key", root / "console.key"
        for path in (self.peer_key, self.console_key):
            path.write_text(os.urandom(32).hex())
            path.chmod(0o600)
        self.ingresses = []
        try:
            for port, target in zip(self.tls_ports, ports):
                self.ingresses.append(Ingress(port, target, self.cert, tls_key))
        except BaseException:
            self.close()
            raise

    def args(self, index):
        args = ["--console-behind-proxy", "--console-origin", "https://console.test",
                "--console-trusted-proxy", "127.0.0.1/32",
                "--console-key-file", str(self.console_key),
                "--console-peer-key-file", str(self.peer_key),
                "--console-peer-ca-file", str(self.cert)]
        for other, port in enumerate(self.tls_ports):
            if other != index:
                args += ["--console-peer", f"{other + 1}=https://localhost:{port}"]
        return args

    @staticmethod
    def request(*args, **kwargs):
        headers = {"Origin": "https://console.test", "X-Forwarded-Proto": "https"}
        kwargs["extra_headers"] = dict(headers, **kwargs.get("extra_headers", {}))
        return h.request(*args, **kwargs)

    @staticmethod
    def stream(port, cookie):
        return Stream(port, cookie, "/console/ws", origin="https://console.test",
                      extra_headers={"X-Forwarded-Proto": "https"})

    def credentials(self, temporary):
        # Enrollment consumes five password checks. Use another real node for enrollment;
        # the measured node then issues a session through normal replicated authorization.
        credentials, _, _, recovery = totp.enroll(self, self.ports[1], temporary, True)
        return dict(credentials, code=recovery[0])

    def snapshot(self, cookie):
        result = []
        for observer, port in enumerate(self.ports, 1):
            status, _, body = self.request(port, "GET", "/console/api/nodes", cookie=cookie)
            if status != 200:
                raise RuntimeError(f"management peer coverage unavailable: HTTP {status}")
            rows = json.loads(body)["peers"]
            result.extend(dict(row, observer=observer) for row in rows)
        return result

    def ready(self, cookie):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if current(self.snapshot(cookie), require_geo=False):
                return
            time.sleep(0.5)
        raise RuntimeError("six authenticated management directions did not become current")

    def close(self):
        for ingress in self.ingresses:
            ingress.close()
        self.ingresses = []


def current(rows, require_geo=True):
    expected = {(observer, node) for observer in (1, 2, 3) for node in (1, 2, 3)
                if observer != node}
    pairs = {(row["observer"], row["node"]) for row in rows}
    return len(rows) == 6 and pairs == expected and all(
        row["status"] == "current" and row["boot"] is not None
        and row["age_seconds"] is not None and row["age_seconds"] <= 2
        and row["clock_skew_seconds"] is not None and row["clock_skew_seconds"] <= 2
        and (row["geoip_available"] or not require_geo) for row in rows)


def coverage(before, after, seconds):
    if not current(before) or not current(after) or seconds <= 0:
        return False
    previous = {(row["observer"], row["node"]): row for row in before}
    for row in after:
        start = previous[(row["observer"], row["node"])]
        if row["boot"] != start["boot"] or row["resets"] != start["resets"]:
            return False
        if int(row["watermark"]) <= int(start["watermark"]):
            return False
    return True
