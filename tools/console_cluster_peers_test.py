"""Three real TLS console peers: local-only contributions, boot recovery and quorum isolation."""
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import time
from types import SimpleNamespace
import console_cluster_test as cluster_test
import console_peer_fixture as fixture
import console_peer_test as peer_test
import console_totp_test as totp
from console_tls_ingress import Ingress
from console_topics_client import Client


class Cluster(cluster_test.Cluster):
    def __init__(self, binary, root, h):
        headers = {"Origin": "https://console.test", "X-Forwarded-Proto": "https"}
        def request(*args, **kwargs):
            kwargs["extra_headers"] = dict(headers, **kwargs.get("extra_headers", {}))
            return h.request(*args, **kwargs)
        trusted = SimpleNamespace(port=h.port, request=request)
        super().__init__(binary, root, trusted)
        self.raw = h
        self.tls_ports = [h.port() for _ in range(3)]
        self.cert, tls_key = fixture.certificate(self.root)
        self.master = os.urandom(32)
        self.key = fixture.proof(self.master, b"key", b"")
        self.peer_key = self.root / "console-peer.key"
        self.console_key = self.root / "console.key"
        for path, key in ((self.peer_key, self.master), (self.console_key, os.urandom(32))):
            path.write_text(key.hex())
            path.chmod(0o600)
        self.ingresses = [Ingress(self.tls_ports[i], self.consoles[i], self.cert, tls_key)
                          for i in range(3)]

    def start(self, i):
        args = [self.binary, "--host", "127.0.0.1", "--port", str(self.data[i]), "--workers", "1",
                "--trust-forwarded", "--console", f"127.0.0.1:{self.consoles[i]}",
                "--console-behind-proxy", "--console-origin", "https://console.test",
                "--console-trusted-proxy", "127.0.0.1/32", "--console-key-file", str(self.console_key),
                "--console-peer-key-file", str(self.peer_key), "--console-peer-ca-file", str(self.cert)]
        for j in range(3):
            if i != j:
                args += ["--console-peer", f"{j + 1}=https://localhost:{self.tls_ports[j]}"]
        self.procs[i] = subprocess.Popen(args + self.cluster_args(i), stdout=self.logs[i],
                                        stderr=self.logs[i])

    def close(self):
        failures = []
        for i, proc in enumerate(self.procs):
            if proc is None or proc.poll() is not None:
                continue
            try:
                self.stop(i)
            except BaseException as error:
                failures.append(str(error))
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
        for ingress in self.ingresses:
            ingress.close()
        for log in self.logs:
            log.seek(0)
            text = log.read()
            if any(word in text for word in ("panic", "leaked", "abandoned cluster member")):
                failures.append(text[-3000:])
            log.close()
        assert not failures, failures


def reports(c, node, cookie):
    status, _, body = c.h.request(c.consoles[node], "GET", "/console/api/nodes", cookie=cookie)
    assert status == 200, body
    return {row["node"]: row for row in json.loads(body)["peers"]}


def traffic(c, node, count=16):
    for _ in range(count):
        status, _, _ = c.raw.request(c.data[node], "GET", "/peer-traffic", extra_headers={
            "X-Forwarded-For": "8.8.8.8", "User-Agent": "Mozilla/5.0", "Accept": "text/html"})
        assert status in (200, 302, 403, 429, 503), status


def retained(c, cookie, csrf):
    port = c.consoles[0]
    query = {"node": 2, "limit": 10}
    status, _, body = c.h.request(port, "POST", "/console/api/timeline", query, cookie, csrf)
    assert status == 200, (status, body)
    page = json.loads(body)
    assert page["node"] == 2 and 0 < len(page["rows"]) <= 8, page
    assert sum(sum(int(value) for key, value in row["counts"].items()
                   if key not in ("origin_4xx", "origin_5xx")) for row in page["rows"]) >= 16, page
    # A freshly restarted node can have fewer than eight seconds. Ask for one row to
    # exercise real pagination without assuming a slow machine or sleeping through traffic.
    query["limit"] = 1
    status, _, body = c.h.request(port, "POST", "/console/api/timeline", query, cookie, csrf)
    page = json.loads(body)
    assert status == 200 and page["next_before"] is not None, page
    cursor = dict(query, before=page["next_before"], epoch=page["epoch"], boot=page["boot"])
    status, _, body = c.h.request(port, "POST", "/console/api/timeline", cursor, cookie, csrf)
    older = json.loads(body)
    assert status == 200 and older["node"] == 2 and older["boot"] == page["boot"], body
    assert all(int(row["sequence"]) < int(cursor["before"]) for row in older["rows"])
    status, _, body = c.h.request(port, "POST", "/console/api/rankings/query", {"node": 2},
                                  cookie, csrf)
    rankings = json.loads(body)
    assert status == 200 and rankings["node"] == 2, body
    assert bytes(rankings["boot"]).hex() == page["boot"] and len(rankings["rows"]) <= 8
    assert c.h.request(port, "POST", "/console/api/timeline", {"node": 99}, cookie, csrf)[0] == 503
    return cursor


def retention_shared(c, cookie, csrf, write=False):
    form = {"key": "retention.minutes", "value": "1", "confirmed": True,
            "expected_revision": "0"}
    if write:
        status, _, body = c.h.request(c.consoles[0], "POST", "/console/api/settings/change",
                                      form, cookie, csrf)
        assert status == 200, (status, body)
        status, _, body = c.h.request(c.consoles[1], "POST", "/console/api/settings/change",
                                      form, cookie, csrf)
        assert status == 409, (status, body)
    for port in c.consoles:
        status, _, body = c.h.request(port, "POST", "/console/api/settings/query", {}, cookie, csrf)
        rows = json.loads(body)
        assert status == 200, (status, body)
        saved = next(row for row in rows if row["key"] == form["key"])
        assert saved["value"] == "1" and str(saved["revision"]) == "1", saved


def scenario(c):
    c.start(1)
    c.start(2)
    result = subprocess.run([c.binary, "init-admin", "peer-admin"] + c.cluster_args(0),
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    temporary = re.search(r"Temporary console password .*: ([0-9a-f]{48})", result.stderr)[1]
    c.start(0)
    for i in range(3):
        c.ready(i)
    credentials, _, _, recovery = totp.enroll(c.h, c.consoles[0], {
        "username": "peer-admin", "password": temporary}, True)
    # Verify restart ownership and reset the setup operation's verification allowance.
    for i in range(3):
        c.stop(i)
    for i in (1, 2, 0):
        c.start(i)
    for i in range(3):
        c.ready(i)
    status, headers, body = c.h.request(c.consoles[0], "POST", "/console/api/login",
                                      dict(credentials, code=recovery[0]))
    assert status == 200, body
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    csrf = json.loads(body)["csrf"]
    retention_shared(c, cookie, csrf, write=True)
    for i in range(3):
        peer_test.wait(lambda: all(row["status"] == "current" for row in reports(c, i, cookie).values()),
                       "all direct peers observed")
    original = reports(c, 0, cookie)
    traffic(c, 1)
    current = peer_test.wait(lambda: (rows if (rows := reports(c, 0, cookie))[2]["requests"] >= 16
                                      else None), "node 2 contribution received")
    # Node 3 receives node 2's telemetry, but must never forward it as node 3's own traffic.
    peer_test.wait(lambda: reports(c, 2, cookie)[2]["requests"] >= 16, "second direct observer")
    assert reports(c, 0, cookie)[3]["requests"] == original[3]["requests"]
    cursor = retained(c, cookie, csrf)
    c.stop(1)
    stale = peer_test.wait(lambda: (rows[2] if (rows := reports(c, 0, cookie))[2]["status"] == "stale"
                                   else None), "stopped member stale")
    assert stale["requests"] >= current[2]["requests"]
    assert c.h.request(c.consoles[0], "POST", "/console/api/timeline", {"node": 2},
                       cookie, csrf)[0] == 503
    c.stop(2)
    # No majority remains. A separately authenticated management link still receives local
    # snapshots, including beyond the browser authorization/storage wait interval.
    context = ssl.create_default_context(cafile=str(c.cert))
    stream, status, _ = peer_test.incoming(c.tls_ports[0], c.key, tls=context)
    assert status == 101
    client = Client.from_stream(stream)
    try:
        client.command("sub", "stats", {})
        client.until(lambda: "stats" in client.states)
        before = dict(client.states["stats"])
        traffic(c, 0)
        client.until(lambda: client.states["stats"]["requests"] >= before["requests"] + 16)
        client.until(lambda: client.states["stats"]["timestamp"] >= before["timestamp"] + 12)
        assert client.states["stats"]["node"] == 1 and not client.gaps
    finally:
        client.close()
    for i in (1, 2):
        c.start(i)
        c.ready(i)
    restored = peer_test.wait(lambda: (rows[2] if (rows := reports(c, 0, cookie))[2]["status"] == "current"
                                      and rows[2]["boot"] != original[2]["boot"] else None),
                             "rejoined peer has a new boot", 60)
    assert restored["resets"] >= 1
    assert restored["requests"] == 0, "boot changes establish a fresh counter origin"
    assert c.h.request(c.consoles[0], "POST", "/console/api/timeline", cursor,
                       cookie, csrf)[0] == 409, "old boot cursor must not cross a peer restart"
    retention_shared(c, cookie, csrf)


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-cluster-peers-") as root:
        if not cluster_test.supports_cluster(binary, h, root):
            print("console-e2e: TLS cluster peers skipped (build with -Dcluster=true)")
            return
        cluster = Cluster(binary, root, h)
        try:
            scenario(cluster)
        except BaseException:
            for index, log in enumerate(cluster.logs):
                log.flush()
                log.seek(0)
                print(f"peer node {index + 1}: {log.read()[-3000:]}")
            raise
        finally:
            cluster.close()
    print("console-e2e: three TLS peers, local-only totals, quorum isolation and restart passed")


if __name__ == "__main__":
    import sys
    import console_e2e as h
    check(os.path.abspath(sys.argv[1]), h)
