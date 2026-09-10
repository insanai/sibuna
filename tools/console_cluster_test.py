#!/usr/bin/env python3
"""Three-node console scenario: membership, edit propagation, leader loss, lost quorum,
rejoin, cross-node revocation and local-command isolation. Requires -Dcluster=true."""
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import console_bootstrap_test as bootstrap
import console_rule_hit_cluster_test as rule_history
from console_users_test import login

NODES = 3


class Cluster:
    def __init__(self, binary, root, h):
        self.binary, self.root, self.h = binary, Path(root), h
        self.data = [self.h.port() for _ in range(NODES)]
        self.peers = [self.h.port() for _ in range(NODES)]
        self.consoles = [self.h.port() for _ in range(NODES)]
        self.procs = [None] * NODES
        self.logs = [open(self.root / f"node{i + 1}.log", "w+") for i in range(NODES)]
        self.psk = self.root / "psk"
        self.psk.write_bytes(os.urandom(32).hex().encode())
        self.psk.chmod(0o600)
        self.logins = []

    def cluster_args(self, i):
        args = ["--data-dir", str(self.root / f"node{i + 1}"), "--storage-poll-ms", "100",
                "--cluster-node", str(i + 1), "--cluster-listen", f"127.0.0.1:{self.peers[i]}",
                "--cluster-secret-file", str(self.psk)]
        for j in range(NODES):
            if i != j:
                args += ["--cluster-peer", f"{j + 1}@127.0.0.1:{self.peers[j]}"]
        return args

    def start(self, i):
        args = [self.binary, "--host", "127.0.0.1", "--port", str(self.data[i]), "--workers", "1",
                "--trust-forwarded", "--console", f"127.0.0.1:{self.consoles[i]}",
                "--console-advertise", f"http://127.0.0.1:{self.consoles[i]}"]
        for j in range(NODES):
            if i != j:
                args += ["--console-probe", f"{j + 1}=http://127.0.0.1:{self.data[j]}"]
        args += self.cluster_args(i)
        self.procs[i] = subprocess.Popen(args, stdout=self.logs[i], stderr=self.logs[i])

    def ready(self, i, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.procs[i].poll() is not None:
                raise RuntimeError(f"node {i + 1} exited with {self.procs[i].returncode}")
            try:
                if self.h.request(self.consoles[i], "GET", "/console/api/setup")[0] == 200:
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.2)
        raise TimeoutError(f"node {i + 1} console did not become ready")

    def stop(self, i):
        proc = self.procs[i]
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.logs[i].flush()
            self.logs[i].seek(0)
            tail = self.logs[i].read()[-3000:]
            proc.kill()
            proc.wait()
            raise AssertionError(f"node {i + 1} did not stop within 30 s; log tail:\n{tail}")
        assert proc.returncode == 0, f"node {i + 1} shutdown status {proc.returncode}"
        self.procs[i] = None

    def session(self, i, credentials):
        # The login limiter allows five attempts per minute per address and account.
        self.logins = [t for t in self.logins if time.monotonic() - t < 60]
        if len(self.logins) >= 4:
            time.sleep(max(0, 61 - (time.monotonic() - self.logins[0])))
        self.logins.append(time.monotonic())
        cookie, csrf, _ = login(self.h, self.consoles[i], credentials)
        return cookie, csrf

    def wait(self, predicate, timeout, what):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                last = predicate()
                if last:
                    return last
            except (OSError, http.client.HTTPException, AssertionError) as error:
                last = error
            time.sleep(0.25)
        raise AssertionError(f"{what}: {last!r}")


def members(h, port, session):
    code, _, body = h.request(port, "GET", "/console/api/nodes", cookie=session[0])
    assert code == 200, code
    return json.loads(body)


def supports_cluster(binary, h, root):
    log = open(Path(root) / "probe.log", "w+")
    proc = subprocess.Popen([binary, "--host", "127.0.0.1", "--port", str(h.port()),
                             "--data-dir", str(Path(root) / "probe"), "--cluster-node", "1",
                             "--cluster-listen", "127.0.0.1:1"], stdout=log, stderr=log)
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return True
    log.seek(0)
    return "ClusterSupportNotBuilt" not in log.read()


def probe_health(page, node):
    for probe in page["probes"]:
        if probe["node"] == node:
            return probe["health"]
    return None


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-console-cluster-") as root:
        if not supports_cluster(binary, h, root):
            print("console-e2e: cluster scenarios skipped (build with -Dcluster=true)")
            return
        cluster = Cluster(binary, root, h)
        try:
            scenario(cluster, h)
        except BaseException:
            for i, log in enumerate(cluster.logs):
                proc = cluster.procs[i]
                status = "running" if proc is not None and proc.poll() is None else (
                    "stopped" if proc is None else f"exited {proc.returncode}")
                log.flush()
                log.seek(0)
                print(f"--- node {i + 1} ({status}) log tail ---\n{log.read()[-3000:]}")
            raise
        finally:
            for i in range(NODES):
                if cluster.procs[i] is not None and cluster.procs[i].poll() is None:
                    cluster.procs[i].terminate()
                    cluster.procs[i].wait(timeout=30)
            for log in cluster.logs:
                log.seek(0)
                text = log.read()
                assert "ChainMismatch" not in text and "leaked" not in text, text[-800:]
                # Zaxonlite 0.6.2 bounds its own shutdown; Sibuna's 15 s safety net must
                # never trigger.
                assert "did not stop within" not in text, text[-800:]
                assert "abandoned cluster member" not in text, text[-800:]
    print("console-e2e: three-node membership, edit, failover, quorum loss, rejoin passed")


def scenario(c, h):
    c.start(1)
    c.start(2)
    # Bootstrap the administrator into the replicated store through node 1's identity.
    result = subprocess.run([c.binary, "init-admin", "admin"] + c.cluster_args(0),
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    import re
    temporary = re.search(r"Temporary console password .*: ([0-9a-f]{48})", result.stderr)[1]
    c.start(0)
    for i in range(NODES):
        c.ready(i)
    credentials = bootstrap.change(h, c.consoles[0], {"username": "admin", "password": temporary},
                                   "cluster admin private passphrase")
    c.logins.append(time.monotonic())
    s1 = c.session(0, credentials)
    # The first announcement can precede the advertised origin by one storage tick.
    page = c.wait(lambda: (lambda p: p if len(p["page"]["members"]) == NODES and
                           all(m["last_seen"] > 0 and m["console_url"]
                               for m in p["page"]["members"]) else None)(
                               members(h, c.consoles[0], s1)), 60, "all members announced")
    assert page["page"]["storage"]["role"] in ("leader", "follower")
    assert page["page"]["storage"]["quorum"]
    leader = c.wait(lambda: members(h, c.consoles[0], s1)["page"]["storage"]["leader"], 30,
                    "leader known")
    assert any(m["node"] == leader for m in page["page"]["members"])
    assert all(m["console_url"] == f"http://127.0.0.1:{c.consoles[m['node'] - 1]}"
               for m in page["page"]["members"])
    c.wait(lambda: all(probe_health(members(h, c.consoles[0], s1), n) == "healthy"
                       for n in (2, 3)), 30, "peers probed healthy")
    # A rule saved on node 1's console changes node 3's decision.
    code, _, body = h.request(c.consoles[0], "POST", "/console/api/policies/query", {}, *s1)
    assert code == 200
    committed = json.loads(body)["committed"]
    document = {"id": "cluster-rule", "name": "Cluster rule", "action": "deny",
                "path": "/cluster-rule"}
    code, _, body = h.request(c.consoles[0], "POST", "/console/api/policies/edit",
                              {"expected_revision": committed, "document": json.dumps(document)},
                              *s1)
    assert code == 200, body
    saved = int(json.loads(body)["committed"])
    c.wait(lambda: h.request(c.data[2], "GET", "/cluster-rule", extra_headers={
        "X-Forwarded-For": "8.8.9.7", "User-Agent": "Mozilla/5.0"})[0] == 403, 30,
           "node 3 enforces the rule")
    c.wait(lambda: all(int(m["applied_revision"]) >= saved
                       for m in members(h, c.consoles[0], s1)["page"]["members"]), 30,
           "every member acknowledged the revision")
    captured_hits = rule_history.capture(c, h, s1, saved)
    # Leader loss: survivors keep serving reads and report the stopped member as down.
    lost = leader - 1
    survivor = (lost + 1) % NODES
    other = (lost + 2) % NODES
    c.stop(lost)
    s2 = c.session(survivor, credentials)
    c.wait(lambda: probe_health(members(h, c.consoles[survivor], s2), leader) == "down", 30,
           "stopped member probed down")
    new_leader = c.wait(lambda: (lambda l: l if l not in (None, leader) else None)(
        members(h, c.consoles[survivor], s2)["page"]["storage"]["leader"]), 45, "new leader")
    assert new_leader in (survivor + 1, other + 1)
    assert h.request(c.consoles[survivor], "GET", "/console/api/stats", cookie=s2[0])[0] == 200
    # Two of three still commit: an edit on one survivor is enforced by the other.
    code, _, body = h.request(c.consoles[survivor], "POST", "/console/api/policies/query", {},
                              *s2)
    assert code == 200
    document = {"id": "cluster-rule-2", "name": "Cluster rule 2", "action": "deny",
                "path": "/cluster-rule-2"}
    code, _, body = h.request(c.consoles[survivor], "POST", "/console/api/policies/edit",
                              {"expected_revision": json.loads(body)["committed"],
                               "document": json.dumps(document)}, *s2)
    assert code == 200, body
    c.wait(lambda: h.request(c.data[other], "GET", "/cluster-rule-2", extra_headers={
        "X-Forwarded-For": "8.8.9.8", "User-Agent": "Mozilla/5.0"})[0] == 403, 30,
           "other survivor enforces the second rule")
    # Lost quorum: mutations fail quickly and honestly; the data plane keeps serving.
    c.stop(other)
    started = time.monotonic()
    code, _, body = h.request(c.consoles[survivor], "POST", "/console/api/policies/edit",
                              {"expected_revision": "1", "document": json.dumps(document)}, *s2)
    assert code == 503 and time.monotonic() - started < 15, (code, body)
    assert b"CONSOLEQUORUM" in body, body
    assert h.request(c.data[survivor], "GET", "/__sibuna/health")[0] == 200
    assert h.request(c.data[survivor], "GET", "/cluster-rule", extra_headers={
        "X-Forwarded-For": "8.8.9.9", "User-Agent": "Mozilla/5.0"})[0] == 403
    # Rejoin: both stopped nodes return with new boots and the second rule applied.
    c.start(lost)
    c.start(other)
    c.ready(lost)
    c.ready(other)
    s3 = c.session(survivor, credentials)
    c.wait(lambda: all(probe_health(members(h, c.consoles[survivor], s3), n) == "healthy"
                       for n in (lost + 1, other + 1)), 90, "rejoined members healthy")
    c.wait(lambda: h.request(c.data[lost], "GET", "/cluster-rule-2", extra_headers={
        "X-Forwarded-For": "8.8.9.10", "User-Agent": "Mozilla/5.0"})[0] == 403, 60,
           "restarted node enforces the second rule")
    rule_history.recovered(c, h, survivor, s3, captured_hits)
    # Revocation on one console ends a session issued by another.
    s4 = c.session(other, credentials)
    assert h.request(c.consoles[other], "GET", "/console/api/session", cookie=s4[0])[0] == 200
    assert h.request(c.consoles[survivor], "POST", "/console/api/logout", {}, *s4)[0] == 200
    c.wait(lambda: h.request(c.consoles[other], "GET", "/console/api/session",
                             cookie=s4[0])[0] == 401, 10, "revoked on the other console")
    # A local drain affects only its node; sessions and receipts replicate.
    s5 = s3
    code, _, body = h.request(c.consoles[lost], "GET", "/console/api/nodes/local", cookie=s5[0])
    assert code == 200
    node = json.loads(body)
    request = dict(id=node["operation_id"], node=node["node"], boot=node["boot"],
                   expected_revision=str(node["control_revision"]), kind="drain")
    code, _, body = h.request(c.consoles[lost], "POST", "/console/api/nodes/command", request,
                              *s5)
    assert code == 200 and json.loads(body)["state"] == "applied", body
    assert h.request(c.data[lost], "GET", "/__sibuna/health")[0] == 503
    assert h.request(c.data[survivor], "GET", "/__sibuna/health")[0] == 200
    c.wait(lambda: h.request(c.consoles[survivor], "POST", "/console/api/nodes/command/read",
                             {"id": request["id"]}, *s3)[0] == 200, 30,
           "receipt readable from another console")
    for i in range(NODES):
        c.stop(i)


if __name__ == "__main__":
    import console_e2e
    check(os.path.abspath(sys.argv[1]), console_e2e)
