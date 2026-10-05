#!/usr/bin/env python3
"""Qualify durable CRS selection, node convergence, leader loss and restart."""
import argparse
import crs_fixture_source as fixtures
import json
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

import console_bootstrap_test as bootstrap
import console_e2e as helper
from console_cluster_test import Cluster, members, supports_cluster
from crs_console_check import ATTACK, HEADERS, PASSWORD
from crs_management_check import prepare, request, select, status
from proxy_e2e import exchange
from proxy_fixture import origin


class CrsCluster(Cluster):
    def __init__(self, binary, root, candidate, upstream):
        super().__init__(str(binary), root, helper)
        self.candidate, self.upstream = candidate, upstream
        self.seeded = False
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps({"waf": False, "default_action": "ALLOW", "rules": [
            {"name": "cluster-admission", "path": "*", "action": "ALLOW"}]}))

    def node_args(self, node):
        args = super().node_args(node) + ["--upstream-port", str(self.upstream),
                                          "--policy-file", str(self.policy)]
        if node == 0 and not self.seeded:
            self.seeded = True
            args += ["--crs-mode", "audit", "--crs-dir", str(self.candidate), "--crs-slots", "2"]
        return args

    def close(self):
        errors = []
        for node, process in enumerate(self.procs):
            if process is None:
                continue
            try:
                self.stop(node)
            except BaseException as error:
                errors.append(str(error))
                if process.poll() is None:
                    process.kill()
                    process.wait()
        for log in self.logs:
            log.flush()
            log.seek(0)
            content = log.read()
            if any(word in content for word in ("panic", "leaked", "abandoned cluster member")):
                errors.append(content[-3000:])
            log.close()
        assert not errors, errors


def convergence(cluster, sessions, revision, mode):
    def observed():
        for node, process in enumerate(cluster.procs):
            if process is None:
                continue
            view = status(cluster.consoles[node], *sessions[node])
            local = view["local"]["selection"]
            if view["revision"] != revision or not local or local["revision"] != revision:
                return False
            assert local["mode"] == mode, view
            assert (local["slots"] == 0) == (mode == "off"), view
        return True
    cluster.wait(observed, 180, f"CRS revision {revision} applied on every running node")


def scenario(cluster):
    cluster.start(1)
    cluster.start(2)
    bootstrap_result = subprocess.run([cluster.binary, "init-admin", "admin"] +
                                      cluster.cluster_args(0), capture_output=True,
                                      text=True, timeout=120)
    assert bootstrap_result.returncode == 0, bootstrap_result.stderr
    temporary = re.search(r"Temporary console password .*: ([0-9a-f]{48})",
                          bootstrap_result.stderr)[1]
    cluster.start(0)
    for node in range(3):
        cluster.ready(node)
    credentials = bootstrap.change(helper, cluster.consoles[0], {
        "username": "admin", "password": temporary}, PASSWORD)
    sessions = [cluster.session(node, credentials) for node in range(3)]
    convergence(cluster, sessions, 1, "audit")
    for port in cluster.data:
        assert exchange(port, ATTACK, HEADERS)[0] == 200
    port, session = cluster.consoles[0], sessions[0]
    before = status(port, *session)
    candidate = prepare(port, *session, before, "enforce")
    assert all(exchange(data, ATTACK, HEADERS)[0] == 200 for data in cluster.data)
    select(port, *session, candidate, 1, "enforce")
    convergence(cluster, sessions, 2, "enforce")
    assert all(exchange(data, ATTACK, HEADERS)[0] == 403 for data in cluster.data)
    leader = cluster.wait(lambda: members(helper, port, session)["page"]["storage"]["leader"],
                          30, "leader known") - 1
    cluster.stop(leader)
    survivor, other = (leader + 1) % 3, (leader + 2) % 3
    port, session = cluster.consoles[survivor], sessions[survivor]
    cluster.wait(lambda: members(helper, port, session)["page"]["storage"]["quorum"],
                 60, "survivors have quorum")
    candidate = prepare(port, *session, status(port, *session), "off")
    select(port, *session, candidate, 2, "off")
    convergence(cluster, sessions, 3, "off")
    cluster.stop(other)
    def quorum_unavailable():
        code, _, body = helper.request(port, "GET", "/console/api/nodes", cookie=session[0])
        if code == 503:
            return True
        assert code == 200, (code, body)
        return not json.loads(body)["page"]["storage"]["quorum"]
    cluster.wait(quorum_unavailable, 30, "quorum loss visible or management unavailable")
    code, _, body = request(port, *session, "prepare", {
        "id": uuid.uuid4().hex, "kind": "mode", "expected_revision": "3"})
    assert code in (409, 429, 503), (code, body)
    assert exchange(cluster.data[survivor], ATTACK, HEADERS)[0] == 200
    cluster.start(other)
    cluster.ready(other)
    cluster.start(leader)
    cluster.ready(leader)
    convergence(cluster, sessions, 3, "off")
    for port in cluster.data:
        assert exchange(port, ATTACK, HEADERS)[0] == 200
    port, session = cluster.consoles[survivor], sessions[survivor]
    candidate = prepare(port, *session, status(port, *session), kind="rollback")
    select(port, *session, candidate, 3, "enforce")
    convergence(cluster, sessions, 4, "enforce")
    assert all(exchange(data, ATTACK, HEADERS)[0] == 403 for data in cluster.data)
    identifier = uuid.uuid4().hex
    code, _, body = request(port, *session, "prepare", {
        "id": identifier, "kind": "check", "expected_revision": "4", "version": "4.30.0",
        "configuration": "# position check\nInvalidDirective private-cluster-configuration\n"})
    assert code == 200, (code, body)
    def refused():
        view = status(port, *session)
        assert view["revision"] == 4, view
        candidate = next(row for row in view["candidates"] if row and row["id"] == identifier)
        if candidate["state"] != "failed":
            assert candidate["state"] == "preparing", candidate
            return False
        diagnostic = candidate["diagnostic"]
        assert diagnostic["path"] == "sibuna-operator.conf" and diagnostic["line"] == 2
        assert "private-cluster-configuration" not in json.dumps(diagnostic)
        return True
    cluster.wait(refused, 180, "incompatible candidate refused without changing selection")
    convergence(cluster, sessions, 4, "enforce")
    assert all(exchange(data, ATTACK, HEADERS)[0] == 403 for data in cluster.data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    fixtures.arguments(parser)
    args = parser.parse_args()
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-cluster-") as temporary:
        root = Path(temporary)
        assert supports_cluster(str(binary), helper, root), "requires a cluster-enabled binary"
        candidate = fixtures.resolve(binary, args, root)
        application, worker = origin()
        cluster = CrsCluster(binary, root, candidate, application.server_port)
        try:
            scenario(cluster)
        except BaseException:
            for node, log in enumerate(cluster.logs):
                log.flush()
                log.seek(0)
                print(f"Node {node + 1} log tail:\n{log.read()[-3000:]}")
            raise
        finally:
            try:
                cluster.close()
            finally:
                application.shutdown()
                application.server_close()
                worker.join(5)
    print("Three-node CRS: Audit/Enforce/Off, separate selection, leader loss, quorum refusal, "
          "restart restoration, exact rollback and clean shutdown pass.")


if __name__ == "__main__":
    main()
