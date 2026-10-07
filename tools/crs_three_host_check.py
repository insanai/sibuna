#!/usr/bin/env python3
"""Qualify CRS selection, convergence, failover and restart across three real Linux hosts.

This runs the loopback `crs_cluster_check.scenario` against separate machines. Consensus
uses mutual TLS, management uses validated HTTPS peers behind a TLS ingress, and every
console session needs TOTP. The controller reaches loopback listeners through SSH tunnels.

Each host needs a remote root prepared like the 2026-10-01 launch fixture: `control/`
holds agent.py, Caddyfile, node and peer certificates, peer/console keys, the consensus
secret and challenge seed; `runtime/` holds caddy and a `-Dcluster=true` sibuna binary;
node 1 also holds a signed `candidate/` from `sibuna crs check`. See
`benchmarks/results/linux-launch-harness-20261001.json` for those controllers.
"""
import argparse
from datetime import datetime, timezone
import http.client
import json
from pathlib import Path
import re
import shlex
import subprocess
import time

import console_e2e as helper
import console_totp_test as totp
from crs_cluster_check import scenario

DATA, CONSOLE, TLS, CONSENSUS, ORIGIN = 39101, 39102, 39103, 39104, 39105
POLICY = json.dumps({"waf": False, "default_action": "ALLOW", "rules": [
    {"name": "cluster-admission", "path": "*", "action": "ALLOW"}]})
direct_request = helper.request


def proxied(*args, **kwargs):
    # The ingress terminates TLS; the console trusts it to state the original scheme.
    headers = {"Origin": "https://console.test", "X-Forwarded-Proto": "https"}
    kwargs["extra_headers"] = dict(headers, **(kwargs.get("extra_headers") or {}))
    return direct_request(*args, **kwargs)


class RemoteCluster:
    def __init__(self, hosts, root, run):
        self.hosts, self.root, self.run = hosts, root, run
        self.binary = root + "/runtime/sibuna"
        self.procs, self.tunnels, self.infrastructure = [None] * 3, [], []
        self.data, self.consoles, self.seeded, self.serial = [], [], False, 0
        self.recovery = []
        self.processes, self.identities = {}, []
        self.started = time.monotonic()

    def ssh(self, index, args, timeout=150):
        result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                                 self.hosts[index], shlex.join(args)],
                                capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f"host {index + 1}: {result.stderr[-2000:]}")
        return result

    def agent(self, index, operation, value):
        result = self.ssh(index, ["python3", self.root + "/control/agent.py", operation,
                                  json.dumps(value)])
        return json.loads(result.stdout)

    def launch(self, index, name, args):
        kind = name
        self.serial += 1
        name = f"{self.run}-{name}-{self.serial}"
        self.agent(index, "launch", {"name": name, "args": args})
        self.processes[name] = {"node": index + 1, "kind": kind, "name": name,
                                "ready": None, "stop_status": None}
        return name

    def process_status(self, index, name):
        script = ("import json, pathlib, sys; p=pathlib.Path(sys.argv[1]); "
                  "print(json.dumps(int(p.read_text()) if p.exists() else None))")
        result = self.ssh(index, ["python3", "-c", script,
                                 f"{self.root}/processes/{name}/status"])
        return json.loads(result.stdout)

    def identity(self, index):
        script = ("import hashlib,json,pathlib,platform,sys; "
                  "p=pathlib.Path(sys.argv[1]); "
                  "print(json.dumps({'hostname':platform.node(), 'kernel':platform.release(), "
                  "'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}))")
        result = json.loads(self.ssh(index, ["python3", "-c", script, self.binary]).stdout)
        return {"host": self.hosts[index], "binary": self.binary, **result}

    def prepare(self):
        for index in range(3):
            self.identities.append(self.identity(index))
            self.ssh(index, ["sh", "-c", f"umask 077; printf %s {shlex.quote(POLICY)} > "
                             f"{self.root}/control/crs-policy.json"])
            self.infrastructure.append((index, self.launch(index, "tls", [
                self.root + "/runtime/caddy", "run", "--config",
                self.root + "/control/Caddyfile"])))
            self.infrastructure.append((index, self.launch(index, "origin", [
                self.root + "/runtime/caddy", "respond", "--listen",
                f"127.0.0.1:{ORIGIN}", "--body", "origin"])))
            ports = helper.port(), helper.port()
            tunnel = subprocess.Popen([
                "ssh", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-N",
                "-L", f"{ports[0]}:127.0.0.1:{DATA}", "-L", f"{ports[1]}:127.0.0.1:{CONSOLE}",
                self.hosts[index]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.tunnels.append(tunnel)
            self.data.append(ports[0])
            self.consoles.append(ports[1])
        time.sleep(2)
        assert all(tunnel.poll() is None for tunnel in self.tunnels), "SSH tunnel failed"
        assert len({row["sha256"] for row in self.identities}) == 1, "mixed cluster binaries"

    def cluster_args(self, index):
        args = ["--data-dir", f"{self.root}/data/{self.run}", "--storage-poll-ms", "100",
                "--cluster-node", str(index + 1), "--cluster-listen",
                f"{self.address(index)}:{CONSENSUS}",
                "--cluster-secret-file", self.root + "/control/psk",
                "--cluster-tls-cert", self.root + "/control/node.crt",
                "--cluster-tls-key", self.root + "/control/node.key",
                "--cluster-tls-ca", self.root + "/control/peer.pem"]
        for other in range(3):
            if other != index:
                args += ["--cluster-peer", f"{other + 1}@{self.address(other)}:{CONSENSUS}"]
        return args

    def address(self, index):
        return self.hosts[index].split("@", 1)[-1]

    def node_args(self, index):
        control = self.root + "/control/"
        args = [self.binary, "--host", "127.0.0.1", "--port", str(DATA), "--workers", "2",
                "--mode", "reverse_proxy", "--upstream-port", str(ORIGIN),
                "--policy-file", control + "crs-policy.json", "--trust-forwarded",
                "--console", f"127.0.0.1:{CONSOLE}", "--console-behind-proxy",
                "--console-origin", "https://console.test", "--console-trusted-proxy",
                "127.0.0.1/32", "--console-key-file", control + "console.key",
                "--console-peer-key-file", control + "peer.key",
                "--console-peer-ca-file", control + "peer.pem"]
        for other in range(3):
            if other != index:
                args += ["--console-peer", f"{other + 1}=https://agy{other + 1:02}.incus:{TLS}"]
        if index == 0 and not self.seeded:
            # Only the first boot seeds a signed source; restarts restore the durable choice.
            self.seeded = True
            args += ["--crs-mode", "audit", "--crs-dir", self.root + "/candidate",
                     "--crs-slots", "2"]
        return args + self.cluster_args(index)

    def start(self, index):
        self.procs[index] = self.launch(index, f"node{index + 1}", self.node_args(index))

    def ready(self, index, timeout=120):
        started, checked = time.monotonic(), 0
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if time.monotonic() - checked >= 1:
                checked = time.monotonic()
                status = self.process_status(index, self.procs[index])
                if status is not None:
                    raise RuntimeError(f"node {index + 1} exited before readiness: {status}")
            try:
                health = direct_request(self.data[index], "GET", "/__sibuna/health")[0]
                setup = proxied(self.consoles[index], "GET", "/console/api/setup")[0]
                if health == 200 and setup < 500:
                    self.processes[self.procs[index]]["ready"] = {
                        "seconds": time.monotonic() - started, "health": health, "setup": setup}
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.5)
        raise TimeoutError(f"node {index + 1} did not become ready")

    def stop(self, index):
        status = self.agent(index, "stop", {"name": self.procs[index]})["status"]
        self.processes[self.procs[index]]["stop_status"] = status
        assert status == 0, f"node {index + 1} shutdown status {status}"
        self.procs[index] = None

    def bootstrap(self):
        self.start(1)
        self.start(2)
        result = self.ssh(0, [self.binary, "init-admin", "admin"] + self.cluster_args(0))
        temporary = re.search(r"Temporary console password .*: ([0-9a-f]{48})",
                              result.stderr)[1]
        self.start(0)
        for index in range(3):
            self.ready(index)
        credentials, _, _, recovery = totp.enroll(helper, self.consoles[1], {
            "username": "admin", "password": temporary}, True)
        self.recovery = recovery
        return credentials

    def session(self, index, credentials):
        # Recovery codes are single use, so each node's session spends a distinct one.
        # Enrollment already spent this minute's password checks; wait for the limiter.
        body = dict(credentials, code=self.recovery.pop(0))
        deadline = time.monotonic() + 130
        while True:
            code, headers, reply = helper.request(self.consoles[index], "POST",
                                                  "/console/api/login", body)
            if code != 429 or time.monotonic() > deadline:
                break
            time.sleep(10)
        assert code == 200, (code, reply)
        return headers["Set-Cookie"].split(";", 1)[0], json.loads(reply)["csrf"]

    def wait(self, predicate, timeout, what):
        deadline, last = time.monotonic() + timeout, None
        while time.monotonic() < deadline:
            try:
                last = predicate()
                if last:
                    return last
            except (OSError, http.client.HTTPException, AssertionError) as error:
                last = error
            time.sleep(0.5)
        raise AssertionError(f"{what}: {last!r}")

    def close(self):
        errors = []
        for index, name in enumerate(self.procs):
            if name is not None:
                try:
                    self.stop(index)
                except BaseException as error:
                    errors.append(str(error))
        for index, name in reversed(self.infrastructure):
            try:
                status = self.agent(index, "stop", {"name": name})["status"]
                self.processes[name]["stop_status"] = status
                assert status == 0, f"{name} shutdown status {status}"
            except BaseException as error:
                errors.append(str(error))
        for tunnel in self.tunnels:
            tunnel.terminate()
            tunnel.wait(timeout=10)
        assert not errors, errors

    def report(self, build_commit, failure):
        controller = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        changes = subprocess.check_output(["git", "diff", "--name-only", "HEAD"],
                                          text=True).splitlines()
        return {"date": datetime.now(timezone.utc).isoformat(), "run": self.run,
                "build_commit": build_commit, "controller_commit": controller,
                "controller_changes": changes, "binary_identities": self.identities,
                "elapsed_seconds": time.monotonic() - self.started,
                "passed": failure is None, "failure": None if failure is None else str(failure),
                "processes": list(self.processes.values()), "transport": {
                    "consensus": "mutual TLS", "management": "validated HTTPS peers",
                    "controller": "SSH tunnels", "sessions": "TOTP"},
                "required_checks": ["Audit/Enforce/Off", "separate preparation and selection",
                           "leader loss", "quorum refusal", "durable restart restoration",
                           "exact rollback", "incompatible preparation refusal",
                           "all owned daemons and ingress processes stop with status zero"]}

    def logs(self):
        for index, name in enumerate(self.procs):
            if name is not None:
                result = subprocess.run(["ssh", "-o", "BatchMode=yes", self.hosts[index],
                                         f"tail -c 3000 {self.root}/processes/{name}/daemon.log"],
                                        capture_output=True, text=True, timeout=30)
                print(f"Node {index + 1} log tail:\n{result.stdout}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", action="append", required=True,
                        help="user@address for nodes 1, 2 and 3, in order")
    parser.add_argument("--root", required=True, help="prepared remote fixture root")
    parser.add_argument("--report", type=Path, help="write functional qualification provenance")
    parser.add_argument("--build-commit", help="source commit used to build the remote binary")
    args = parser.parse_args()
    if len(args.host) != 3:
        parser.error("exactly three --host values are required")
    if args.report and (not args.build_commit or
                        not re.fullmatch(r"[0-9a-f]{40}", args.build_commit)):
        parser.error("--report requires a full hexadecimal --build-commit")
    helper.request = proxied
    cluster = RemoteCluster(args.host, args.root, str(int(time.time())))
    failure = None
    try:
        cluster.prepare()
        scenario(cluster)
    except BaseException as error:
        failure = error
        cluster.logs()
    finally:
        try:
            cluster.close()
        except BaseException as cleanup:
            if failure is None:
                failure = cleanup
            else:
                failure.add_note(f"Fixture cleanup: {cleanup}")
        if args.report:
            args.report.write_text(json.dumps(cluster.report(args.build_commit, failure),
                                              indent=2) + "\n")
    if failure is not None:
        raise failure
    print("Three-host CRS: Audit/Enforce/Off, separate selection, leader loss, quorum refusal, "
          "restart restoration, exact rollback and clean shutdown pass across real machines.")


if __name__ == "__main__":
    main()
