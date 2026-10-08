#!/usr/bin/env python3
"""Bounded functional soak of persistent console/CRS owners, not a throughput benchmark.

The cluster root must be prepared as documented by crs_three_host_check.py. Keep the
controller on a host that will remain available. Each mode owns an isolated root and
stops its observers, daemons and origin on completion, failure or SIGTERM. A stop file
beside the report requests cleanup. Reports contain no passwords, factors or session tokens.
"""
import argparse
from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time
import console_e2e as h
import console_bootstrap_test as bootstrap
import console_totp_test as totp
from console_soak_stream import Observer
from crs_console_check import ATTACK, HEADERS
from crs_management_check import prepare, select, status
from crs_cluster_check import convergence, scenario
import crs_three_host_check as remote
from proxy_e2e import exchange
from proxy_fixture import origin
import private_file

stopping = False


def signal_stop(*unused):
    global stopping
    stopping = True


def validate_logs(directory):
    for path in Path(directory).rglob("*.log"):
        assert path.stat().st_size < 64 * 1024 * 1024, "log bound exhausted"
        content = path.read_bytes()
        assert not any(word in content for word in (
            b"panic", b"abandoned cluster member", b"memory leaked")), "fatal daemon log"


def resource(pid, directory):
    text = Path(f"/proc/{pid}/status").read_text()
    rss = int(next(line.split()[1] for line in text.splitlines() if line.startswith("VmRSS:")))
    logs = sum(p.stat().st_size for p in Path(directory).rglob("*.log"))
    assert rss < 768 * 1024, "resident memory exceeded the soak's 768 MiB guard"
    assert logs < 64 * 1024 * 1024, "logs exceeded the soak's 64 MiB guard"
    return {"rss_kib": rss, "log_bytes": logs}


class Single:
    def __init__(self, binary, root, candidate):
        self.binary, self.root, self.candidate = str(binary), root, str(candidate)
        root.mkdir(mode=0o700)
        self.data, self.consoles = [h.port()], [h.port()]
        self.observers, self.sessions, self.recovery = [], [], []
        self.procs, self.seeded = [None], False
        self.key = root / "console.key"
        self.key.write_text(os.urandom(32).hex() + "\n")
        private_file.permissions(self.key)
        self.policy = root / "policy.json"
        self.policy.write_text(remote.POLICY)
        self.log = (root / "daemon.log").open("w+")
        self.identities = [{"binary": self.binary,
                            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}]
        try:
            self.application, self.origin_worker = origin()
        except BaseException:
            self.log.close()
            raise

    def start(self, unused=0):
        extra = ["--port", str(self.data[0]), "--upstream-port",
                 str(self.application.server_port), "--policy-file", str(self.policy)]
        if not self.seeded:
            self.seeded = True
            extra += ["--crs-mode", "enforce", "--crs-dir", self.candidate, "--crs-slots", "2"]
        self.procs[0] = h.start(self.binary, str(self.root / "data"), self.consoles[0],
                               self.log, str(self.key), extra=extra)

    def ready(self, unused=0):
        assert h.request(self.consoles[0], "GET", "/console/api/setup")[0] == 200

    def stop(self, unused=0):
        h.stop(self.procs[0])
        self.procs[0] = None
        validate_logs(self.root)

    def setup(self):
        temporary = bootstrap.initialize(self.binary, str(self.root / "data"), "soak-admin")
        self.start()
        self.credentials, self.factor_secret, _, self.recovery = totp.enroll(
            h, self.consoles[0], temporary)
        renew(self)

    def sample(self):
        assert self.procs[0].poll() is None, "single-node daemon exited"
        self.application.requests.clear()
        return [resource(self.procs[0].pid, self.root)]

    def close(self):
        try:
            close_observers(self)
        finally:
            try:
                if self.procs[0] is not None:
                    self.stop()
            finally:
                self.application.shutdown()
                self.application.server_close()
                self.origin_worker.join(timeout=5)
                self.log.close()
                assert not self.origin_worker.is_alive()


class Cluster(remote.RemoteCluster):
    def __init__(self, hosts, root):
        super().__init__(hosts, root, str(int(time.time())))
        self.observers, self.sessions = [], []

    def bootstrap(self):
        self.credentials = super().bootstrap()
        return self.credentials

    def session(self, index, credentials):
        session = super().session(index, credentials)
        if len(self.sessions) <= index:
            self.sessions.append(session)
        else:
            self.sessions[index] = session
        return session

    def setup(self):
        h.request = remote.proxied
        self.prepare()
        scenario(self)
        observe(self)

    def sample(self):
        script = ("import json,sys; from pathlib import Path; "
                  "sys.path.insert(0,sys.argv[1]); from console_soak import resource; "
                  "d=Path(sys.argv[2]); print(json.dumps(resource(int((d/'pid').read_text()),d)))")
        result = []
        for index, name in enumerate(self.procs):
            assert self.process_status(index, name) is None, "cluster daemon exited"
            result.append(json.loads(self.ssh(index, ["python3", "-c", script,
                self.root + "/source/tools", self.root + "/processes/" + name]).stdout))
        return result

    def stop(self, index):
        name = self.procs[index]
        super().stop(index)
        script = ("import sys; sys.path.insert(0,sys.argv[1]); "
                  "from console_soak import validate_logs; validate_logs(sys.argv[2])")
        self.ssh(index, ["python3", "-c", script, self.root + "/source/tools",
                         self.root + "/processes/" + name])

    def close(self):
        try:
            close_observers(self)
        finally:
            super().close()


def close_observers(owner):
    errors = []
    for observer in owner.observers:
        try:
            observer.close()
        except BaseException as error:
            errors.append(str(error))
    owner.observers = []
    assert not errors, errors


def observe(owner):
    assert not owner.observers
    for index, session in enumerate(owner.sessions):
        owner.observers.append(Observer(owner.consoles[index], session[0], index + 1,
                                        isinstance(owner, Cluster)))


def renew(owner):
    close_observers(owner)
    if len(owner.recovery) < len(owner.consoles):
        cookie, csrf = owner.sessions[0]
        body = {"password": owner.credentials["password"],
                "code": totp.code(owner.factor_secret, int(time.time()) // 30)}
        code, _, result = h.request(owner.consoles[0], "POST", "/console/api/totp/recovery",
                                    body, cookie, csrf)
        assert code == 200, "recovery replacement refused"
        owner.recovery = json.loads(result)["recovery_codes"]
    owner.sessions = []
    for port in owner.consoles:
        body = dict(owner.credentials, code=owner.recovery.pop(0))
        owner.sessions.append(recovery_login(port, body))
    observe(owner)


def recovery_login(port, body):
    # Enrollment spends this address's verification quota. Wait; never weaken it.
    deadline = time.monotonic() + 130
    while True:
        code, headers, result = h.request(port, "POST", "/console/api/login", body)
        if code != 429 or time.monotonic() > deadline:
            break
        time.sleep(10)
    assert code == 200, "soak session renewal refused"
    return headers["Set-Cookie"].split(";", 1)[0], json.loads(result)["csrf"]


def check(owner):
    views = [status(port, *session) for port, session in zip(owner.consoles, owner.sessions)]
    revisions = {view["revision"] for view in views}
    modes = {view["local"]["selection"]["mode"] for view in views}
    assert len(revisions) == len(modes) == 1, "nodes disagree outside a planned transition"
    mode = modes.pop()
    for port in owner.data:
        assert exchange(port, "/soak", HEADERS)[0] == 200, "benign request refused"
        assert exchange(port, ATTACK, HEADERS)[0] == (403 if mode == "enforce" else 200)
    streams = [observer.summary() for observer in owner.observers]
    return {"revision": revisions.pop(), "mode": mode,
            "resources": owner.sample(), "subscriptions": streams}


def change_mode(owner):
    before = status(owner.consoles[0], *owner.sessions[0])
    mode = "audit" if before["current"]["artifact"]["settings"]["mode"] == "enforce" else "enforce"
    candidate = prepare(owner.consoles[0], *owner.sessions[0], before, mode)
    select(owner.consoles[0], *owner.sessions[0], candidate, before["revision"], mode)
    if isinstance(owner, Cluster):
        convergence(owner, owner.sessions, before["revision"] + 1, mode)


def write_report(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def run(owner, args):
    started = time.monotonic()
    report = {"source_commit": args.build_commit, "kind": args.kind, "state": "starting",
              "start_utc": datetime.now(timezone.utc).isoformat(), "seconds": args.seconds,
              "identities": owner.identities, "samples": [], "checks": 0, "restarts": 0,
              "selections": 0, "peak_rss_kib": [0] * len(owner.procs),
              "scope": "Functional soak. Bounded traffic and multi-topic subscriptions; not performance acceptance."}
    samples = deque(maxlen=40)
    failure = None
    complete = False
    try:
        owner.setup()
        started = time.monotonic()
        report["active_start_utc"] = datetime.now(timezone.utc).isoformat()
        report["identities"] = owner.identities
        restart_at, select_at, renew_at = args.restart_seconds, args.select_seconds, 1200
        while time.monotonic() - started < args.seconds and not stopping:
            if args.report.with_name("stop").exists():
                break
            elapsed = time.monotonic() - started
            if elapsed >= renew_at:
                renew(owner)
                renew_at = elapsed + 1200
            if elapsed >= restart_at:
                close_observers(owner)
                index = report["restarts"] % len(owner.procs)
                owner.stop(index)
                owner.start(index)
                owner.ready(index)
                if isinstance(owner, Cluster):
                    view = status(owner.consoles[0], *owner.sessions[0])
                    convergence(owner, owner.sessions, view["revision"], view["current"]["artifact"]["settings"]["mode"])
                observe(owner)
                report["restarts"] += 1
                restart_at = elapsed + args.restart_seconds
            if elapsed >= select_at:
                change_mode(owner)
                report["selections"] += 1
                select_at = elapsed + args.select_seconds
            sample = {"elapsed_seconds": round(time.monotonic() - started, 2), **check(owner)}
            samples.append(sample)
            report["checks"] += 1
            for index, resource_sample in enumerate(sample["resources"]):
                report["peak_rss_kib"][index] = max(report["peak_rss_kib"][index], resource_sample["rss_kib"])
            report.update(state="running", samples=list(samples), elapsed_seconds=sample["elapsed_seconds"])
            write_report(args.report, report)
            time.sleep(min(15, max(0, args.seconds - (time.monotonic() - started))))
        complete = (time.monotonic() - started >= args.seconds and not stopping and
                    not args.report.with_name("stop").exists())
    except BaseException as error:
        failure = type(error).__name__ + ": " + str(error)[:500]
    finally:
        try:
            owner.close()
            report["cleanup"] = "All owned daemons, observers and origins stopped cleanly."
        except BaseException as error:
            failure = (failure or "") + "; cleanup: " + str(error)[:500]
        report.update(state="failed" if failure else "passed" if complete else "interrupted",
                      failure=failure, elapsed_seconds=round(time.monotonic() - started, 2),
                      end_utc=datetime.now(timezone.utc).isoformat())
        write_report(args.report, report)
    assert failure is None, failure


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("single", "cluster"))
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--root", required=True)
    parser.add_argument("--host", action="append")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--build-commit", required=True)
    parser.add_argument("--seconds", type=int, default=43200)
    parser.add_argument("--restart-seconds", type=int, default=600)
    parser.add_argument("--select-seconds", type=int, default=1800)
    args = parser.parse_args()
    if not 30 <= args.seconds <= 43200 or not 15 <= args.restart_seconds <= 3600:
        parser.error("duration must be 30..43200 seconds; restart interval must be 15..3600")
    if args.select_seconds < 60 or args.report.exists():
        parser.error("selection interval must be at least 60 seconds; report must be new")
    if len(args.build_commit) != 40 or any(c not in "0123456789abcdef" for c in args.build_commit):
        parser.error("--build-commit must be the full hexadecimal source identity")
    if args.kind == "cluster" and len(args.host or []) != 3:
        parser.error("cluster mode requires exactly three --host values")
    if args.kind == "single" and (not args.binary or not args.candidate):
        parser.error("single mode requires --binary and --candidate")
    signal.signal(signal.SIGTERM, signal_stop)
    signal.signal(signal.SIGINT, signal_stop)
    owner = Cluster(args.host, args.root) if args.kind == "cluster" else Single(
        args.binary.resolve(), Path(args.root), args.candidate.resolve())
    run(owner, args)


if __name__ == "__main__":
    main()
