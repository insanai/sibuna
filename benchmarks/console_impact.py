#!/usr/bin/env python3
"""Console isolation gate (SID 0007): data-plane throughput and p99 with the console compiled
out, compiled in but disabled, idle, and serving eight live dashboards, under admitted,
challenged, denied and policy-reload workloads. Rounds interleave configurations in rotated
order; a noisy baseline yields "inconclusive", never a pass.

    python3 benchmarks/console_impact.py [--quick] [--rounds N] [--seconds S]
        [--host-label TEXT] [--cluster] [--geoip-data SNAPSHOT]
        [--mode forward_auth|reverse_proxy] [--capture-heads]

Reverse-proxy runs relay to a local `caddy respond` origin. With --capture-heads the console-enabled
configurations store redacted heads, and an "audited" workload (an XSS finding in audit mode
admitted with a session) exercises the capture path; compiled-out and disabled never capture.
"""
import argparse
import json
import math
import os
from pathlib import Path
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from run import ROOT, free_port, metadata, record, ready, stop, request
from tools import WRK_LUA, ATTACK, PeakRss, cpu_seconds, drain_time_wait, wrk
from distributed import headers, session

sys.path.insert(0, str(ROOT / "tools"))
import console_bootstrap_test as bootstrap  # noqa: E402
import console_e2e  # noqa: E402
from console_dashboard import Dashboard, covered, difference, stop_clients  # noqa: E402
import console_peer_impact as peer_impact  # noqa: E402

CONFIGURATIONS = ("compiled_out", "disabled", "idle", "active")
# An XSS finding in audit mode: admitted with a session, recorded as an incident and, with
# capture on, stored with its heads. The policy file below sets only that category to audit.
AUDITED = "/private?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
AUDIT_POLICY = {"inspection": {"xss": "audit"}}
GATE = {"throughput_loss_max": 0.01, "p99_increase_max": 0.10, "baseline_spread_max": 0.01}
DASHBOARDS = 8


def build(prefix, console, cluster, geoip=None):
    args = ["zig", "build", "-j1", "-Doptimize=ReleaseFast", "-p", str(prefix)]
    if not console:
        args.append("-Dconsole=false")
    if cluster:
        args.append("-Dcluster=true")
    if console and geoip:
        args.append(f"-Dgeoip-data={geoip}")
    subprocess.run(args, cwd=ROOT, check=True)
    binary = prefix / "bin/sibuna"
    return {"path": str(binary), "bytes": binary.stat().st_size,
            "sha256": __import__("hashlib").sha256(binary.read_bytes()).hexdigest(),
            "build": " ".join(args[2:])}


class Daemon:
    """One configuration: a daemon (or a three-node cluster) plus optional dashboards."""

    def __init__(self, name, binary, temp, cluster, seed, psk, settings):
        self.name, self.binary, self.temp, self.cluster = name, binary, temp, cluster
        self.seed, self.psk, self.settings = seed, psk, settings
        self.port = free_port()
        self.console_port = free_port() if name in ("idle", "active") else None
        self.procs, self.logs, self.clients = [], [], []
        self.target_proc = None
        self.consoles = ([self.console_port] + [free_port() for _ in range(2 if cluster else 0)]
                         if self.console_port else [])
        self.mesh = peer_impact.Mesh(temp, self.consoles) if cluster and self.consoles else None
        self.helper = self.mesh or console_e2e

    def args(self, index, data, peers):
        args = [self.binary, "--host", "127.0.0.1", "--port", str(data[index]), "--workers", "2",
                "--mode", self.settings["mode"], "--algorithm", "hashcash", "--difficulty", "8",
                "--shield", "--secret-file", str(self.seed), "--rate-limit", "100000000",
                "--idle-timeout", "5", "--trust-forwarded",
                "--policy-file", str(self.settings["policy"]),
                "--data-dir", str(self.temp / f"{self.name}-node{index}"),
                "--storage-poll-ms", "100"]
        if self.settings["mode"] == "reverse_proxy":
            args += ["--upstream-port", str(self.settings["upstream_port"])]
        if self.consoles:
            args += ["--console", f"127.0.0.1:{self.consoles[index]}"]
            # Capture is a console option: only enabled consoles can store heads.
            if self.settings["capture_heads"]:
                args.append("--console-capture-heads")
            if self.mesh:
                args += self.mesh.args(index)
        if self.cluster:
            args += ["--cluster-node", str(index + 1), "--cluster-listen",
                     f"127.0.0.1:{peers[index]}", "--cluster-secret-file", str(self.psk)]
            for j in range(len(data)):
                if j != index:
                    args += ["--cluster-peer", f"{j + 1}@127.0.0.1:{peers[j]}"]
        return args

    def cluster_args(self, index, peers):
        args = ["--data-dir", str(self.temp / f"{self.name}-node{index}"),
                "--storage-poll-ms", "100", "--cluster-node", str(index + 1),
                "--cluster-listen", f"127.0.0.1:{peers[index]}",
                "--cluster-secret-file", str(self.psk)]
        for j in range(len(peers)):
            if j != index:
                args += ["--cluster-peer", f"{j + 1}@127.0.0.1:{peers[j]}"]
        return args

    def launch(self, index, data, peers):
        log = open(self.temp / f"{self.name}-node{index}.log", "w+")
        self.logs.append(log)
        self.procs.append(subprocess.Popen(self.args(index, data, peers),
                                           stdout=log, stderr=log))
        if index == 0:
            self.target_proc = self.procs[-1]

    def start(self):
        count = 3 if self.cluster else 1
        data = [self.port] + [free_port() for _ in range(count - 1)]
        peers = [free_port() for _ in range(count)]
        # A replicated store needs quorum before the administrator can be bootstrapped:
        # peers start first, then init-admin runs with node 1's cluster identity.
        for index in range(1, count):
            self.launch(index, data, peers)
        if self.console_port:
            if self.cluster:
                result = subprocess.run(
                    [self.binary, "init-admin", "admin"] + self.cluster_args(0, peers),
                    capture_output=True, text=True, timeout=120)
                assert result.returncode == 0, result.stderr
                match = re.search(r"Temporary console password .*: ([0-9a-f]{48})",
                                  result.stderr)
                self.credentials = {"username": "admin", "password": match[1]}
            else:
                self.credentials = bootstrap.initialize(
                    self.binary, str(self.temp / f"{self.name}-node0"), "admin")
        self.launch(0, data, peers)
        for proc in self.procs:
            ready(proc, int(proc.args[proc.args.index("--port") + 1]), timeout=120)
        if self.console_port:
            self.dashboards()

    def dashboards(self):
        h = self.helper
        permanent = "console impact private passphrase"
        credentials = (self.mesh.credentials(self.credentials) if self.mesh else
                       bootstrap.change(h, self.console_port, self.credentials, permanent))
        status, reply, body = h.request(self.console_port, "POST", "/console/api/login",
                                        credentials)
        assert status == 200, body
        self.cookie = reply["Set-Cookie"].split(";", 1)[0]
        self.csrf = json.loads(body)["csrf"]
        if self.mesh:
            self.mesh.ready(self.cookie)
        code, _, body = h.request(self.console_port, "GET", "/console/api/geoip",
                                  cookie=self.cookie)
        assert code == 200, ("geoip", code)
        self.geoip = json.loads(body)
        if self.name != "active":
            return
        for _ in range(DASHBOARDS):
            client = Dashboard(h, self.console_port, self.cookie, self.csrf)
            self.clients.append(client)
            client.start()

    def stop_all(self):
        failures = stop_clients(self.clients)
        for proc in self.procs:
            try:
                stop(proc)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                failures.append(error)
        if self.mesh:
            try:
                self.mesh.close()
            except (OSError, RuntimeError) as error:
                failures.append(error)
        for log in self.logs:
            log.close()
        if failures:
            raise RuntimeError("impact fixture cleanup failed") from failures[0]


def sample(daemon, path, hdrs, load, script):
    drain_time_wait()
    wrk(daemon.port, path, hdrs, {**load, "seconds": load["warmup_seconds"]}, script)
    peers_before = daemon.mesh.snapshot(daemon.cookie) if daemon.mesh else []
    tracker = PeakRss(daemon.target_proc.pid)
    cpu_before = cpu_seconds(daemon.target_proc.pid)
    before = [client.snapshot() for client in daemon.clients]
    tracker.start()
    try:
        result = wrk(daemon.port, path, hdrs, load, script)
        after = [client.snapshot() for client in daemon.clients]
    finally:
        tracker.stopping.set()
        tracker.join()
    wall = result["duration_us"] / 1e6
    cpu_used = cpu_seconds(daemon.target_proc.pid) - cpu_before
    peers_after = daemon.mesh.snapshot(daemon.cookie) if daemon.mesh else []
    return {"requests": result["requests"],
            "requests_per_second": result["requests"] / wall if wall > 0 else 0,
            "latency_us": result["latency_us"], "errors": result["errors"],
            "cpu_seconds": cpu_used,
            "peak_rss_kib": tracker.peak,
            "dashboards": difference(before, after),
            "peers": {"before": peers_before, "after": peers_after,
                      "covered": peer_impact.coverage(peers_before, peers_after, wall)
                      if daemon.mesh else None},
            "wall_seconds": wall}


class Reloader(threading.Thread):
    """Policy reloads: a fresh honeypot ban every 250 ms inserts a reputation row, which
    bumps the policy version and rebuilds the engine on the next storage tick."""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port, self.stopping, self.count = port, threading.Event(), 0

    def run(self):
        while not self.stopping.is_set():
            self.count += 1
            ip = f"203.0.{(self.count >> 8) & 255}.{self.count & 255}"
            try:
                request(self.port, "/__sibuna/honeypot", headers(ip))
            except (OSError, RuntimeError):
                pass
            self.stopping.wait(0.25)


def workloads(cookie):
    with_cookie = headers("8.8.8.8", cookie=cookie)
    return {
        "admitted": ("/private", with_cookie, 200),
        "challenged": ("/private", headers("8.8.8.8"), 401),
        "denied": (ATTACK, with_cookie, 403),
        "policy_reload": ("/private", with_cookie, 200),
        "audited": (AUDITED, with_cookie, 200),
    }


def bootstrap_ci(baseline, candidate, resamples=2000, increase=False):
    assert len(baseline) == len(candidate) and baseline
    rng = random.Random(7)
    ratios = []
    for _ in range(resamples):
        indices = [rng.randrange(len(baseline)) for _ in baseline]
        b = statistics.median(baseline[i] for i in indices)
        c = statistics.median(candidate[i] for i in indices)
        ratios.append(c / b - 1 if increase else 1 - c / b)
    ratios.sort()
    return [ratios[int(0.025 * resamples)], ratios[int(0.975 * resamples) - 1]]


def summarize(samples):
    rates = [s["requests_per_second"] for s in samples]
    p99 = [s["latency_us"]["p99"] for s in samples]
    return {"samples": samples, "requests_per_second_median": statistics.median(rates),
            "requests_per_second_min": min(rates), "requests_per_second_max": max(rates),
            "spread": ((max(rates) - min(rates)) / statistics.median(rates)
                       if statistics.median(rates) > 0 else None),
            "valid_measurements": all(math.isfinite(value) and value > 0
                                      for sample in samples for value in (
                                          sample["requests_per_second"],
                                          sample["latency_us"]["p99"], sample["wall_seconds"])),
            "latency_us_p99_median": statistics.median(p99),
            "peak_rss_kib_max": max(s["peak_rss_kib"] for s in samples),
            "errors_total": {k: sum(s["errors"][k] for s in samples)
                             for k in samples[0]["errors"]},
            "dashboard_frames_per_second_min": min(
                (client["frames"] / sample["wall_seconds"]
                 for sample in samples if sample["wall_seconds"] > 0
                 for client in sample["dashboards"]), default=0)}


def verdict(baseline, candidate):
    if (not baseline["valid_measurements"] or not candidate["valid_measurements"] or
            len(baseline["samples"]) != len(candidate["samples"])):
        return {"verdict": "inconclusive", "reason": "missing, invalid or unpaired measurements"}
    loss = 1 - candidate["requests_per_second_median"] / baseline["requests_per_second_median"]
    p99 = candidate["latency_us_p99_median"] / baseline["latency_us_p99_median"] - 1
    ci = bootstrap_ci([s["requests_per_second"] for s in baseline["samples"]],
                      [s["requests_per_second"] for s in candidate["samples"]])
    latency_ci = bootstrap_ci([s["latency_us"]["p99"] for s in baseline["samples"]],
                              [s["latency_us"]["p99"] for s in candidate["samples"]],
                              increase=True)
    result = {"throughput_loss": loss, "p99_increase": p99, "bootstrap_ci_95_loss": ci,
              "bootstrap_ci_95_p99_increase": latency_ci}
    transport_errors = any(
        value for group in (baseline, candidate)
        for key, value in group["errors_total"].items() if key != "status")
    if (transport_errors or baseline["spread"] > GATE["baseline_spread_max"] or
            len(baseline["samples"]) < 5):
        result["verdict"] = "inconclusive"
    elif ci[0] > GATE["throughput_loss_max"] or latency_ci[0] > GATE["p99_increase_max"]:
        result["verdict"] = "fail"
    elif ci[1] <= GATE["throughput_loss_max"] and latency_ci[1] <= GATE["p99_increase_max"]:
        result["verdict"] = "pass"
    else:
        result["verdict"] = "inconclusive"
    return result


def matrix(binaries, temp, load, rounds, cluster, names, seed, psk, script, settings):
    results = {name: {cfg: [] for cfg in CONFIGURATIONS} for name in names}
    clients, geoip = [], []
    for round_index in range(rounds):
        order = CONFIGURATIONS[round_index % 4:] + CONFIGURATIONS[:round_index % 4]
        for position, cfg in enumerate(order):
            # Exactly one measured configuration is alive. An active console's polling,
            # collectors and storage cannot contaminate a compiled-out baseline round.
            directory = temp / f"round-{round_index}-{cfg}"
            directory.mkdir()
            binary = binaries["compiled_out" if cfg == "compiled_out" else "console"]["path"]
            daemon = Daemon(cfg, binary, directory, cluster, seed, psk, settings)
            try:
                daemon.start()
                cookie = session(daemon.port, "8.8.8.8")[0]
                offset = round_index % len(names)
                for workload in names[offset:] + names[:offset]:
                    path, hdrs, expected = workloads(cookie)[workload]
                    status = request(daemon.port, path, hdrs)[0]
                    assert status == expected, (cfg, workload, status, expected)
                    reloader = Reloader(daemon.port) if workload == "policy_reload" else None
                    if reloader:
                        reloader.start()
                    try:
                        entry = sample(daemon, path, hdrs, load, script)
                    finally:
                        if reloader:
                            reloader.stopping.set()
                            reloader.join()
                    if reloader:
                        entry["policy_reloads_triggered"] = reloader.count
                    entry.update(round=round_index + 1, position=position)
                    results[workload][cfg].append(entry)
                    print(f"  round {round_index + 1} {workload:14s} {cfg:13s} "
                          f"{entry['requests_per_second']:9.0f} req/s "
                          f"p99 {entry['latency_us']['p99'] / 1000:6.2f} ms", flush=True)
                clients.extend(client.snapshot() for client in daemon.clients)
                if daemon.clients:
                    geoip.append(daemon.geoip)
            finally:
                daemon.stop_all()
    samples = [sample for workload in results.values() for sample in workload["active"]]
    peer_samples = [sample for workload in results.values() for cfg in ("idle", "active")
                    for sample in workload[cfg]]
    return finish(results, names), {
        "subscribers": DASHBOARDS, "delivered": covered(samples, DASHBOARDS),
        "peers_covered": all(sample["peers"]["covered"] for sample in peer_samples)
                         if cluster else None,
        "geoip": geoip, "geoip_available": bool(geoip) and all(g["ranges"] > 0 for g in geoip),
        "frames_total": sum(client["frames"] for client in clients),
        "reconnects": sum(client["reconnects"] for client in clients),
        "http_errors": sum(client["http_errors"] for client in clients),
        "stream_errors": sum(client["stream_errors"] for client in clients),
        "frames_per_second_per_subscriber_min": min((
            client["frames"] / sample["wall_seconds"]
            for sample in samples if sample["wall_seconds"] > 0
            for client in sample["dashboards"]), default=0)}


def finish(results, names):
    out = {}
    worst = "pass"
    order = {"pass": 0, "inconclusive": 1, "fail": 2}
    for workload in names:
        configurations = {cfg: summarize(samples) for cfg, samples in results[workload].items()}
        baseline = configurations["compiled_out"]
        for cfg in CONFIGURATIONS[1:]:
            configurations[cfg]["versus_compiled_out"] = verdict(baseline, configurations[cfg])
            worst = max(worst, configurations[cfg]["versus_compiled_out"]["verdict"],
                        key=order.get)
        out[workload] = {"configurations": configurations}
    return {"workloads": out, "verdict": worst}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="two workloads, two short rounds")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--seconds", type=int, default=15)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--connections", type=int, default=32)
    parser.add_argument("--host-label", default="undeclared host",
                        help="Declare the measuring host and its quiet state for the record")
    parser.add_argument("--cluster", action="store_true", help="three PSK nodes with TLS console peers")
    parser.add_argument("--geoip-data", type=Path,
                        help="Validated production country snapshot; required for acceptance")
    parser.add_argument("--mode", choices=("forward_auth", "reverse_proxy"),
                        default="forward_auth", help="data-plane mode under load")
    parser.add_argument("--capture-heads", action="store_true",
                        help="store redacted heads on enabled consoles and add the audited workload")
    args = parser.parse_args()
    if not args.quick and args.geoip_data is None:
        parser.error("a full impact run needs --geoip-data; use --quick only for smoke checks")
    if min(args.rounds, args.seconds, args.threads, args.connections) <= 0 or args.warmup < 0:
        parser.error("rounds, seconds, threads and connections must be positive")
    if args.geoip_data:
        args.geoip_data = args.geoip_data.resolve(strict=True)
    if args.quick:
        args.rounds, args.seconds, args.warmup = 2, 2, 1
    names = ("admitted", "denied") if args.quick else (
        "admitted", "challenged", "denied", "policy_reload")
    if args.capture_heads:
        names += ("audited",)
    load = {"threads": args.threads, "connections": args.connections, "seconds": args.seconds,
            "warmup_seconds": args.warmup}
    with tempfile.TemporaryDirectory(prefix="sibuna-console-impact-") as directory:
        temp = Path(directory)
        binaries = {"compiled_out": build(temp / "out-a", False, args.cluster),
                    "console": build(temp / "out-b", True, args.cluster, args.geoip_data)}
        script = temp / "wrk.lua"
        script.write_text(WRK_LUA)
        seed = temp / "seed"
        seed.write_bytes(os.urandom(32))
        psk = temp / "psk"
        psk.write_bytes(os.urandom(32).hex().encode())
        psk.chmod(0o600)
        policy = temp / "policy.json"
        policy.write_text(json.dumps(AUDIT_POLICY))
        origin_port = free_port() if args.mode == "reverse_proxy" else None
        application = None
        if origin_port:
            # The same static origin as the whole-product harness, so relay cost is bounded
            # by a compiled server rather than by a Python fixture.
            if shutil.which("caddy") is None:
                parser.error("reverse-proxy runs need caddy on PATH for the origin stub")
            application = subprocess.Popen(
                ["caddy", "respond", "--listen", f"127.0.0.1:{origin_port}", "--body", "origin"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
        settings = {"mode": args.mode, "capture_heads": args.capture_heads, "policy": policy,
                    "upstream_port": origin_port}
        started = time.monotonic()
        try:
            results, dashboards = matrix(binaries, temp, load, args.rounds, args.cluster,
                                         names, seed, psk, script, settings)
        finally:
            if application:
                application.terminate()
                application.wait(timeout=10)
        provenance = metadata(binaries["console"]["path"])
    # Eight dashboards that stopped receiving frames would make "active" an idle daemon.
    if (not dashboards["delivered"] or not dashboards["geoip_available"] or args.quick or
            args.host_label == "undeclared host" or
            (args.cluster and not dashboards["peers_covered"])):
        results["verdict"] = "inconclusive"
    data = {"meta": {**provenance, "binaries": binaries, "host_label": args.host_label,
                     "quick": args.quick, "cluster": args.cluster,
                     "mode": args.mode, "capture_heads": args.capture_heads,
                     "audit_policy": AUDIT_POLICY,
                     "origin": ("caddy respond (static 200)" if args.mode == "reverse_proxy"
                                else None),
                     "management_peers": 6 if args.cluster else 0,
                     "resource_target_node": 1,
                     "peer_coverage": "current before and after each sample; advancing watermarks",
                     "geoip_snapshot": ({"bytes": args.geoip_data.stat().st_size,
                                         "sha256": __import__("hashlib").sha256(
                                             args.geoip_data.read_bytes()).hexdigest()}
                                        if args.geoip_data else None),
                     "elapsed_seconds": time.monotonic() - started},
            "load": {**load, "rounds": args.rounds,
                     "order": "rotating configurations and workloads; one configuration alive"},
            "wrk": subprocess.run(["wrk", "--version"], capture_output=True, text=True,
                                  check=False).stdout.split("\n")[0],
            "gate": GATE, "dashboards": dashboards, **results,
            "dashboard_workload": {"endpoint": "/console/ws", "stats_hz": 1, "rankings_interval_seconds": 10,
                                   "timeline_interval_seconds": 10, "timeline_limit": 10,
                                   "details": "rankings and open timeline for a single issuer",
                                   "period": "24 hours plus yesterday, all selected nodes",
                                   "period_page_rows": 96,
                                   "period_refresh_seconds_after_completion": 60,
                                   "geometry": "loaded once before warmup",
                                   "client": "network emulation; rendering measured separately"},
            "limitations": [
                "Cluster idle/active configurations run three consoles and six authenticated "
                "TLS peer directions. Boundary checks require fresh observations, stable "
                "boots and advancing watermarks; they do not measure every peer frame.",
                "CPU and peak RSS describe the traffic-serving node 1. Cluster TLS ingress "
                "fixtures share the load-generator host; their memory is separate.",
                "Loopback wrk shares the host with the daemons; inconclusive results are "
                "reported, never rounded to a pass.",
                "Peak RSS is sampled every 100 ms from ps; short spikes can be missed.",
                "The cluster case loads node 1 only; replication cost lands on all nodes.",
                "Head capture is a console option: compiled-out and disabled configurations "
                "never capture, so the audited workload compares capture against no console."]
            + ([] if dashboards["delivered"] else [
                "At least one subscriber lacked required frames or successful rankings/timeline "
                "queries, or a recently completed retained-period scan during a sample; "
                "the active workload is inconclusive."])}
    record(data, "console-impact-cluster-latest" if args.cluster else "console-impact-latest")
    print(f"console-impact verdict: {results['verdict']}", flush=True)
    return 0 if results["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
