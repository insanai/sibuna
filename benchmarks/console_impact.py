#!/usr/bin/env python3
"""Console isolation gate (SID 0007): data-plane throughput and p99 with the console compiled
out, compiled in but disabled, idle, and serving eight live dashboards, under admitted,
challenged, denied and policy-reload workloads. Rounds interleave configurations in rotated
order; a noisy baseline yields "inconclusive", never a pass.

    python3 benchmarks/console_impact.py [--quick] [--rounds N] [--seconds S]
        [--host-label TEXT] [--cluster]
"""
import argparse
import json
import os
from pathlib import Path
import random
import re
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
from console_ws_test import Stream  # noqa: E402

CONFIGURATIONS = ("compiled_out", "disabled", "idle", "active")
GATE = {"throughput_loss_max": 0.01, "p99_increase_max": 0.10, "baseline_spread_max": 0.01}
DASHBOARDS = 8


def build(prefix, console, cluster):
    args = ["zig", "build", "-Doptimize=ReleaseFast", "-p", str(prefix)]
    if not console:
        args.append("-Dconsole=false")
    if cluster:
        args.append("-Dcluster=true")
    subprocess.run(args, cwd=ROOT, check=True)
    binary = prefix / "bin/sibuna"
    return {"path": str(binary), "bytes": binary.stat().st_size,
            "sha256": __import__("hashlib").sha256(binary.read_bytes()).hexdigest(),
            "build": " ".join(args[2:])}


class Daemon:
    """One configuration: a daemon (or a three-node cluster) plus optional dashboards."""

    def __init__(self, name, binary, temp, cluster, seed, psk):
        self.name, self.binary, self.temp, self.cluster = name, binary, temp, cluster
        self.seed, self.psk = seed, psk
        self.port = free_port()
        self.console_port = free_port() if name in ("idle", "active") else None
        self.procs, self.logs, self.streams, self.readers = [], [], [], []
        self.frames = 0
        self.stopping = threading.Event()

    def args(self, index, data, peers):
        args = [self.binary, "--host", "127.0.0.1", "--port", str(data[index]), "--workers", "2",
                "--mode", "forward_auth", "--algorithm", "hashcash", "--difficulty", "8",
                "--shield", "--secret-file", str(self.seed), "--rate-limit", "100000000",
                "--idle-timeout", "5", "--trust-forwarded",
                "--data-dir", str(self.temp / f"{self.name}-node{index}"),
                "--storage-poll-ms", "100"]
        if self.console_port and index == 0:
            args += ["--console", f"127.0.0.1:{self.console_port}"]
        if self.cluster:
            args += ["--cluster-node", str(index + 1), "--cluster-listen",
                     f"127.0.0.1:{peers[index]}", "--cluster-secret-file", str(self.psk)]
            for j in range(len(data)):
                if j != index:
                    args += ["--cluster-peer", f"{j + 1}@127.0.0.1:{peers[j]}"]
        return args

    def start(self):
        count = 3 if self.cluster else 1
        data = [self.port] + [free_port() for _ in range(count - 1)]
        peers = [free_port() for _ in range(count)]
        if self.console_port:
            self.credentials = bootstrap.initialize(
                self.binary, str(self.temp / f"{self.name}-node0"), "admin")
        for index in range(count):
            log = open(self.temp / f"{self.name}-node{index}.log", "w+")
            self.logs.append(log)
            self.procs.append(subprocess.Popen(self.args(index, data, peers),
                                               stdout=log, stderr=log))
        for proc, port in zip(self.procs, data):
            ready(proc, port, timeout=120)
        if self.console_port:
            self.dashboards()

    def dashboards(self):
        h = console_e2e
        permanent = "console impact private passphrase"
        credentials = bootstrap.change(h, self.console_port, self.credentials, permanent)
        status, reply, body = h.request(self.console_port, "POST", "/console/api/login",
                                        credentials)
        assert status == 200, body
        self.cookie = reply["Set-Cookie"].split(";", 1)[0]
        if self.name != "active":
            return
        for _ in range(DASHBOARDS):
            stream = Stream(self.console_port, self.cookie)
            stream.send(1, b'{"op":"subscribe","topics":["stats"]}')
            self.streams.append(stream)
            reader = threading.Thread(target=self.read, args=(stream,), daemon=True)
            reader.start()
            self.readers.append(reader)

    def read(self, stream):
        stream.sock.settimeout(1)
        while not self.stopping.is_set():
            try:
                opcode, payload = stream.receive()
            except (OSError, ValueError):
                if self.stopping.is_set():
                    return
                continue
            if opcode == 9:
                stream.send(10, payload)
            elif opcode == 1:
                self.frames += 1
            elif opcode == 8:
                return

    def stop_all(self):
        self.stopping.set()
        for stream in self.streams:
            try:
                stream.close()
            except OSError:
                pass
        for reader in self.readers:
            reader.join(timeout=5)
        for proc in self.procs:
            stop(proc)
        for log in self.logs:
            log.close()


def sample(daemon, path, hdrs, load, script):
    drain_time_wait()
    wrk(daemon.port, path, hdrs, {**load, "seconds": load["warmup_seconds"]}, script)
    tracker = PeakRss(daemon.procs[0].pid)
    cpu_before = cpu_seconds(daemon.procs[0].pid)
    frames_before = daemon.frames
    tracker.start()
    result = wrk(daemon.port, path, hdrs, load, script)
    tracker.stopping.set()
    tracker.join()
    wall = result["duration_us"] / 1e6
    return {"requests": result["requests"], "requests_per_second": result["requests"] / wall,
            "latency_us": result["latency_us"], "errors": result["errors"],
            "cpu_seconds": cpu_seconds(daemon.procs[0].pid) - cpu_before,
            "peak_rss_kib": tracker.peak,
            "dashboard_frames": daemon.frames - frames_before, "wall_seconds": wall}


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
    with_cookie = headers(cookie=cookie)
    return {
        "admitted": ("/private", with_cookie, 200),
        "challenged": ("/private", headers(), 401),
        "denied": (ATTACK, with_cookie, 403),
        "policy_reload": ("/private", with_cookie, 200),
    }


def bootstrap_ci(baseline, candidate, resamples=1000):
    rng = random.Random(7)
    ratios = []
    for _ in range(resamples):
        b = statistics.median(rng.choice(baseline) for _ in baseline)
        c = statistics.median(rng.choice(candidate) for _ in candidate)
        ratios.append(1 - c / b)
    ratios.sort()
    return [ratios[int(0.025 * resamples)], ratios[int(0.975 * resamples) - 1]]


def summarize(samples):
    rates = [s["requests_per_second"] for s in samples]
    p99 = [s["latency_us"]["p99"] for s in samples]
    return {"samples": samples, "requests_per_second_median": statistics.median(rates),
            "requests_per_second_min": min(rates), "requests_per_second_max": max(rates),
            "spread": (max(rates) - min(rates)) / statistics.median(rates),
            "latency_us_p99_median": statistics.median(p99),
            "peak_rss_kib_max": max(s["peak_rss_kib"] for s in samples),
            "errors_total": {k: sum(s["errors"][k] for s in samples) for k in samples[0]["errors"]},
            "dashboard_frames_per_second_min": min(
                s["dashboard_frames"] / s["wall_seconds"] for s in samples)}


def verdict(baseline, candidate):
    loss = 1 - candidate["requests_per_second_median"] / baseline["requests_per_second_median"]
    p99 = candidate["latency_us_p99_median"] / baseline["latency_us_p99_median"] - 1
    ci = bootstrap_ci([s["requests_per_second"] for s in baseline["samples"]],
                      [s["requests_per_second"] for s in candidate["samples"]])
    result = {"throughput_loss": loss, "p99_increase": p99, "bootstrap_ci_95_loss": ci}
    if baseline["spread"] > GATE["baseline_spread_max"] or (
            ci[0] <= GATE["throughput_loss_max"] <= ci[1]):
        result["verdict"] = "inconclusive"
    elif loss > GATE["throughput_loss_max"] or p99 > GATE["p99_increase_max"]:
        result["verdict"] = "fail"
    else:
        result["verdict"] = "pass"
    return result


def matrix(binaries, temp, load, rounds, cluster, names, seed, psk, script):
    daemons = {name: Daemon(name, binaries["console" if name != "compiled_out" else
                                           "compiled_out"]["path"], temp, cluster, seed, psk)
               for name in CONFIGURATIONS}
    reloaders = {}
    try:
        for daemon in daemons.values():
            daemon.start()
        cookies = {name: session(daemon.port) for name, daemon in daemons.items()}
        results = {name: {cfg: [] for cfg in CONFIGURATIONS} for name in names}
        for round_index in range(rounds):
            for workload in names:
                order = CONFIGURATIONS[round_index % 4:] + CONFIGURATIONS[:round_index % 4]
                for position, cfg in enumerate(order):
                    daemon = daemons[cfg]
                    path, hdrs, expected = workloads(cookies[cfg])[workload]
                    status = request(daemon.port, path, hdrs)[0]
                    assert status == expected, (cfg, workload, status, expected)
                    if workload == "policy_reload":
                        reloaders[cfg] = Reloader(daemon.port)
                        reloaders[cfg].start()
                    try:
                        entry = sample(daemon, path, hdrs, load, script)
                    finally:
                        if workload == "policy_reload":
                            reloaders[cfg].stopping.set()
                            reloaders[cfg].join()
                            entry["policy_reloads_triggered"] = reloaders[cfg].count
                    entry.update(round=round_index + 1, position=position)
                    results[workload][cfg].append(entry)
                    print(f"  round {round_index + 1} {workload:14s} {cfg:13s} "
                          f"{entry['requests_per_second']:9.0f} req/s "
                          f"p99 {entry['latency_us']['p99'] / 1000:6.2f} ms", flush=True)
        frames = sum(s["dashboard_frames"] for w in results.values() for s in w["active"])
        return finish(results, names), {"subscribers": DASHBOARDS, "frames_total": frames,
                                        "frames_per_second_per_subscriber_min": min(
                                            summarize(results[w]["active"])
                                            ["dashboard_frames_per_second_min"] / DASHBOARDS
                                            for w in names)}
    finally:
        for daemon in daemons.values():
            daemon.stop_all()


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
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--connections", type=int, default=32)
    parser.add_argument("--host-label", default="undeclared host",
                        help="Declare the measuring host and its quiet state for the record")
    parser.add_argument("--cluster", action="store_true", help="three PSK nodes, console on 1")
    args = parser.parse_args()
    if args.quick:
        args.rounds, args.seconds, args.warmup = 2, 2, 1
    names = ("admitted", "denied") if args.quick else (
        "admitted", "challenged", "denied", "policy_reload")
    load = {"threads": args.threads, "connections": args.connections, "seconds": args.seconds,
            "warmup_seconds": args.warmup}
    with tempfile.TemporaryDirectory(prefix="sibuna-console-impact-") as directory:
        temp = Path(directory)
        binaries = {"compiled_out": build(temp / "out-a", False, args.cluster),
                    "console": build(temp / "out-b", True, args.cluster)}
        script = temp / "wrk.lua"
        script.write_text(WRK_LUA)
        seed = temp / "seed"
        seed.write_bytes(os.urandom(32))
        psk = temp / "psk"
        psk.write_bytes(os.urandom(32).hex().encode())
        psk.chmod(0o600)
        started = time.monotonic()
        results, dashboards = matrix(binaries, temp, load, args.rounds, args.cluster, names,
                                     seed, psk, script)
    data = {"meta": {**metadata(), "binaries": binaries, "host_label": args.host_label,
                     "quick": args.quick, "cluster": args.cluster,
                     "elapsed_seconds": time.monotonic() - started},
            "load": {**load, "rounds": args.rounds, "order": "rotating"},
            "wrk": subprocess.run(["wrk", "--version"], capture_output=True, text=True,
                                  check=False).stdout.split("\n")[0],
            "gate": GATE, "dashboards": dashboards, **results,
            "limitations": [
                "Loopback wrk shares the host with the daemons; inconclusive results are "
                "reported, never rounded to a pass.",
                "Peak RSS is sampled every 100 ms from ps; short spikes can be missed.",
                "The cluster case loads node 1 only; replication cost lands on all nodes."]}
    record(data, "console-impact-latest")
    print(f"console-impact verdict: {results['verdict']}", flush=True)
    return 0 if results["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
