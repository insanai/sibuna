#!/usr/bin/env python3
"""Three real Sibuna nodes under wrk: throughput, latency, CPU, memory, and security parity.

Compares one node without storage, one node with embedded storage, and a
three-member replicated cluster (loopback pre-shared key, then mutual TLS).
Every node is a complete daemon process; wrk drives each node alone and all
nodes at once. Security checks are the same as the distributed harness:
cross-node sessions, WAF denial with a valid session, issuer-bound solution
replay, honeypot ban propagation, and service after the elected leader stops.
"""
import argparse
import json
import pathlib
import re
import statistics
import subprocess
import tempfile
import time

from distributed import UA, headers, propagate_ban, session, tls_material
from run import ROOT, free_port, metadata, ready, record, request, stop
from tools import WRK_LUA, PeakRss, cpu_seconds, drain_time_wait, rss_kib


def wrk_start(port, path, hdrs, load, script):
    args = ["wrk", f"-t{load['threads']}", f"-c{load['connections']}",
            f"-d{load['seconds']}s", "-s", str(script)]
    for key, value in hdrs.items():
        args += ["-H", f"{key}: {value}"]
    return subprocess.Popen(args + [f"http://127.0.0.1:{port}{path}"], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def wrk_finish(proc):
    out, _ = proc.communicate(timeout=120)
    match = re.search(r"WRKJSON (\{.*\})", out)
    if proc.returncode != 0 or not match:
        return {"error": out[-300:]}
    return json.loads(match.group(1))


def load_round(procs, targets, path, hdrs, load, script):
    """Runs wrk against every target port at once and accounts each node."""
    drain_time_wait()
    trackers = [PeakRss(p.pid) for p in procs]
    before = [cpu_seconds(p.pid) for p in procs]
    for t in trackers:
        t.start()
    started = [wrk_start(port, path, hdrs, load, script) for port in targets]
    results = [wrk_finish(w) for w in started]
    for t in trackers:
        t.stopping.set()
        t.join()
    cpu = [cpu_seconds(p.pid) - b for p, b in zip(procs, before)]
    if any("error" in r for r in results):
        return {"failed": True, "errors": [r.get("error") for r in results]}
    requests = sum(r["requests"] for r in results)
    wall = max(r["duration_us"] for r in results) / 1e6
    return {
        "failed": False,
        "requests": requests,
        "requests_per_second": requests / wall,
        "latency_us_p50_max_over_targets": max(r["latency_us"]["p50"] for r in results),
        "latency_us_p99_max_over_targets": max(r["latency_us"]["p99"] for r in results),
        "non_2xx_3xx": sum(r["errors"]["status"] for r in results),
        "cpu_seconds_per_node": cpu,
        "cpu_us_per_request": sum(cpu) * 1e6 / max(requests, 1),
        "cores_busy_total": sum(cpu) / wall,
        "peak_rss_kib_per_node": [t.peak for t in trackers],
    }


def summarize(rounds):
    good = [r for r in rounds if not r["failed"]]
    if not good:
        return {"failed": True, "rounds": rounds}
    rates = [r["requests_per_second"] for r in good]
    return {
        "failed": False,
        "requests_per_second_median": statistics.median(rates),
        "requests_per_second_min": min(rates), "requests_per_second_max": max(rates),
        "latency_us_p50_median": statistics.median(r["latency_us_p50_max_over_targets"] for r in good),
        "latency_us_p99_median": statistics.median(r["latency_us_p99_max_over_targets"] for r in good),
        "cpu_us_per_request_median": statistics.median(r["cpu_us_per_request"] for r in good),
        "cores_busy_total_median": statistics.median(r["cores_busy_total"] for r in good),
        "peak_rss_kib_per_node_max": [max(r["peak_rss_kib_per_node"][i] for r in good)
                                      for i in range(len(good[0]["peak_rss_kib_per_node"]))],
        "non_2xx_3xx_total": sum(r["non_2xx_3xx"] for r in good),
        "rounds": rounds,
    }


def idle_cost(procs, seconds):
    """CPU a quiet node spends on consensus and storage polling."""
    before = [cpu_seconds(p.pid) for p in procs]
    time.sleep(seconds)
    after = [cpu_seconds(p.pid) for p in procs]
    return {"seconds": seconds,
            "cpu_cores_per_node": [(a - b) / seconds for a, b in zip(after, before)],
            "rss_kib_per_node": [rss_kib(p.pid) for p in procs]}


def node_args(binary, i, ports, peers, temp, seed, psk, workers, storage, clustered, tls):
    args = [str(binary), "--host", "127.0.0.1", "--port", str(ports[i]), "--workers",
            str(workers), "--mode", "forward_auth", "--algorithm", "hashcash",
            "--difficulty", "8", "--shield", "--secret-file", str(seed),
            "--rate-limit", "100000000", "--idle-timeout", "5"]
    if storage or clustered:
        args += ["--data-dir", str(temp / f"node{i}"), "--storage-poll-ms", "100"]
    if clustered:
        args += ["--cluster-node", str(i + 1), "--cluster-listen", f"127.0.0.1:{peers[i]}",
                 "--cluster-secret-file", str(psk)]
        if tls:
            args += ["--cluster-tls-cert", str(temp / f"node{i}.crt"),
                     "--cluster-tls-key", str(temp / f"node{i}.key"),
                     "--cluster-tls-ca", str(temp / "ca.crt")]
        for j in range(len(ports)):
            if i != j:
                args += ["--cluster-peer", f"{j + 1}@127.0.0.1:{peers[j]}"]
    return args


def security_checks(ports, cookie, solution, clustered):
    checks = {}
    checks["cross_node_session"] = all(
        request(p, "/private", headers(cookie=cookie))[0] == 200 for p in ports)
    checks["waf_denial_with_session"] = all(
        request(p, "/search?q=%27%20OR%201%3D1--", headers(cookie=cookie))[0] == 403
        for p in ports)
    if len(ports) > 1:
        replay = request(ports[1], "/__sibuna/verify", headers(), "POST", solution)[0]
        checks["cross_node_solution_replay_status"] = replay
        checks["solution_replay_rejected_on_other_node"] = replay == 400
    if clustered:
        checks["ban_propagation_ms"] = propagate_ban(ports, "198.51.100.90")
    return checks


def run_case(case, binary, load, repetitions, workers, script, idle_seconds):
    nodes, storage, clustered, tls = case["nodes"], case["storage"], case["clustered"], case["tls"]
    with tempfile.TemporaryDirectory(prefix="sibuna-cluster-") as name:
        temp = pathlib.Path(name)
        seed, psk = temp / "seed", temp / "psk"
        seed.write_text("42" * 32)
        psk.write_text("sibuna-local-benchmark-psk-32-bytes")
        if tls:
            tls_material(temp)
        ports, peers = [free_port() for _ in range(nodes)], [free_port() for _ in range(nodes)]
        procs, logs = [], []
        try:
            for i in range(nodes):
                log = (temp / f"node{i}.log").open("w+")
                logs.append(log)
                args = node_args(binary, i, ports, peers, temp, seed, psk, workers, storage,
                                 clustered, tls)
                procs.append(subprocess.Popen(args, cwd=ROOT, stdout=log, stderr=log))
            for proc, port in zip(procs, ports):
                ready(proc, port, timeout=90)
            time.sleep(1)
            result = {**case, "workers_per_node": workers,
                      "idle": idle_cost(procs, idle_seconds)}
            cookie, solution = session(ports[0])
            result["checks"] = security_checks(ports, cookie, solution, clustered)
            hdr = headers(cookie=cookie)
            workloads = [("admitted", "/private", hdr), ("challenged", "/private", headers()),
                         ("attack", "/search?q=%27%20OR%201%3D1--", hdr)]
            result["per_node"] = {}
            for label, path, h in workloads:
                rounds = [load_round(procs, [ports[0]], path, h, load, script)
                          for _ in range(repetitions)]
                result["per_node"][label] = summarize(rounds)
                s = result["per_node"][label]
                print(f"  {case['case']:22s} node 1  {label:10s} "
                      f"{s.get('requests_per_second_median', 0):9.0f} req/s "
                      f"p99 {s.get('latency_us_p99_median', 0) / 1000:6.2f} ms "
                      f"cpu {s.get('cpu_us_per_request_median', 0):6.1f} us/req", flush=True)
            if nodes > 1:
                result["all_nodes"] = {}
                for label, path, h in workloads:
                    rounds = [load_round(procs, ports, path, h, load, script)
                              for _ in range(repetitions)]
                    result["all_nodes"][label] = summarize(rounds)
                    s = result["all_nodes"][label]
                    print(f"  {case['case']:22s} all {nodes}   {label:10s} "
                          f"{s.get('requests_per_second_median', 0):9.0f} req/s "
                          f"p99 {s.get('latency_us_p99_median', 0) / 1000:6.2f} ms "
                          f"cpu {s.get('cpu_us_per_request_median', 0):6.1f} us/req "
                          f"cores {s.get('cores_busy_total_median', 0):.2f}", flush=True)
            if clustered:
                leaders = []
                for i, log in enumerate(logs):
                    log.flush()
                    log.seek(0)
                    if "became leader; writes are ready" in log.read():
                        leaders.append(i)
                leader = leaders[-1] if leaders else 0
                result["failover"] = {"stopped_leader_node": leader + 1,
                                      "leader_found_in_logs": bool(leaders)}
                stop(procs[leader])
                survivors = [i for i in range(nodes) if i != leader]
                s_procs = [procs[i] for i in survivors]
                s_ports = [ports[i] for i in survivors]
                rounds = [load_round(s_procs, s_ports, "/private", hdr, load, script)
                          for _ in range(repetitions)]
                result["failover"]["admitted_all_survivors"] = summarize(rounds)
                result["failover"]["post_failover_ban_propagation_ms"] = propagate_ban(
                    s_ports, "198.51.100.91")
                s = result["failover"]["admitted_all_survivors"]
                print(f"  {case['case']:22s} leader {leader + 1} stopped: survivors "
                      f"{s.get('requests_per_second_median', 0):9.0f} req/s, ban propagation "
                      f"{result['failover']['post_failover_ban_propagation_ms']:.0f} ms",
                      flush=True)
            chain_ok = True
            for log in logs:
                log.flush()
                log.seek(0)
                text = log.read()
                if "ChainMismatch" in text or "chain mismatch" in text:
                    chain_ok = False
            result["checks"]["storage_chain_log_clean"] = chain_ok
            return result
        except Exception as error:
            captured = []
            for i, log in enumerate(logs):
                log.flush()
                log.seek(0)
                captured.append(f"node {i + 1} log:\n{log.read()[-6000:]}")
            raise RuntimeError(f"{error}\n" + "\n".join(captured)) from error
        finally:
            for proc in procs:
                stop(proc)
            for log in logs:
                log.close()


CASES = [
    {"case": "single, no storage", "nodes": 1, "storage": False, "clustered": False, "tls": False},
    {"case": "single, embedded storage", "nodes": 1, "storage": True, "clustered": False,
     "tls": False},
    {"case": "cluster of 3, PSK", "nodes": 3, "storage": True, "clustered": True, "tls": False},
    {"case": "cluster of 3, mutual TLS", "nodes": 3, "storage": True, "clustered": True,
     "tls": True},
]

LIMITATIONS = [
    "One host, loopback, forward-auth Shield; all nodes, wrk, and the harness share eight cores.",
    "Workers per node are fixed at two so three nodes and the load generator fit on the host; "
    "single-node cases use the same setting for parity, so their absolute throughput is below "
    "the four-worker figures in tools-comparison-latest.json.",
    "Per-node rows drive node 1 only; all-node rows run one wrk process per node at once and "
    "sum requests, with CPU summed over nodes and latency the worst of the three.",
    "Idle CPU is the ps user+system time over a quiet interval and includes storage polling "
    "at --storage-poll-ms 100 and consensus heartbeats.",
    "Sessions are shared by seed; challenge verification is issuer-bound; rate limits and "
    "spent sets stay local to each node.",
    "Replication and TLS costs here are loopback costs; WAN latency changes propagation times.",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=4)
    parser.add_argument("--repetitions", type=int, default=2)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--connections", type=int, default=32)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--idle-seconds", type=int, default=10)
    args = parser.parse_args()
    subprocess.run(["zig", "build", "-Dcluster=true", "-Doptimize=ReleaseFast"],
                   cwd=ROOT, check=True)
    binary = ROOT / "zig-out/bin/sibuna"
    load = {"threads": args.threads, "connections": args.connections, "seconds": args.seconds}
    with tempfile.TemporaryDirectory(prefix="sibuna-cluster-lua-") as name:
        script = pathlib.Path(name) / "done.lua"
        script.write_text(WRK_LUA)
        data = {"meta": metadata(), "load": {**load, "repetitions": args.repetitions},
                "wrk": subprocess.run(["wrk", "--version"], text=True, capture_output=True,
                                      check=False).stdout.splitlines()[0],
                "binary_bytes": binary.stat().st_size, "cases": [],
                "limitations": LIMITATIONS}
        for case in CASES:
            print(f"Measuring {case['case']}", flush=True)
            try:
                data["cases"].append(run_case(case, binary, load, args.repetitions,
                                              args.workers, script, args.idle_seconds))
                data["cases"][-1]["status"] = "passed"
            except Exception as error:
                print(str(error)[-3000:], flush=True)
                data["cases"].append({**case, "status": "failed", "error": str(error)[:2000]})
    record(data, "cluster-latest")
    if any(c["status"] == "failed" for c in data["cases"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
