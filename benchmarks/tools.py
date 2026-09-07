#!/usr/bin/env python3
"""Whole-product comparison under an external load generator.

Starts Sibuna (Gate and Shield) and Anubis as complete processes, drives each
with wrk over loopback, and records throughput, latency percentiles, CPU time
and resident memory of the product process. Third-party binaries stay outside
this repository; SafeLine (Docker-only) and Cloudflare (hosted) cannot run on
a developer host and are recorded as not measured with the published facts
that a reader can check.
"""
import argparse
import json
import os
import pathlib
import re
import shutil
import statistics
import subprocess
import tempfile
import threading
import time
from compare import API, HEADERS, cookies, request, solution
from run import ROOT, free_port, metadata, record, stop

WRK_LUA = r'''
done = function(summary, latency, requests)
  io.write(string.format('WRKJSON {"requests":%d,"duration_us":%d,"bytes":%d,'
    .. '"errors":{"connect":%d,"read":%d,"write":%d,"status":%d,"timeout":%d},'
    .. '"latency_us":{"p50":%d,"p90":%d,"p99":%d,"max":%d,"mean":%.1f}}\n',
    summary.requests, summary.duration, summary.bytes, summary.errors.connect,
    summary.errors.read, summary.errors.write, summary.errors.status, summary.errors.timeout,
    latency:percentile(50), latency:percentile(90), latency:percentile(99),
    latency.max, latency.mean))
end
'''

ATTACK = "/search?q=%27%20OR%201%3D1--"
ORIGIN_BODY = "<!doctype html><title>origin</title><p>ok"


def cpu_seconds(pid):
    """Accumulated user+system CPU time of one process from ps (h:mm:ss.cc or m:ss.cc)."""
    text = subprocess.check_output(["ps", "-o", "time=", "-p", str(pid)], text=True).strip()
    parts = [float(p) for p in text.split(":")]
    total = 0.0
    for part in parts:
        total = total * 60 + part
    return total


def rss_kib(pid):
    return int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True))


class PeakRss(threading.Thread):
    def __init__(self, pid):
        super().__init__(daemon=True)
        self.pid, self.peak, self.stopping = pid, 0, threading.Event()

    def run(self):
        while not self.stopping.is_set():
            try:
                self.peak = max(self.peak, rss_kib(self.pid))
            except (subprocess.CalledProcessError, ValueError):
                return
            self.stopping.wait(0.1)


def wrk(port, path, headers, load, script):
    args = ["wrk", f"-t{load['threads']}", f"-c{load['connections']}",
            f"-d{load['seconds']}s", "-s", str(script)]
    for key, value in headers.items():
        args += ["-H", f"{key}: {value}"]
    out = subprocess.check_output(args + [f"http://127.0.0.1:{port}{path}"], text=True,
                                  stderr=subprocess.STDOUT)
    match = re.search(r"WRKJSON (\{.*\})", out)
    if not match:
        raise RuntimeError(out)
    return json.loads(match.group(1))


def measure(port, pid, origin_pid, path, headers, load, script, repetitions):
    samples, failures = [], []
    for _ in range(repetitions):
        drain_time_wait()
        tracker = PeakRss(pid)
        cpu_before, origin_before = cpu_seconds(pid), cpu_seconds(origin_pid) if origin_pid else 0
        tracker.start()
        try:
            result = wrk(port, path, headers, load, script)
        except (subprocess.CalledProcessError, RuntimeError) as exc:
            # wrk exits nonzero when it cannot connect at all (for example after the
            # product exhausted the host's ephemeral ports); keep the evidence.
            tracker.stopping.set()
            tracker.join()
            failures.append({"error": str(exc)[:300], "peak_rss_kib": tracker.peak})
            continue
        tracker.stopping.set()
        tracker.join()
        cpu = cpu_seconds(pid) - cpu_before
        origin_cpu = (cpu_seconds(origin_pid) - origin_before) if origin_pid else None
        wall = result["duration_us"] / 1e6
        samples.append({
            "requests": result["requests"],
            "requests_per_second": result["requests"] / wall,
            "latency_us": result["latency_us"],
            "errors": result["errors"],
            "cpu_seconds": cpu,
            "cores_busy": cpu / wall,
            "cpu_us_per_request": cpu * 1e6 / max(result["requests"], 1),
            "origin_cpu_seconds": origin_cpu,
            "peak_rss_kib": tracker.peak,
        })
    if not samples:
        return {"failed": True, "failures": failures, "requests_per_second_median": None,
                "latency_us_p50_median": None, "latency_us_p99_median": None,
                "cpu_us_per_request_median": None, "cores_busy_median": None,
                "peak_rss_kib_max": max(f["peak_rss_kib"] for f in failures), "samples": []}
    rates = [s["requests_per_second"] for s in samples]
    median = sorted(samples, key=lambda s: s["requests_per_second"])[len(samples) // 2]
    return {
        "failed": False, "failures": failures,
        "requests_per_second_median": statistics.median(rates),
        "requests_per_second_min": min(rates), "requests_per_second_max": max(rates),
        "latency_us_p50_median": statistics.median(s["latency_us"]["p50"] for s in samples),
        "latency_us_p99_median": statistics.median(s["latency_us"]["p99"] for s in samples),
        "cpu_us_per_request_median": statistics.median(s["cpu_us_per_request"] for s in samples),
        "cores_busy_median": statistics.median(s["cores_busy"] for s in samples),
        "peak_rss_kib_max": max(s["peak_rss_kib"] for s in samples),
        "errors_total": {k: sum(s["errors"][k] for s in samples) for k in samples[0]["errors"]},
        "median_sample": median, "samples": samples,
    }


def product_args(product, mode, binary, port, origin_port, temp, workers):
    if product.startswith("sibuna"):
        args = [str(binary), "--gate" if product == "sibuna-gate" else "--shield",
                "--host", "127.0.0.1", "--port", str(port), "--workers", str(workers),
                "--algorithm", "hashcash", "--difficulty", "8",
                "--rate-limit", "100000000", "--idle-timeout", "5"]
        if mode == "forward_auth":
            args += ["--mode", "forward_auth"]
        else:
            args += ["--upstream-host", "127.0.0.1", "--upstream-port", str(origin_port)]
        return args, {}
    policy = temp / "policy.yaml"
    policy.write_text("bots:\n  - name: generic-browser\n    user_agent_regex: Mozilla\n"
                      "    action: CHALLENGE\ndnsbl: false\nhoneypot:\n  enabled: false\n")
    target = "" if mode == "forward_auth" else f"http://127.0.0.1:{origin_port}"
    args = [str(binary), "--bind", f"127.0.0.1:{port}", "--metrics-bind",
            f"127.0.0.1:{free_port()}", f"--target={target}", "--difficulty", "2",
            "--policy-fname", str(policy), "--slog-level", "ERROR", "--cookie-secure=false"]
    return args, {"GOMAXPROCS": str(workers)}


def drain_time_wait(limit=3000, timeout=90):
    """Loopback churn leaves sockets in TIME_WAIT; wait so ephemeral ports cannot run out."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        out = subprocess.run(["netstat", "-an", "-p", "tcp"], capture_output=True, text=True,
                             check=False).stdout
        if out.count("TIME_WAIT") < limit:
            return
        time.sleep(1)


def wait_ready(proc, port, check):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("server exited during startup")
        try:
            request(port, check)
            return
        except (OSError, RuntimeError):
            time.sleep(0.05)
    raise RuntimeError("server startup timeout")


def workloads(product, mode, cookie):
    """(name, path, headers, expected status, description)."""
    check = API + "check" if product == "anubis" and mode == "forward_auth" else "/private"
    with_cookie = {**HEADERS, "Cookie": cookie}
    shield = product == "sibuna-shield"
    return [
        ("admitted", check, with_cookie, 200,
         "Valid session cookie; the request is admitted (and proxied to the origin)."),
        ("challenged", check, HEADERS, 401 if mode == "forward_auth" else 200,
         "No cookie, browser User-Agent; the product answers with its challenge."),
        ("allowed_static", "/robots.txt", {**HEADERS, "User-Agent": "curl/8.0"}, 200,
         "Non-browser client on a path both products allow without a challenge."),
        ("attack", ATTACK, with_cookie, 403 if shield else 200,
         "Valid session plus an SQL injection query; only an inspecting product refuses it."),
    ]


def run_case(product, mode, binary, origin_port, origin_pid, load, repetitions, workers, script):
    with tempfile.TemporaryDirectory(prefix="sibuna-tools-") as name:
        temp = pathlib.Path(name)
        port = free_port()
        args, extra_env = product_args(product, mode, binary, port, origin_port, temp, workers)
        with (temp / "server.log").open("w+") as log:
            proc = subprocess.Popen(args, stdout=log, stderr=log, cwd=temp,
                                    env={**os.environ, **extra_env})
            try:
                probe = API + "check" if product == "anubis" and mode == "forward_auth" \
                    else "/private"
                wait_ready(proc, port, ("GET", probe, HEADERS, None, 401 if mode == "forward_auth"
                                        else 200))
                time.sleep(0.5)
                idle = rss_kib(proc.pid)
                solver_product = "sibuna" if product.startswith("sibuna") else "anubis"
                hdr, _ = request(port, solution(port, solver_product))
                cookie = cookies(hdr)
                assert cookie, hdr
                result = {"product": product, "mode": mode, "workers": workers,
                          "binary_bytes": binary.stat().st_size, "idle_rss_kib": idle,
                          "workloads": {}}
                for label, path, headers, expected, description in workloads(product, mode,
                                                                             cookie):
                    drain_time_wait()
                    try:
                        status, _, _ = probe_status(port, path, headers)
                    except OSError as exc:
                        status = f"probe failed: {exc}"
                    if status != expected:
                        print(f"  {product} {mode} {label}: expected {expected}, got {status}",
                              flush=True)
                    metrics = measure(port, proc.pid, origin_pid if mode == "reverse_proxy"
                                      else None, path, headers, load, script, repetitions)
                    metrics.update({"path": path, "status": status, "expected_status": expected,
                                    "description": description})
                    result["workloads"][label] = metrics
                    if metrics["failed"]:
                        print(f"  {product:14s} {mode:13s} {label:15s} {status} "
                              f"FAILED: {metrics['failures'][-1]['error'][:80]}", flush=True)
                        continue
                    print(f"  {product:14s} {mode:13s} {label:15s} {status} "
                          f"{metrics['requests_per_second_median']:9.0f} req/s "
                          f"p99 {metrics['latency_us_p99_median'] / 1000:6.2f} ms "
                          f"cpu {metrics['cpu_us_per_request_median']:6.1f} us/req "
                          f"rss {metrics['peak_rss_kib_max'] // 1024} MiB", flush=True)
                result["rss_kib_after_workload"] = rss_kib(proc.pid)
                return result
            except Exception:
                log.flush()
                log.seek(0)
                print(log.read()[-4000:])
                raise
            finally:
                stop(proc)


def probe_status(port, path, headers):
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", path, headers=headers)
        reply = conn.getresponse()
        return reply.status, reply.getheaders(), reply.read()
    finally:
        conn.close()


NOT_MEASURED = [
    {
        "product": "safeline-ce",
        "version_checked": "9.x community edition (chaitin/SafeLine, September 2026)",
        "reason": "Ships only as a Docker Compose stack (tengine, detector, mgt, luigi, fvm, "
                  "chaos, postgres); no Docker daemon on this host and the detector image is "
                  "not an open-source build that can be compiled here.",
        "published": {
            "minimum_host": "Linux x86_64 or arm64 with SSSE3, 1 CPU core, 1 GB RAM, 5 GB disk, "
                            "Docker 20.10.14+ and Compose 2.0+",
            "false_positive_rate": "0.07% (balance) / 0.22% (strict), vendor-reported",
            "detection_rate": "71.65% (balance) / 76.17% (strict), vendor-reported",
        },
    },
    {
        "product": "cloudflare-waf",
        "version_checked": "developers.cloudflare.com/waf, September 2026",
        "reason": "Hosted service on Cloudflare's network; it cannot be installed on a host, "
                  "and any loopback measurement would measure the network path, not the WAF.",
        "published": {
            "custom_rules": "Free 5, Pro 20, Business 100, Enterprise 1000",
            "rate_limiting_rules": "Free 1, Pro 2, Business 5, Enterprise 100",
            "managed_rulesets": "Free Managed Ruleset on all plans; Cloudflare Managed and OWASP "
                                "Core rulesets from Pro; Sensitive Data Detection on Enterprise",
        },
    },
]

LIMITATIONS = [
    "One host, loopback; wrk shares the CPU with the product and the origin stub.",
    "Origin is `caddy respond`; reverse-proxy figures include its cost, forward-auth figures "
    "have no origin.",
    "Hashcash work matched at 8 zero bits for Sibuna and 2 zero hex digits for Anubis; both "
    "use one signing secret, browser solve time is not measured.",
    "CPU time is ps accumulated user+system time of the product process; memory is the peak "
    "resident set sampled every 100 ms.",
    "Sibuna closes proxied connections after each response; Anubis keeps them open. The "
    "reverse-proxy rows measure that difference as well as admission cost.",
    "Anubis binary built or downloaded from its official release outside this repository; its "
    "origin transport runs with Go's default idle-connection limits (no flags were changed).",
    "A workload whose load generator could not connect (ephemeral ports exhausted by the "
    "product's own origin churn) is recorded as failed with the error text, not skipped.",
    "No TLS, no WAN, no real browsers; a ranking on this host is not a ranking on yours.",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anubis", required=True, type=pathlib.Path)
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--connections", type=int, default=64)
    parser.add_argument("--threads", type=int, default=2)
    args = parser.parse_args()
    for tool in ("wrk", "caddy"):
        if shutil.which(tool) is None:
            parser.error(f"{tool} is required on PATH")
    anubis = args.anubis.resolve(strict=True)
    subprocess.run(["zig", "build", "-Doptimize=ReleaseFast"], cwd=ROOT, check=True)
    sibuna = ROOT / "zig-out/bin/sibuna"
    load = {"threads": args.threads, "connections": args.connections, "seconds": args.seconds}
    with tempfile.TemporaryDirectory(prefix="sibuna-tools-lua-") as name:
        script = pathlib.Path(name) / "done.lua"
        script.write_text(WRK_LUA)
        origin_port = free_port()
        origin = subprocess.Popen(["caddy", "respond", "--listen", f"127.0.0.1:{origin_port}",
                                   "--body", ORIGIN_BODY],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(1)
            data = {"meta": metadata(), "load": {**load, "repetitions": args.repetitions},
                    "wrk": subprocess.run(["wrk", "--version"], text=True, capture_output=True,
                                          check=False).stdout.splitlines()[0],
                    "origin": "caddy respond (static 200)",
                    "anubis_version": subprocess.check_output([str(anubis), "--version"],
                                                              text=True).strip(),
                    "runs": [], "not_measured": NOT_MEASURED, "limitations": LIMITATIONS}
            for mode in ("forward_auth", "reverse_proxy"):
                for product, binary in (("sibuna-gate", sibuna), ("sibuna-shield", sibuna),
                                        ("anubis", anubis)):
                    print(f"Measuring {product} in {mode}", flush=True)
                    drain_time_wait()
                    data["runs"].append(run_case(product, mode, binary, origin_port,
                                                 origin.pid, load, args.repetitions,
                                                 args.workers, script))
        finally:
            stop(origin)
    record(data, "tools-comparison-latest")


if __name__ == "__main__":
    main()
