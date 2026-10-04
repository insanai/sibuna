#!/usr/bin/env python3
"""Compare native BunkerWeb and Sibuna HTTP/1.1 proxy/inspection profiles.

This deliberately excludes browser challenges, TLS, control planes and attack-detection
accuracy. Interleaved rounds compare identical requests on an identical Caddy origin.
Refuse publication if any probe, measured status or transport validation fails.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import statistics
import subprocess
import tempfile
import time

import bunkerweb_fixture as bunker
from process_accounting import PeakRss, snapshot
from http_load import HttpLoad
from run import ROOT, free_port, metadata, record, stop
from tools import ATTACK, ORIGIN_BODY

HEADERS = {"Host": "benchmark.test", "User-Agent": "Mozilla/5.0 SibunaBenchmark",
           "Accept": "text/html", "Accept-Encoding": "identity"}
PROFILES = ("origin", "sibuna-gate", "bunkerweb-proxy", "sibuna-shield", "bunkerweb-crs",
            "bunkerweb-crs-small-error")
CASES = (
    ("benign_get", "GET", "/private", None),
    ("benign_json_8k", "POST", "/api", json.dumps({"message": "hello", "pad": "x" * 8000})),
    ("sqli_query", "GET", ATTACK, None),
    ("sqli_json", "POST", "/api", json.dumps({"query": "1' OR 1=1--"})),
)


def script(path, method, body):
    path.write_text("""
statuses = {}
threads = {}
setup = function(thread) table.insert(threads, thread) end
response = function(status, headers, body)
  statuses[status] = (statuses[status] or 0) + 1
end
done = function(summary, latency, requests)
  local totals = {}
  for _, thread in ipairs(threads) do
    for status, count in pairs(thread:get('statuses')) do
      totals[status] = (totals[status] or 0) + count
    end
  end
  io.write(string.format('WRKJSON {"requests":%d,"duration_us":%d,"bytes":%d,'
    .. '"errors":{"connect":%d,"read":%d,"write":%d,"status":%d,"timeout":%d},'
    .. '"latency_us":{"p50":%d,"p90":%d,"p99":%d,"max":%d,"mean":%.1f},'
    .. '"statuses":{', summary.requests, summary.duration, summary.bytes,
    summary.errors.connect, summary.errors.read, summary.errors.write,
    summary.errors.status, summary.errors.timeout, latency:percentile(50),
    latency:percentile(90), latency:percentile(99), latency.max, latency.mean))
  local first = true
  for status, count in pairs(totals) do
    if not first then io.write(',') end
    io.write(string.format('"%d":%d', status, count))
    first = false
  end
  io.write('}}\\n')
end
""" + f"\nwrk.method = {json.dumps(method)}\n"
        + (f"wrk.body = {json.dumps(body)}\n" if body is not None else ""))


def probe(port, method, path, body, expected):
    import http.client
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        headers = dict(HEADERS)
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        payload = response.read()
        if response.status != expected:
            raise ValueError(f"{method} {path}: expected {expected}, got {response.status}: "
                             f"{payload[:200]!r}")
        if expected == 200 and payload != ORIGIN_BODY.encode():
            raise ValueError("an admitted response did not match the origin fixture")
        return {"status": response.status, "body_bytes": len(payload),
                "body_sha256": hashlib.sha256(payload).hexdigest()}
    finally:
        connection.close()


def expected_status(profile, label):
    return 403 if label.startswith("sqli") and profile in (
        "sibuna-shield", "bunkerweb-crs", "bunkerweb-crs-small-error") else 200


def wait_ready(process, port):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"product exited: {process.returncode}")
        try:
            probe(port, "GET", "/private", None, 200)
            return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("product did not become ready")


def launch(profile, arguments, port, origin, temporary, log, cpus):
    if profile.startswith("bunkerweb"):
        settings = bunker.configure(arguments.rootfs, port, origin,
                                    arguments.workers, profile.startswith("bunkerweb-crs"),
                                    small_error=profile == "bunkerweb-crs-small-error")
        return bunker.start(arguments.rootfs, cpus, log), settings
    policy = temporary / "policy.json"
    policy.write_text('{"default_action":"allow","rules":[]}\n')
    command = ["taskset", "-c", ",".join(map(str, cpus)), str(arguments.sibuna),
               "--gate" if profile == "sibuna-gate" else "--shield",
               "--host", arguments.listen_host, "--port", str(port),
               "--workers", str(arguments.workers), "--upstream-host", "127.0.0.1",
               "--upstream-port", str(origin), "--policy-file", str(policy),
               "--rate-limit", "100000000", "--idle-timeout", "15"]
    return subprocess.Popen(command, stdout=log, stderr=log), {
        "command": command, "policy": json.loads(policy.read_text()),
        "console_active": False, "storage_active": False,
    }


def stop_product(profile, process, rootfs):
    if not profile.startswith("bunkerweb"):
        stop(process)
        return
    pid_file = rootfs / "var/run/bunkerweb/nginx.pid"
    if process.poll() is None and pid_file.exists():
        pid = int(pid_file.read_text())
        if pid not in snapshot(process.pid)["pids"]:
            raise RuntimeError("nginx PID does not belong to this fixture")
        os.kill(pid, signal.SIGQUIT)
    process.wait(timeout=15)
    if process.returncode:
        raise RuntimeError(f"BunkerWeb stop returned {process.returncode}")


def validate_measured(measured, expected):
    transport = {key: value for key, value in measured["errors"].items() if key != "status"}
    if any(transport.values()) or measured["statuses"] != {
            str(expected): measured["requests"]} or not measured["requests"]:
        raise ValueError(f"invalid measured responses: {measured}")


def measure(process, port, label, method, path, body, expected, arguments, temporary):
    lua = temporary / "request.lua"
    script(lua, method, body)
    headers = dict(HEADERS)
    if body is not None:
        headers["Content-Type"] = "application/json"
    evidence = probe(port, method, path, body, expected)
    load = {"threads": arguments.threads, "connections": arguments.connections,
            "seconds": arguments.seconds}
    # Separate logical CPU sets avoid product/generator scheduling overlap. Other
    # host tenants and shared physical cores are outside this container's control.
    old_affinity = os.sched_getaffinity(0)
    os.sched_setaffinity(0, arguments.load_cpus)
    try:
        arguments.generator.run(port, path, headers, {**load, "seconds": arguments.warmup}, lua)
        before = snapshot(process.pid)
        tracker = PeakRss(process.pid)
        tracker.start()
        try:
            measured = arguments.generator.run(port, path, headers, load, lua)
        finally:
            peak = tracker.finish()
        after = snapshot(process.pid)
    finally:
        os.sched_setaffinity(0, old_affinity)
    validate_measured(measured, expected)
    if expected == 403 and measured["errors"]["status"] != measured["requests"]:
        raise ValueError("wrk status accounting disagrees with the response hook")
    if before["pids"] != after["pids"]:
        raise ValueError("product process membership changed during measurement")
    wall = measured["duration_us"] / 1e6
    cpu = after["cpu_seconds"] - before["cpu_seconds"]
    return {"label": label, "method": method, "path": path,
            "request_body_bytes": len(body or ""), "probe": evidence,
            "requests_per_second": measured["requests"] / wall,
            "cpu_seconds": cpu, "cpu_us_per_request": cpu * 1e6 / measured["requests"],
            "peak_process_tree_rss_kib": peak, "process_pids": after["pids"], **measured}


def summarize(samples):
    return {"samples": samples,
            "requests_per_second_median": statistics.median(
                sample["requests_per_second"] for sample in samples),
            "requests_per_second_min": min(sample["requests_per_second"] for sample in samples),
            "requests_per_second_max": max(sample["requests_per_second"] for sample in samples),
            "p50_us_median": statistics.median(sample["latency_us"]["p50"] for sample in samples),
            "p99_us_median": statistics.median(sample["latency_us"]["p99"] for sample in samples),
            "cpu_us_per_request_median": statistics.median(
                sample["cpu_us_per_request"] for sample in samples),
            "peak_process_tree_rss_kib_max": max(
                       sample["peak_process_tree_rss_kib"] for sample in samples)}


def tool_versions():
    # wrk prints its version and usage but returns 1, unlike caddy's version command.
    versions = {}
    for name, command, accepted in (("wrk", ["wrk", "--version"], (0, 1)),
                                    ("caddy", ["caddy", "version"], (0,))):
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        if result.returncode not in accepted or not result.stdout.strip():
            raise RuntimeError(f"could not identify {name}: {result.stdout}")
        versions[name] = result.stdout.strip().splitlines()[0]
    return versions


def run_rounds(arguments, temporary, origin, origin_port, cpus, data):
    results = {profile: {case[0]: [] for case in CASES} for profile in PROFILES}
    configurations = {}
    for round_index in range(arguments.repetitions):
        order = PROFILES[round_index % len(PROFILES):] + PROFILES[:round_index % len(PROFILES)]
        data["rounds"].append(list(order))
        for profile in order:
            port = origin_port if profile == "origin" else free_port()
            with (temporary / f"{profile}.log").open("w+") as log:
                process, settings = (origin, {}) if profile == "origin" else launch(
                    profile, arguments, port, origin_port, temporary, log, cpus)
                configurations[profile] = settings
                try:
                    wait_ready(process, port)
                    for label, method, path, body in CASES:
                        expected = expected_status(profile, label)
                        sample = measure(process, port, label, method, path, body,
                                         expected, arguments, temporary)
                        if profile == "bunkerweb-crs-small-error" and expected == 403:
                            if sample["probe"]["body_sha256"] != hashlib.sha256(
                                    bunker.ERROR_BODY).hexdigest():
                                raise ValueError("custom error response did not match fixture")
                        results[profile][label].append({"round": round_index, **sample})
                        print(f"round {round_index + 1} {profile} {label}: "
                              f"{sample['requests_per_second']:.0f} req/s; "
                              f"p99 {sample['latency_us']['p99'] / 1000:.2f} ms", flush=True)
                except Exception:
                    log.seek(0)
                    print(log.read()[-4000:], flush=True)
                    raise
                finally:
                    if profile != "origin":
                        stop_product(profile, process, arguments.rootfs)
    data["runs"] = [{"profile": profile, "configuration": configurations[profile],
                     "workloads": {label: summarize(samples) for label, samples
                                   in results[profile].items()}} for profile in PROFILES]


def parse_arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--sibuna", type=Path, default=ROOT / "zig-out/bin/sibuna")
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--connections", type=int, default=64)
    parser.add_argument("--load-host", help="SSH destination for a separate Linux wrk host")
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--load-wrk", default="wrk")
    parser.add_argument("--load-library-dir")
    parser.add_argument("--ssh-known-hosts")
    arguments = parser.parse_args()
    for field in ("seconds", "warmup", "repetitions", "workers", "threads", "connections"):
        if getattr(arguments, field) < 1:
            parser.error(f"{field} must be positive")
    if arguments.load_host and arguments.target_host == "127.0.0.1":
        parser.error("--load-host requires a --target-host reachable from the generator")
    return arguments


def main():
    arguments = parse_arguments()
    allowed = sorted(os.sched_getaffinity(0))
    if len(allowed) < arguments.workers + 4:
        raise ValueError("need separate CPUs for product, generator and origin")
    cpus = allowed[:arguments.workers]
    arguments.load_cpus = allowed[arguments.workers:arguments.workers + 2]
    origin_cpus = allowed[arguments.workers + 2:arguments.workers + 4]
    arguments.rootfs = arguments.rootfs.resolve(strict=True)
    arguments.image = arguments.image.resolve(strict=True)
    arguments.sibuna = arguments.sibuna.resolve(strict=True)
    arguments.listen_host = "0.0.0.0" if arguments.load_host else "127.0.0.1"
    arguments.generator = HttpLoad(arguments.target_host, arguments.load_host,
                                   arguments.load_wrk, arguments.load_library_dir,
                                   arguments.ssh_known_hosts)
    remote_generator = arguments.generator.identity()
    data = {"meta": metadata(arguments.sibuna), "bunkerweb": bunker.identity(
        arguments.rootfs, arguments.image), "load": {
        field: getattr(arguments, field) for field in (
            "seconds", "warmup", "repetitions", "workers", "threads", "connections")},
        "affinity": {"product": cpus, "origin": origin_cpus, "generator":
                     remote_generator["cpus"] if remote_generator else arguments.load_cpus},
        "runs": [], "rounds": [], "functional_pass": False,
        "topology": "two-host" if arguments.load_host else "loopback",
        "generator": remote_generator,
        "target_host": arguments.target_host,
        "tools": tool_versions(),
        "limitations": [
            "Unprivileged container on a shared host; no control of CPU frequency or host load.",
            "HTTP/1.1; no TLS, browser challenges, sessions or AI-bot detection test.",
            "Unconditional admission configured; inspection enabled only in Shield/CRS profiles.",
            "Default CRS v4 rules; Sibuna heuristic inspection is not equivalent rule coverage.",
            "Stock denial pages differ; a separate CRS profile serves a 235-byte static 403 page.",
            "Product CPU allowance equal; generator and origin on separate allowed CPU sets.",
            "Control planes, audit/access logging, rate limits, feeds and compression inactive.",
            "BunkerWeb upstream keepalive explicitly enabled; Sibuna uses its native transport.",
            "CPU uses summed user/system ticks; peak summed RSS double-counts shared pages.",
            "wrk response hooks validate statuses and add client cost; expected 403 is valid.",
            "An origin baseline bounds fixture throughput; results are not universal rankings.",
            "CPU interval includes generator invocation; remote SSH setup precedes wrk timing.",
        ]}
    with tempfile.TemporaryDirectory(prefix="sibuna-bunkerweb-") as name:
        temporary = Path(name)
        origin_port = free_port()
        origin = subprocess.Popen(["taskset", "-c", ",".join(map(str, origin_cpus)),
                                   "caddy", "respond", "--listen",
                                   f"{arguments.listen_host}:{origin_port}",
                                   "--body", ORIGIN_BODY], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        try:
            wait_ready(origin, origin_port)
            run_rounds(arguments, temporary, origin, origin_port, cpus, data)
        finally:
            stop(origin)
    data["functional_pass"] = True
    record(data, "bunkerweb-two-host-latest" if arguments.load_host
           else "bunkerweb-comparison-latest")


if __name__ == "__main__":
    main()
