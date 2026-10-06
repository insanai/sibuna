#!/usr/bin/env python3
"""Measure the native CRS request path: disabled, audit and enforce at paranoia 1 and 2.

Every profile runs the same console-enabled binary with eight signed-in dashboards, so the
comparison isolates CRS evaluation rather than the console. Rounds rotate profile order.
CRS figures are reported separately from the lightweight inspector, which stays disabled.
"""
import argparse
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import console_bootstrap_test as bootstrap
import console_e2e as helper
from admission_client import Request
from console_dashboard import Dashboard, difference, stop_clients
from http_load import HttpLoad
from http_measure import Workload, measure
from product_fixtures import Context
from run import ROOT, free_port, metadata, record, stop
from tools import ATTACK, ORIGIN_BODY

PASSWORD = "CRS request path benchmark passphrase"
HEADERS = {"Host": "benchmark.test", "User-Agent": "Mozilla/5.0 SibunaBenchmark",
           "Accept": "text/html", "Accept-Encoding": "identity"}
PROFILES = (("disabled", None, None), ("audit-pl1", "audit", 1), ("enforce-pl1", "enforce", 1),
            ("audit-pl2", "audit", 2), ("enforce-pl2", "enforce", 2))
BOUNDARY = "SibunaBenchmarkBoundary"
MULTIPART = (f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\n"
             "quarterly report\r\n"
             f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; "
             "filename=\"report.txt\"\r\nContent-Type: text/plain\r\n\r\n" +
             "Plain benchmark upload line.\n" * 560 + f"\r\n--{BOUNDARY}--\r\n")
CASES = (
    ("small_get", "GET", "/private", None, None),
    ("json_8k", "POST", "/api", "application/json",
     json.dumps({"message": "hello", "pad": "x" * 8000})),
    ("multipart_16k", "POST", "/upload", f"multipart/form-data; boundary={BOUNDARY}",
     MULTIPART),
    ("sqli_query", "GET", ATTACK, None, None),
)
DASHBOARDS = 8


def expected_status(mode, label):
    return 403 if mode == "enforce" and label.startswith("sqli") else 200


def counters(port):
    status, _, body = helper.request(port, "GET", "/__sibuna/metrics")
    assert status == 200, status
    return {name.decode(): int(value) for name, value in
            re.findall(rb"(?m)^(sibuna_crs_\w+) (\d+)$", body)}


def login(port):
    # Honour the console's account limiter instead of weakening it for the fixture.
    while True:
        code, headers, body = helper.request(port, "POST", "/console/api/login", {
            "username": "bench-admin", "password": PASSWORD})
        if code != 429:
            assert code == 200, body
            return headers["Set-Cookie"].split(";", 1)[0], json.loads(body)["csrf"]
        time.sleep(5)


def launch(arguments, profile, temporary, port, console_port, log):
    name, mode, paranoia = profile
    data = temporary / f"data-{name}-{port}"
    credentials = bootstrap.initialize(str(arguments.sibuna), str(data), "bench-admin")
    policy = temporary / "policy.json"
    policy.write_text(json.dumps({"waf": False, "default_action": "ALLOW", "rules": [
        {"name": "benchmark", "path": "*", "action": "ALLOW"}]}))
    command = ["taskset", "-c", ",".join(map(str, arguments.product_cpus)),
               str(arguments.sibuna), "--shield", "--mode", "reverse_proxy",
               "--host", arguments.listen_host, "--port", str(port),
               "--workers", str(arguments.workers), "--upstream-port", str(arguments.origin),
               "--policy-file", str(policy), "--rate-limit", "2000000000",
               "--idle-timeout", "15", "--data-dir", str(data),
               "--console", f"127.0.0.1:{console_port}"]
    if mode:
        command += ["--crs-mode", mode, "--crs-dir", str(arguments.candidate),
                    "--crs-paranoia", str(paranoia), "--crs-detection-paranoia",
                    str(paranoia)]
    process = subprocess.Popen(command, stdout=log, stderr=log)
    wait_console(process, console_port)
    bootstrap.change(helper, console_port, credentials, PASSWORD)
    return process, command


def wait_console(process, console_port):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"daemon exited: {process.returncode}")
        try:
            if helper.request(console_port, "GET", "/console/api/setup")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError("console did not become ready")


def selection(console_port, session):
    status, _, body = helper.request(console_port, "GET", "/console/api/nodes/local",
                                     cookie=session[0])
    assert status == 200, body
    crs = json.loads(body).get("crs") or {}
    return crs.get("selection")


def workload(mode, label, method, path, content_type, body):
    headers = dict(HEADERS)
    if content_type:
        headers["Content-Type"] = content_type
    expected = expected_status(mode, label)
    return Workload(label, Request(method, path, headers, body, expected),
                    origin_response=expected == 200)


def profile_samples(arguments, profile, temporary, round_index):
    port, console_port = free_port(), free_port()
    with (temporary / f"{profile[0]}-{round_index}.log").open("w+") as log:
        process, command = launch(arguments, profile, temporary, port, console_port, log)
        clients = []
        try:
            session = login(console_port)
            for _ in range(DASHBOARDS):
                client = Dashboard(helper, console_port, *session)
                client.start()
                clients.append(client)
            context = Context(arguments, port, arguments.origin, temporary, [])
            samples = {}
            for label, method, path, content_type, body in CASES:
                before, dashboards = counters(port), [c.snapshot() for c in clients]
                sample = measure(context, process, workload(profile[1], label, method, path,
                                                            content_type, body))
                after = counters(port)
                sample["crs_counters"] = {key: after[key] - before.get(key, 0) for key in after}
                sample["work_limit_rate"] = sample["crs_counters"].get(
                    "sibuna_crs_incomplete_total", 0) / max(sample["requests"], 1)
                sample["dashboards"] = difference(dashboards, [c.snapshot() for c in clients])
                samples[label] = sample
                print(f"round {round_index + 1} {profile[0]} {label}: "
                      f"{sample['requests_per_second']:.0f} req/s; "
                      f"p99 {sample['latency_us']['p99'] / 1000:.2f} ms", flush=True)
            return samples, command, selection(console_port, session)
        except Exception:
            log.seek(0)
            print(log.read()[-4000:], flush=True)
            raise
        finally:
            failures = stop_clients(clients)
            stop(process)
            if failures:
                raise RuntimeError(f"dashboard failures: {failures}")


def summarize(samples):
    def median(key):
        return statistics.median(key(sample) for sample in samples)
    return {"samples": samples,
            "requests_per_second_median": median(lambda s: s["requests_per_second"]),
            "requests_per_second_min": min(s["requests_per_second"] for s in samples),
            "requests_per_second_max": max(s["requests_per_second"] for s in samples),
            "p50_us_median": median(lambda s: s["latency_us"]["p50"]),
            "p90_us_median": median(lambda s: s["latency_us"]["p90"]),
            "p99_us_median": median(lambda s: s["latency_us"]["p99"]),
            "max_us_max": max(s["latency_us"]["max"] for s in samples),
            "cpu_us_per_request_median": median(lambda s: s["cpu_us_per_request"]),
            "peak_process_tree_rss_kib_max": max(s["peak_process_tree_rss_kib"]
                                                 for s in samples),
            "work_limit_rate_max": max(s["work_limit_rate"] for s in samples)}


def run_rounds(arguments, temporary, data):
    results = {profile[0]: {case[0]: [] for case in CASES} for profile in PROFILES}
    configurations = {}
    for round_index in range(arguments.repetitions):
        offset = round_index % len(PROFILES)
        order = PROFILES[offset:] + PROFILES[:offset]
        data["rounds"].append([profile[0] for profile in order])
        for profile in order:
            samples, command, selected = profile_samples(arguments, profile, temporary,
                                                         round_index)
            configurations[profile[0]] = {"command": command, "selection": selected}
            for label, sample in samples.items():
                results[profile[0]][label].append({"round": round_index, **sample})
    data["runs"] = [{"profile": name, "mode": mode, "paranoia": paranoia,
                     "configuration": configurations[name],
                     "workloads": {label: summarize(samples) for label, samples
                                   in results[name].items()}}
                    for name, mode, paranoia in PROFILES]


def parse_arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sibuna", type=Path, default=ROOT / "zig-out/bin/sibuna")
    parser.add_argument("--candidate", type=Path, required=True,
                        help="signed CRS 4.30.0 candidate from `sibuna crs check`")
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


def prepare(arguments):
    allowed = sorted(os.sched_getaffinity(0))
    if len(allowed) < arguments.workers + 4:
        raise ValueError("need separate CPUs for product, generator and origin")
    arguments.product_cpus = allowed[:arguments.workers]
    arguments.load_cpus = allowed[arguments.workers:arguments.workers + 2]
    arguments.origin_cpus = allowed[arguments.workers + 2:arguments.workers + 4]
    arguments.sibuna = arguments.sibuna.resolve(strict=True)
    arguments.candidate = arguments.candidate.resolve(strict=True)
    arguments.listen_host = "0.0.0.0" if arguments.load_host else "127.0.0.1"
    arguments.generator = HttpLoad(arguments.target_host, arguments.load_host,
                                   arguments.load_wrk, arguments.load_library_dir,
                                   arguments.ssh_known_hosts)
    return arguments.generator.identity()


def run_metadata(arguments, generator):
    return {"meta": metadata(arguments.sibuna), "load": {
        field: getattr(arguments, field) for field in (
            "seconds", "warmup", "repetitions", "workers", "threads", "connections")},
        "affinity": {"product": arguments.product_cpus, "origin": arguments.origin_cpus,
                     "generator": generator["cpus"] if generator else arguments.load_cpus},
        "dashboards": DASHBOARDS, "runs": [], "rounds": [], "functional_pass": False,
        "topology": "two-host" if arguments.load_host else "loopback",
        "generator": generator, "target_host": arguments.target_host,
        "crs_release": "4.30.0",
        "limitations": [
            "Unprivileged container on a shared host; CPU frequency and host load are not "
            "controlled.",
            "HTTP/1.1 without TLS; admission is unconditional and the lightweight inspector "
            "is disabled.",
            "Every profile runs the console with eight dashboards; storage records CRS "
            "findings for the attack workload.",
            "Stock CRS 4.30.0 at the stated paranoia with default thresholds and work budget.",
            "CPU sums user/system ticks of the process tree; peak RSS is the process tree.",
            "wrk response hooks validate statuses and add client cost; expected 403 is valid.",
        ]}


def main():
    arguments = parse_arguments()
    generator = prepare(arguments)
    data = run_metadata(arguments, generator)
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-bench-") as name:
        temporary = Path(name)
        arguments.origin = free_port()
        origin = subprocess.Popen(["taskset", "-c", ",".join(map(str, arguments.origin_cpus)),
                                   "caddy", "respond", "--listen",
                                   f"127.0.0.1:{arguments.origin}", "--body", ORIGIN_BODY],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            run_rounds(arguments, temporary, data)
        finally:
            stop(origin)
    data["functional_pass"] = True
    record(data, "crs-request-path" + ("-two-host-latest" if arguments.load_host else
                                       "-loopback-latest"))


if __name__ == "__main__":
    main()
