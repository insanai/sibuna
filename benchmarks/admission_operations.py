#!/usr/bin/env python3
"""Matched proof/session operations with native protocols and two external clients."""
from pathlib import Path
import statistics
import subprocess
import tempfile
import time

from admission_batches import measure
from admission_client import AdmissionClient, Request
from bunkerweb import parse_arguments, prepare, run_metadata, wait_ready
from compare import API
from process_accounting import PeakRss, snapshot
from product_fixtures import BITS, CLIENT_HEADERS, Context, start_product, stop_product
from run import free_port, record, stop
from tools import ORIGIN_BODY

CASES = (("sibuna-gate", "forward_auth", "default"),
         ("anubis", "forward_auth", "default"), ("anubis", "forward_auth", "hs512"),
         ("sibuna-shield", "forward_auth", "default"),
         ("bunkerweb-js", "reverse_proxy", "default"),
         ("bunkerweb-js-crs", "reverse_proxy", "default"))
OPERATIONS = 200
PROOFS = 32
BATCHES = 7


def measured_batches(context, process, batches):
    before = snapshot(process.pid)
    tracker = PeakRss(process.pid)
    tracker.start()
    try:
        rows = measure(context.options.generator, context.port, batches)
    finally:
        peak = tracker.finish()
    after = snapshot(process.pid)
    if before["pids"] != after["pids"]:
        raise ValueError("process membership changed during admission batches")
    cpu = after["cpu_seconds"] - before["cpu_seconds"]
    operations = sum(row["operations"] for row in rows)
    return {"samples": rows, "operations_per_second_median": statistics.median(
                row["operations_per_second"] for row in rows),
            "operations_per_second_min": min(row["operations_per_second"] for row in rows),
            "operations_per_second_max": max(row["operations_per_second"] for row in rows),
            "cpu_seconds": cpu,
            "cpu_us_per_operation": cpu * 1e6 / operations if cpu >= 0.01 else None,
            "peak_process_tree_rss_kib": peak}


def operations(context, process, profile, mode):
    client = AdmissionClient("127.0.0.1", context.port, profile)
    deadline = time.monotonic() + 30
    while True:
        try:
            cookie = client.session()
            break
        except OSError:
            if process.poll() is not None or time.monotonic() > deadline:
                raise
            time.sleep(0.1)
    check = API + "check" if profile == "anubis" else "/private"
    missing_status = 302 if profile.startswith("bunkerweb") else 401
    valid = Request("GET", check, {**CLIENT_HEADERS, "Cookie": cookie})
    missing = Request("GET", check, CLIENT_HEADERS, expected=missing_status)
    for task in (valid, missing):
        client.exchange(task)  # Untimed positive and negative session witnesses.
    results = {}
    for label, group in (("valid_session", [valid]), ("unauthenticated_check", [missing])):
        results[label] = measured_batches(context, process, [[group] * OPERATIONS
                                                           for _ in range(BATCHES)])
    # Proof verification precedes bootstrap stress so adaptive issuance stays at 16 bits.
    prepared = [[[client.prepare()] for _ in range(PROOFS)] for _ in range(BATCHES)]
    results["proof_verification"] = measured_batches(context, process, prepared)
    bootstrap = client.bootstrap()
    for task in bootstrap:
        client.exchange(task)
    results["challenge_bootstrap"] = measured_batches(context, process,
                                                      [[bootstrap] * OPERATIONS
                                                       for _ in range(BATCHES)])
    client.exchange(valid)
    return results


def run_case(options, temporary, origin, cpus, case):
    profile, mode, scheme = case
    context = Context(options, free_port(), origin, temporary, cpus)
    with (temporary / "product.log").open("w+") as log:
        process, configuration = start_product(profile, context, log, True, mode, scheme)
        try:
            results = operations(context, process, profile, mode)
            print(f"admission {profile} {mode} {scheme}: " + ", ".join(
                f"{k} {v['operations_per_second_median']:.0f} ops/s" for k,v in results.items()),
                flush=True)
            return {"profile": profile, "mode": mode, "scheme": scheme,
                    "configuration": configuration, "operations": results}
        except Exception:
            log.seek(0)
            print(log.read()[-2000:], flush=True)
            raise
        finally:
            stop_product(profile, process, options.rootfs)


def main():
    options = parse_arguments()
    if not options.anubis or not options.load_host:
        raise ValueError("--anubis and --load-host are required")
    cpus, origin_cpus, generator = prepare(options)
    data = run_metadata(options, cpus, origin_cpus, generator)
    data["scope"] = {"clients": 2, "batches": BATCHES, "operations_per_batch": OPERATIONS,
                     "proofs_per_batch": PROOFS, "verified_proof_bits": BITS,
                     "not_measured": "BunkerWeb native forward-auth endpoint"}
    data["limitations"] = [
        "Products/origin on .18, two Python client processes on .20; separate physical hosts.",
        "Four product CPUs; two generator CPUs; HTTP/1.1; no TLS or browser solve timing.",
        "SHA-256 work matched at 16 zero bits; native envelopes/session mechanisms differ.",
        "Sibuna/Anubis use native forward-auth; BunkerWeb session checks include origin relay.",
        "Anubis default Ed25519 and optional HS512 are measured separately.",
        "Bootstrap is HTML+JSON for Sibuna, HTML for Anubis, redirect+HTML for BunkerWeb.",
        "Every proof is fresh and solved before timing; expected statuses checked per request.",
        "Bootstrap may increase Sibuna's adaptive issued difficulty; observed bits recorded.",
        "Same Accept-Encoding: gzip for all; native Anubis challenge compression active.",
        "Each batch includes Python, IPC, HTTP and connection setup; SSH excluded from timing.",
        "CPU interval includes SSH invocation; small tick deltas reported as unresolved.",
        "Shared host/frequency uncontrolled; CRS and heuristic rule coverage are different.",
    ]
    with tempfile.TemporaryDirectory(prefix="sibuna-admission-operations-") as name:
        temporary = Path(name)
        port = free_port()
        origin = subprocess.Popen(["taskset", "-c", ",".join(map(str, origin_cpus)), "caddy",
                                   "respond", "--listen", f"127.0.0.1:{port}",
                                   "--body", ORIGIN_BODY], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        try:
            wait_ready(origin, port)
            data["runs"] = [run_case(options, temporary, port, cpus, case) for case in CASES]
        finally:
            stop(origin)
    data["functional_pass"] = True
    record(data, "products-admission-operations-two-host-latest")


if __name__ == "__main__":
    main()
