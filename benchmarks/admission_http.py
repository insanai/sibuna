#!/usr/bin/env python3
"""HTTP workloads with genuine admitted sessions and browser challenge responses.

Same product/generator/origin hosts and budgets as the proxy comparison. Native
forward-auth endpoints are measured separately; BunkerWeb's proxy is not invented as one.
"""
from pathlib import Path
import subprocess
import tempfile
import time

from admission_client import AdmissionClient, Request
from bunkerweb import parse_arguments, prepare, run_metadata, summarize, wait_ready
from compare import API
from http_measure import Workload, measure
from product_fixtures import BITS, CLIENT_HEADERS, Context, start_product, stop_product
from run import free_port, record, stop
from tools import ATTACK, ORIGIN_BODY

PROXY = ("sibuna-gate", "anubis", "bunkerweb-js", "sibuna-shield", "bunkerweb-js-crs")
AUTH = ("sibuna-gate", "anubis", "sibuna-shield")


def workloads(profile, mode, cookie):
    path = API + "check" if profile == "anubis" and mode == "forward_auth" else "/private"
    admitted = {**CLIENT_HEADERS, "Cookie": cookie}
    challenge_status = 401 if mode == "forward_auth" else (
        302 if profile.startswith("bunkerweb") else 200)
    marker = b"" if challenge_status != 200 else (
        b"anubis_challenge" if profile == "anubis" else b"__sibuna")
    inspecting = profile in ("sibuna-shield", "bunkerweb-js-crs")
    origin = mode == "reverse_proxy"
    return (
        Workload("admitted", Request("GET", path, admitted), origin_response=origin),
        Workload("challenged", Request("GET", path, CLIENT_HEADERS, expected=challenge_status),
                 marker=marker),
        Workload("allowed_static", Request("GET", "/robots.txt",
                 {**CLIENT_HEADERS, "User-Agent": "curl/8.0"}), origin_response=origin),
        Workload("attack", Request("GET", ATTACK, admitted, expected=403 if inspecting else 200),
                 origin_response=origin and not inspecting),
    )


def run_round(options, temporary, origin, cpus, mode, round_index, samples, configurations):
    profiles = PROXY if mode == "reverse_proxy" else AUTH
    offset = round_index % len(profiles)
    for profile in (*profiles[offset:], *profiles[:offset]):
        port = free_port()
        context = Context(options, port, origin, temporary, cpus)
        with (temporary / "product.log").open("w+") as log:
            process, configuration = start_product(profile, context, log,
                                                   protected=True, mode=mode)
            try:
                deadline = time.monotonic() + 30
                client = AdmissionClient("127.0.0.1", port, profile)
                while True:
                    if process.poll() is not None:
                        raise RuntimeError("product exited during startup")
                    try:
                        cookie = client.session()
                        break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise
                        time.sleep(0.1)
                configurations[(mode, profile)] = configuration
                for workload in workloads(profile, mode, cookie):
                    sample = measure(context, process, workload)
                    samples[(mode, profile)][workload.label].append(
                        {"round": round_index, **sample})
                    print(f"round {round_index+1} {mode} {profile} {workload.label}: "
                          f"{sample['requests_per_second']:.0f} req/s; "
                          f"p99 {sample['latency_us']['p99']/1000:.2f} ms", flush=True)
            except Exception:
                log.seek(0)
                print(log.read()[-2000:], flush=True)
                raise
            finally:
                stop_product(profile, process, options.rootfs)


def main():
    options = parse_arguments()
    if not options.anubis:
        raise ValueError("--anubis is required for the three-product comparison")
    cpus, origin_cpus, generator = prepare(options)
    data = run_metadata(options, cpus, origin_cpus, generator)
    data["scope"] = {"proof_bits": BITS, "protocol": "hashcash; native product envelopes",
                     "forward_auth_not_measured": ["BunkerWeb: no native fixture endpoint"],
                     "challenge": "native protected response; bootstrap hops measured separately"}
    data["limitations"] = [
        "Products on one shared Linux container; load on a second physical host; HTTP/1.1.",
        "Four product CPUs, two origin CPUs, two separate-host generator CPUs; no TLS or UI.",
        "Proof work is 16 zero bits; client solving and bootstrap are outside wrk timing.",
        "Challenge response is HTML for Sibuna/Anubis, a 302 redirect for BunkerWeb.",
        "Sibuna/Anubis native forward-auth rows have no origin; BunkerWeb is proxy-only here.",
        "Synthetic forwarded address trusted within this private fixture for session binding.",
        "Rate allowances raised/disabled; consoles, logging, feeds and compression inactive.",
        "CRS coverage exceeds heuristic inspection; this is not a detection-quality test.",
        "Process-tree CPU brackets SSH invocation; summed RSS double-counts shared pages.",
        "Every timed status and pre/post response-class probe must pass; no transport errors.",
        "Fixed concurrency and observed range, not an equal-rate latency or acceptance gate.",
    ]
    samples = {(mode, profile): {label: [] for label in (
        "admitted", "challenged", "allowed_static", "attack")}
        for mode, profiles in (("reverse_proxy", PROXY), ("forward_auth", AUTH))
        for profile in profiles}
    configurations = {}
    with tempfile.TemporaryDirectory(prefix="sibuna-admission-http-") as name:
        temporary = Path(name)
        port = free_port()
        origin = subprocess.Popen(["taskset", "-c", ",".join(map(str, origin_cpus)), "caddy",
                                   "respond", "--listen", f"127.0.0.1:{port}",
                                   "--body", ORIGIN_BODY], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        try:
            wait_ready(origin, port)
            for round_index in range(options.repetitions):
                for mode in ("reverse_proxy", "forward_auth"):
                    run_round(options, temporary, port, cpus, mode, round_index,
                              samples, configurations)
        finally:
            stop(origin)
    data["runs"] = [{"mode": mode, "profile": profile,
                     "configuration": configurations[(mode, profile)],
                     "workloads": {label: summarize(rows) for label, rows in values.items()}}
                    for (mode, profile), values in samples.items()]
    data["functional_pass"] = True
    record(data, "products-admission-http-two-host-latest" if options.load_host
           else "products-admission-http-loopback-latest")


if __name__ == "__main__":
    main()
