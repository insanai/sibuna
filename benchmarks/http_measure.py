#!/usr/bin/env python3
"""External HTTP measurement with owned request descriptions and strict result checks."""
from dataclasses import dataclass
import hashlib
import json
import os

from admission_client import AdmissionClient, Request
from process_accounting import PeakRss, snapshot
from tools import ORIGIN_BODY


@dataclass(frozen=True)
class Workload:
    label: str
    request: Request
    origin_response: bool = False
    marker: bytes = b""


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



def probe(context, workload):
    client = AdmissionClient("127.0.0.1", context.port, "probe")
    headers, body = client.exchange(workload.request)
    if workload.origin_response and body != ORIGIN_BODY.encode():
        raise ValueError("admitted response differs from the origin fixture")
    if workload.marker and workload.marker not in body:
        raise ValueError("response did not contain the expected challenge marker")
    if workload.request.expected == 302:
        location = next((v for k, v in headers if k.lower() == "location"), "")
        if not location.startswith("/challenge"):
            raise ValueError("unexpected BunkerWeb challenge redirect")
    return {"status": workload.request.expected, "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest()}


def validate_measured(measured, expected):
    transport = {key: value for key, value in measured["errors"].items() if key != "status"}
    if any(transport.values()) or measured["statuses"] != {
            str(expected): measured["requests"]} or not measured["requests"]:
        raise ValueError(f"invalid measured responses: {measured}")
    status_errors = measured["requests"] if expected >= 400 else 0
    if measured["errors"]["status"] != status_errors:
        raise ValueError(f"invalid measured responses: {measured}")


def measure(context, process, workload):
    options, task = context.options, workload.request
    lua = context.temporary / "request.lua"
    script(lua, task.method, task.body)
    evidence = probe(context, workload)
    load = {"threads": options.threads, "connections": options.connections,
            "seconds": options.seconds}
    old_affinity = os.sched_getaffinity(0)
    os.sched_setaffinity(0, options.load_cpus)
    try:
        warmup = options.generator.run(context.port, task.path, task.headers,
                                        {**load, "seconds": options.warmup}, lua)
        validate_measured(warmup, task.expected)
        before = snapshot(process.pid)
        tracker = PeakRss(process.pid)
        tracker.start()
        try:
            result = options.generator.run(context.port, task.path, task.headers, load, lua)
        finally:
            peak = tracker.finish()
        after = snapshot(process.pid)
    finally:
        os.sched_setaffinity(0, old_affinity)
    validate_measured(result, task.expected)
    if before["pids"] != after["pids"]:
        raise ValueError("product process membership changed during measurement")
    post = probe(context, workload)
    wall, count = result["duration_us"] / 1e6, result["requests"]
    cpu = after["cpu_seconds"] - before["cpu_seconds"]
    return {"label": workload.label, "path": task.path, "expected_status": task.expected,
            "probe": evidence, "post_probe": post, "requests_per_second": count / wall,
            "cpu_seconds": cpu, "cpu_us_per_request": cpu * 1e6 / count,
            "peak_process_tree_rss_kib": peak, "process_pids": after["pids"], **result}
