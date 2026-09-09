#!/usr/bin/env python3
"""Real local Sibuna processes, replicated storage, external HTTP load generation.

No instrumentation is linked into Sibuna. Results include client/loopback costs;
these are not WAN, DDoS capacity, or global rate/replay guarantees.
"""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import multiprocessing
import pathlib
import statistics
import sys
import subprocess
import tempfile
import time

from run import ROOT, free_port, metadata, ready, record, request, stop

UA = "Mozilla/5.0 SibunaBenchmark"


def headers(ip="203.0.113.30", cookie=None):
    result = {"User-Agent": UA, "X-Forwarded-For": ip, "Accept": "application/json"}
    if cookie:
        result["Cookie"] = cookie
    return result


def session(port, ip="203.0.113.30"):
    status, _, body = request(port, "/__sibuna/challenge.json?path=/private", headers(ip))
    assert status == 200, (status, body)
    challenge = json.loads(body)
    bits = int(challenge["difficulty"])
    for nonce in range(1 << 24):
        digest = hashlib.sha256(f"{challenge['id']}:{nonce}".encode()).digest()
        if int.from_bytes(digest, "big") >> (256 - bits) == 0:
            break
    else:
        raise RuntimeError("no solution within benchmark limit")
    solution = json.dumps({"challenge_id": challenge["id"], "nonce": str(nonce)})
    status, reply, body = request(port, "/__sibuna/verify", headers(ip), "POST", solution)
    assert status == 200, (status, body)
    cookie = next(v for k, v in reply.items() if k.lower() == "set-cookie").split(";", 1)[0]
    return cookie, solution


def load_worker(port, cookie, count, path, expected):
    # Setup and warmup are outside each batch clock. Every response is
    # consumed and checked; a denial or connection failure is never throughput.
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hdr = headers(cookie=cookie)
    try:
        conn.request("GET", path, headers=hdr)
        resp = conn.getresponse()
        resp.read()
        if resp.status != expected:
            raise RuntimeError(f"warmup status {resp.status}, expected {expected}")
        start = time.perf_counter_ns()
        for _ in range(count):
            conn.request("GET", path, headers=hdr)
            resp = conn.getresponse()
            resp.read()
            if resp.status != expected:
                raise RuntimeError(f"load status {resp.status}, expected {expected}")
        return time.perf_counter_ns() - start
    finally:
        conn.close()


def measure(pool, ports, cookie, count, path, expected):
    rates, spans = [], []
    for _ in range(7):
        start = time.perf_counter_ns()
        futures = [pool.submit(load_worker, port, cookie, count, path, expected)
                   for port in ports for _ in range(2)]
        durations = [f.result(timeout=30) for f in futures]
        elapsed = time.perf_counter_ns() - start
        rates.append(len(futures) * count * 1e9 / elapsed)
        spans.append(max(durations) / count)
    return {"path": path, "expected_status": expected, "batches": 7,
            "requests_per_batch": len(ports) * 2 * count,
            "requests_per_second_median": statistics.median(rates),
            "requests_per_second_min": min(rates), "requests_per_second_max": max(rates),
            "slowest_client_ns_per_request_median": statistics.median(spans)}


def propagate_ban(ports, ip):
    start = time.perf_counter_ns()
    assert request(ports[0], "/__sibuna/honeypot", headers(ip))[0] == 403
    deadline = time.monotonic() + 30
    pending = set(ports[1:])
    while pending and time.monotonic() < deadline:
        for port in list(pending):
            if request(port, "/private", headers(ip))[0] == 403:
                pending.remove(port)
        if pending:
            time.sleep(0.02)
    assert not pending, "reputation did not propagate"
    return (time.perf_counter_ns() - start) / 1e6


def storage_metrics(port):
    status, _, body = request(port, "/__sibuna/metrics")
    assert status == 200
    values = {}
    for line in body.decode().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split()
            values[key] = int(value)
    return values


def ingest(ports, cookie):
    # The authenticated-WAF startup probe emitted one incident on each node.
    deadline = time.monotonic() + 30
    while any(storage_metrics(p)["sibuna_incidents_persisted_total"] < 1 for p in ports):
        if time.monotonic() > deadline:
            raise TimeoutError("initial incident did not persist")
        time.sleep(.05)
    def phase(count, rate):
        before = [storage_metrics(p) for p in ports]
        def emit(port):
            start = time.monotonic()
            for i in range(count):
                if rate:
                    time.sleep(max(0, start + i / rate - time.monotonic()))
                assert request(port, "/?q=%3Cscript%3E", headers(cookie=cookie))[0] == 403
        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(len(ports)) as clients:
            list(clients.map(emit, ports))
        emission_seconds = time.monotonic() - start
        deadline = time.monotonic() + 60
        while True:
            after = [storage_metrics(p) for p in ports]
            persisted = sum(a["sibuna_incidents_persisted_total"] - b["sibuna_incidents_persisted_total"]
                            for a, b in zip(after, before))
            dropped = sum(a["sibuna_incidents_dropped_total"] - b["sibuna_incidents_dropped_total"]
                          for a, b in zip(after, before))
            if persisted + dropped == count * len(ports):
                break
            if time.monotonic() > deadline:
                raise TimeoutError(f"unaccounted incidents: emitted={count*len(ports)}, persisted={persisted}, dropped={dropped}")
            time.sleep(.1)
        elapsed = time.monotonic() - start
        batches = sum(a["sibuna_incident_batches_total"] - b["sibuna_incident_batches_total"]
                      for a, b in zip(after, before))
        return {"emitted": count*len(ports), "persisted": persisted, "dropped": dropped,
                "emission_seconds": emission_seconds, "drained_seconds": elapsed,
                "persisted_per_second_including_emission": persisted/elapsed,
                "transactions": batches, "mean_records_per_transaction": persisted/batches if batches else 0}
    sustained = phase(400, 80)
    assert sustained["dropped"] == 0, sustained
    burst = phase(1000, None)
    assert request(ports[0], "/private", headers(cookie=cookie))[0] == 200
    return {"sustained": sustained, "burst": burst,
            "scope": "Three issuers, 240 offered incidents/s for five seconds, followed by 3000-event burst; bounded local experiment"}


def tls_material(temp):
    def openssl(*args):
        subprocess.run(["openssl", *args], cwd=temp, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=Sibuna Benchmark CA", "-keyout", "ca.key", "-out", "ca.crt")
    (temp / "extensions").write_text(
        "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n")
    for i in range(3):
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN=zaxon-node-{i + 1}",
                "-keyout", f"node{i}.key", "-out", f"node{i}.csr")
        openssl("x509", "-req", "-in", f"node{i}.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
                "-CAcreateserial", "-days", "1", "-extfile", "extensions",
                "-out", f"node{i}.crt")


def run_profile(profile, clustered, count, tls=False, ingestion=False):
    with tempfile.TemporaryDirectory(prefix="sibuna-distributed-") as temp:
        temp = pathlib.Path(temp)
        seed, psk = temp / "seed", temp / "psk"
        seed.write_text("42" * 32)
        psk.write_text("sibuna-local-benchmark-psk-32-bytes")
        if tls:
            tls_material(temp)
        ports, peers = [free_port() for _ in range(3)], [free_port() for _ in range(3)]
        procs, logs = [], []
        try:
            for i in range(3):
                args = [str(ROOT / "zig-out/bin/sibuna"), "--host", "127.0.0.1",
                        "--port", str(ports[i]), "--workers", "2", "--mode", "forward_auth",
                        "--algorithm", "hashcash", "--difficulty", "8", "--" + profile,
                        "--secret-file", str(seed), "--rate-limit", "100000000",
                        "--idle-timeout", "2"]
                if clustered:
                    args += ["--data-dir", str(temp / f"node{i}"), "--cluster-node", str(i + 1),
                             "--cluster-listen", f"127.0.0.1:{peers[i]}",
                             "--cluster-secret-file", str(psk), "--storage-poll-ms", "100"]
                    if tls:
                        args += ["--cluster-tls-cert", str(temp / f"node{i}.crt"),
                                 "--cluster-tls-key", str(temp / f"node{i}.key"),
                                 "--cluster-tls-ca", str(temp / "ca.crt")]
                    for j in range(3):
                        if i != j:
                            args += ["--cluster-peer", f"{j + 1}@127.0.0.1:{peers[j]}"]
                log = (temp / f"node{i}.log").open("w+")
                logs.append(log)
                procs.append(subprocess.Popen(args, cwd=ROOT, stdout=log, stderr=log))
            for proc, port in zip(procs, ports):
                ready(proc, port, timeout=90)
            cookie, solution = session(ports[0])
            for port in ports:
                assert request(port, "/private", headers(cookie=cookie))[0] == 200
                expected = 403 if profile == "shield" else 200
                assert request(port, "/?q=%3Cscript%3E", headers(cookie=cookie))[0] == expected
            # Audit actual replay scope rather than assuming shared seed means
            # a globally shared spent set. This limitation is recorded explicitly.
            replay = request(ports[1], "/__sibuna/verify", headers(), "POST", solution)[0]
            assert replay == (400 if clustered else 200), ("unexpected replay scope", replay)
            result = {"profile": profile, "clustered": clustered, "nodes": 3,
                      "workers_per_node": 2, "transport": ("loopback mTLS" if tls else "loopback PSK") if clustered else None,
                      "cross_node_session": "passed", "authenticated_waf": "passed",
                      "cross_node_solution_replay_status": replay,
                      "replay_scope": "issuer-bound in cluster mode; verification requires sticky routing",
                      "rss_kb": [int(subprocess.check_output(
                          ["ps", "-o", "rss=", "-p", str(p.pid)], text=True)) for p in procs]}
            ctx = multiprocessing.get_context("spawn")
            with concurrent.futures.ProcessPoolExecutor(max_workers=6, mp_context=ctx) as pool:
                # Bring up client processes before the measured batches.
                list(pool.map(int, range(6)))
                result["admitted"] = measure(pool, ports, cookie, count, "/private", 200)
                result["challenged"] = measure(pool, ports, None, count, "/private", 401)
                if clustered:
                    if ingestion:
                        result["incident_ingestion"] = ingest(ports, cookie)
                    result["ban_propagation_ms"] = propagate_ban(ports, "198.51.100.77")
                    leaders = []
                    for i, log in enumerate(logs):
                        log.flush()
                        log.seek(0)
                        if "became leader; writes are ready" in log.read():
                            leaders.append(i)
                    assert leaders, "no elected leader found in startup logs"
                    leader = leaders[-1]
                    result["stopped_leader_node"] = leader + 1
                    stop(procs[leader])
                    survivors = [port for i, port in enumerate(ports) if i != leader]
                    result["one_node_down"] = measure(pool, survivors, cookie, count,
                                                      "/private", 200)
                    result["post_failover_ban_propagation_ms"] = propagate_ban(
                        survivors, "198.51.100.78")
            # Healthy HTTP alone can hide a failed background storage node.
            # Inspect externally, after measurement, without daemon hooks.
            for i, log in enumerate(logs):
                log.flush()
                log.seek(0)
                contents = log.read()
                assert "ChainMismatch" not in contents and "chain mismatch" not in contents, (
                    f"node {i + 1}: storage chain validation failed")
            result["storage_chain_log_check"] = "passed"
            return result
        except Exception as error:
            captured = []
            for i, log in enumerate(logs):
                log.flush()
                log.seek(0)
                captured.append(f"node {i + 1} log:\n{log.read()[-12000:]}")
            raise RuntimeError(f"{error}\n" + "\n".join(captured)) from error
        finally:
            for proc in procs:
                stop(proc)
            for log in logs:
                log.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--ingestion", action="store_true", help="also test sustained incidents and overload accounting")
    args = parser.parse_args()
    if not 1 <= args.requests <= 200:
        parser.error("--requests must be 1..200 to keep batches below the connection limit")
    subprocess.run(["zig", "build", "-Dcluster=true", "-Doptimize=ReleaseFast"],
                   cwd=ROOT, check=True)
    data = {"meta": metadata(), "runs": [], "limitations": [
        "One host, loopback, forward-auth; excludes origin proxy and client-facing TLS/WAN costs",
        "External Python clients; batch throughput includes client and IPC overhead",
        "No per-request benchmark clocks, allocations, or hooks in the daemon",
        "Rate limits and spent sets are local; cluster challenges require issuer routing",
        "Existing policy continues on quorum loss; fresh policy needs consensus",
    ]}
    for profile, clustered, tls in [("gate", False, False), ("shield", False, False),
                                    ("shield", True, False), ("shield", True, True)]:
        print(f"Measuring {profile}, clustered={clustered}, tls={tls}", flush=True)
        try:
            result = run_profile(profile, clustered, args.requests, tls, args.ingestion)
            result["status"] = "passed"
            data["runs"].append(result)
        except Exception as error:
            print(str(error), file=sys.stderr, flush=True)
            data["runs"].append({"profile": profile, "clustered": clustered,
                                 "tls": tls, "status": "failed", "error": str(error)})
    record(data, "distributed-latest")
    if any(run["status"] == "failed" for run in data["runs"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
