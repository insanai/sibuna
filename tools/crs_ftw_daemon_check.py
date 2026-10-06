#!/usr/bin/env python3
"""Run the pinned CRS FTW corpus through the actual daemon, a live origin and console evidence.

Every test owns one loopback source address, so saved findings are attributed through the
console's exact client-address filter. Log markers would add headers that rules inspect.
Regex log assertions remain coverage gaps because Sibuna retains rule IDs, not log lines.
Linux is required: other platforms do not route all of 127.0.0.0/8 to loopback.
"""
import argparse
import base64
from collections import Counter
from contextlib import ExitStack
import io
import json
from pathlib import Path
import re
import select
import socket
import socketserver
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid

import yaml

import console_bootstrap_test as bootstrap
import console_e2e as helper
import crs_fixture_source as fixtures
from crs_console_check import PASSWORD, login
from crs_ftw_check import COMMIT, SOURCE_DIGEST, normalize, source_bytes
from crs_management_check import request, select as select_candidate, status

# The pinned corpus's README prescribes these TX settings; tools/crs_ftw_probe.zig
# compiles the same text, so engine and daemon evidence share one configuration.
CONFIGURATION = r"""SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
 "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" \
 "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecAction "id:900005,phase:1,nolog,pass,ctl:ruleRemoveById=910000,\
setvar:tx.crs_validate_utf8_encoding=1,setvar:tx.arg_name_length=100,\
setvar:tx.arg_length=400,setvar:tx.total_arg_length=64000,\
setvar:tx.max_num_args=255,setvar:tx.max_file_size=64100,\
setvar:tx.combined_file_sizes=65535,setvar:tx.reporting_level=4"
"""
RESPONSE_LIMIT = 4 * 1024 * 1024


REPEAT = re.compile(r'\{\{\s*"([^"]*)"\s*\|\s*repeat\s+(\d+)\s*\}\}')


def render(text):
    # go-ftw renders sprig's `repeat` in fixture data; 920400 relies on it for its size.
    return REPEAT.sub(lambda match: match[1] * int(match[2]), text)


def stage(source, output):
    if isinstance(source.get("data"), str):
        source = dict(source, data=render(source["data"]))
    if "encoded_request" in source:
        payload = base64.b64decode(source["encoded_request"])
    else:
        case = normalize(source, 0)
        head = case["line"] + "\r\n" + "".join(
            f'{header["name"]}: {header["value"]}\r\n' for header in case["headers"])
        payload = (head + "\r\n").encode() + case["body"].encode()
    log = output.get("log", {})
    expected = output.get("status")
    return dict(payload=payload, expected=log.get("expect_ids", []),
                forbidden=log.get("no_expect_ids", []),
                status=[expected] if isinstance(expected, int) else expected,
                regex=bool(set(log) - {"expect_ids", "no_expect_ids"}),
                expect_error=output.get("expect_error", False))


def corpus(data):
    tests, files = [], 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in sorted(archive.getmembers(), key=lambda entry: entry.name):
            if "/tests/regression/tests/" not in member.name or not member.name.endswith(".yaml"):
                continue
            if not member.isfile() or member.size > 2 * 1024 * 1024:
                raise ValueError("invalid FTW fixture member")
            files += 1
            document = yaml.safe_load(archive.extractfile(member)) or {}
            for test in document.get("tests", []) or []:
                tests.append(dict(test=f'{document["rule_id"]}-{test["test_id"]}',
                                  response="/RESPONSE-" in member.name,
                                  stages=[stage(item["input"], item["output"])
                                          for item in test["stages"]]))
    if files != 326 or len(tests) != 5193:
        raise ValueError("FTW inventory drift")
    return tests


class Relay(socketserver.ThreadingTCPServer):
    """Counts request bytes that reach the origin; denied requests must contribute none."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, upstream):
        self.upstream, self.forwarded, self.lock = upstream, 0, threading.Lock()
        super().__init__(("127.0.0.1", 0), RelayHandler)

    def count(self, size):
        with self.lock:
            self.forwarded += size

    def total(self):
        with self.lock:
            return self.forwarded


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        with socket.create_connection(("127.0.0.1", self.server.upstream), timeout=30) as origin:
            peers = {self.request: origin, origin: self.request}
            while True:
                readable, _, _ = select.select(list(peers), [], [], 60)
                if not readable:
                    return
                for side in readable:
                    data = side.recv(65536)
                    if not data:
                        return
                    if side is self.request:
                        self.server.count(len(data))
                    peers[side].sendall(data)


def address(index):
    # 127.0.0.1 stays free for the console and calibration traffic.
    return f"127.{10 + index // 65024}.{index // 254 % 256}.{1 + index % 254}"


def exchange(port, source, payload, timeout):
    with socket.socket() as connection:
        connection.settimeout(timeout)
        connection.bind((source, 0))
        connection.connect(("127.0.0.1", port))
        try:
            connection.sendall(payload)
        except OSError as error:
            # An early refusal can close before the whole body is accepted.
            if not isinstance(error, (BrokenPipeError, ConnectionResetError)):
                raise
        return response(connection)


def response(connection):
    data = b""
    try:
        while b"\r\n\r\n" not in data and len(data) < RESPONSE_LIMIT:
            chunk = connection.recv(65536)
            if not chunk:
                break
            data += chunk
    except (ConnectionResetError, socket.timeout):
        pass
    match = re.match(rb"HTTP/\d\.\d (\d{3})", data)
    if not match:
        return None, data[:256].decode("latin-1")
    head, _, body = data.partition(b"\r\n\r\n")
    length = re.search(rb"(?im)^content-length:\s*(\d+)\s*$", head)
    try:
        if length:
            while len(body) < int(length[1]):
                chunk = connection.recv(65536)
                if not chunk:
                    break
                body += chunk
        elif re.search(rb"(?im)^transfer-encoding:.*chunked", head):
            while not body.endswith(b"0\r\n\r\n"):
                chunk = connection.recv(65536)
                if not chunk:
                    break
                body += chunk
    except (ConnectionResetError, socket.timeout):
        pass
    return int(match[1]), None


def drain(port, settled=3):
    # The incident queue is bounded and counts overflow instead of blocking traffic.
    # Waiting for storage to catch up keeps every saved finding attributable.
    stable, previous = 0, None
    deadline = time.monotonic() + 120
    while stable < settled:
        observed = metrics(port)
        if observed["sibuna_incidents_dropped_total"]:
            raise AssertionError("incident evidence dropped; the run is not attributable")
        persisted = observed["sibuna_incidents_persisted_total"]
        stable = stable + 1 if persisted == previous else 0
        previous = persisted
        if time.monotonic() > deadline:
            raise AssertionError("incident persistence did not settle")
        time.sleep(0.06)
    return observed


def run(tests, port, relay, timeout):
    rows = []
    for index, test in enumerate(tests):
        if index % 16 == 0:
            drain(port)
        source = address(index)
        before = relay.total()
        started = time.monotonic()
        stages = []
        for item in test["stages"]:
            try:
                code, error = exchange(port, source, item["payload"], timeout)
            except OSError as failure:
                code, error = None, f"{type(failure).__name__}: {failure}"
            stages.append(dict(status=code, error=error))
        rows.append(dict(test=test["test"], address=source, stages=stages,
                         origin_bytes=relay.total() - before,
                         seconds=round(time.monotonic() - started, 4)))
        if index % 500 == 499:
            print(f"daemon FTW: {index + 1}/{len(tests)} sent", flush=True)
    return rows


def metrics(port):
    connection = socket.create_connection(("127.0.0.1", port), timeout=10)
    with connection:
        connection.sendall(b"GET /__sibuna/metrics HTTP/1.1\r\nHost: metrics.test\r\n"
                           b"Connection: close\r\n\r\n")
        data = b""
        while chunk := connection.recv(65536):
            data += chunk
    values = re.findall(rb"(?m)^(sibuna_\w+) (\d+)$", data)
    return {name.decode(): int(value) for name, value in values}


class Sessions:
    """Rotates authenticated sessions so reads respect, not bypass, per-session budgets."""

    def __init__(self, port, count):
        self.port, self.index, self.unavailable = port, 0, 0
        self.sessions = [self.login() for _ in range(count)]

    def login(self):
        # The account limiter refuses bursts; waiting keeps that defence intact.
        while True:
            code, headers, body = helper.request(self.port, "POST", "/console/api/login", {
                "username": "crs-admin", "password": PASSWORD})
            if code != 429:
                assert code == 200, body
                return headers["Set-Cookie"].split(";", 1)[0], json.loads(body)["csrf"]
            time.sleep(5)

    def query(self, body):
        deadline = time.monotonic() + 20
        while True:
            cookie, csrf = self.sessions[self.index % len(self.sessions)]
            self.index += 1
            code, _, reply = helper.request(self.port, "POST", "/console/api/events/query",
                                            body, cookie, csrf)
            if code == 429:
                time.sleep(60 / (120 * len(self.sessions)))
                continue
            # 503 is the console's fail-closed reply when storage cannot answer in time.
            if code == 503 and time.monotonic() < deadline:
                self.unavailable += 1
                time.sleep(0.5)
                continue
            if code == 503:
                return None
            assert code == 200, (code, reply[:256])
            return json.loads(reply)


def findings(sessions, source):
    found, body = [], {"ip": source, "limit": 10}
    while True:
        page = sessions.query(body)
        if page is None:
            return None
        found.extend(row["crs"] for row in page["rows"] if row.get("crs"))
        if not page.get("next"):
            return found
        body = dict(body, before=page["next"])


def prepare(port, cookie, csrf, settings):
    current = status(port, cookie, csrf)
    identifier = uuid.uuid4().hex
    code, _, reply = request(port, cookie, csrf, "prepare", {
        "id": identifier, "kind": "update", "version": "4.30.0",
        "expected_revision": str(current["revision"]), "settings": settings,
        "configuration": CONFIGURATION})
    assert code == 200, (code, reply)
    deadline = time.monotonic() + 300
    while True:
        observed = status(port, cookie, csrf)
        job = next(row for row in observed["candidates"] if row and row["id"] == identifier)
        if job["state"] == "verified":
            return identifier, current["revision"]
        assert job["state"] == "preparing", job
        assert time.monotonic() < deadline, job
        time.sleep(1)


def evaluate(test, row, observed):
    errors, gaps = [], []
    if observed is None:
        errors.append("console evidence page unavailable")
        observed = []
    ids = sorted({finding["rule_id"] for finding in observed})
    for item, outcome in zip(test["stages"], row["stages"]):
        if item["regex"]:
            gaps.append("regex log assertion")
        if item["expect_error"]:
            if outcome["status"] is not None:
                errors.append(f"expected transport error, observed {outcome['status']}")
        elif outcome["status"] is None:
            errors.append(f"no HTTP response: {outcome['error']}")
        elif item["status"] and outcome["status"] not in item["status"]:
            errors.append(f"status {outcome['status']} not in {item['status']}")
    expected = {value for item in test["stages"] for value in item["expected"]}
    forbidden = {value for item in test["stages"] for value in item["forbidden"]}
    missing, unexpected = sorted(expected - set(ids)), sorted(forbidden & set(ids))
    phases = {finding["phase"] for finding in observed if finding["would_deny"]}
    denied = any(outcome["status"] == 403 for outcome in row["stages"])
    # A request-phase refusal must leave the origin untouched; response denials follow
    # a legitimate delivery and are excluded from this boundary check.
    leaked = denied and phases and max(phases) <= 2 and row["origin_bytes"] > 0
    return dict(row, ids=ids, missing=missing, unexpected=unexpected, errors=errors,
                gaps=gaps, leaked=bool(leaked),
                passed=not (missing or unexpected or errors or leaked))


def engine_rows(paths):
    rows = {}
    for path in paths or []:
        report = json.loads(path.read_text())
        if report.get("commit") != COMMIT or report.get("source_sha256") != SOURCE_DIGEST:
            raise ValueError("engine report provenance mismatch")
        rows.update((row["test"], row) for row in report["rows"])
    return rows


def classify(results, engine, budget):
    # Disagreement with an upstream assertion is only a connector defect when the
    # daemon also differs from the engine's evidence for the same serialized request.
    for result in results:
        reference = engine.get(result["test"])
        if result["passed"]:
            result["class"] = "passed"
        elif result["leaked"]:
            result["class"] = "origin boundary"
        elif reference is None:
            result["class"] = "daemon only"
        elif reference["work"] > budget:
            result["class"] = "work budget"
        elif reference["error"] is not None and not result["ids"] and not result["errors"]:
            # Strict acquisition refusals are deliberate engine contracts, not connector loss.
            result["class"] = "engine refusal"
        elif reference["error"] is None and sorted(reference["ids"]) == result["ids"] and \
                not result["errors"]:
            result["class"] = "engine agrees"
        else:
            result["class"] = "connector difference"
    return Counter(result["class"] for result in results)


def daemon(binary, candidate, root, origin_port, console_port, owned):
    policy = root / "policy.json"
    policy.write_text(json.dumps({"waf": False, "default_action": "ALLOW", "rules": [
        {"name": "ftw", "path": "*", "action": "ALLOW"}]}))
    logfile = owned.enter_context((root / "daemon.log").open("w+"))
    process = helper.start(str(binary), str(root / "data"), console_port, logfile, workers=4,
                           extra=("--upstream-port", str(origin_port),
                                  "--policy-file", str(policy), "--storage-poll-ms", "50",
                                  "--crs-mode", "audit", "--crs-dir", str(candidate)))
    owned.callback(helper.stop, process)
    return int(process.args[process.args.index("--port") + 1])


def qualify(args, root, tests, owned):
    candidate = fixtures.resolve(args.binary, args, root)
    albedo_port = helper.port()
    albedo = subprocess.Popen([str(args.albedo), "--bind", "127.0.0.1", "--port",
                               str(albedo_port)], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    owned.callback(albedo.wait, 10)
    owned.callback(albedo.terminate)
    relay = Relay(albedo_port)
    threading.Thread(target=relay.serve_forever, daemon=True).start()
    owned.callback(relay.server_close)
    owned.callback(relay.shutdown)
    credentials = bootstrap.initialize(str(args.binary), str(root / "data"), "crs-admin")
    console_port = helper.port()
    port = daemon(args.binary, candidate, root, relay.server_address[1], console_port, owned)
    bootstrap.change(helper, console_port, credentials, PASSWORD)
    cookie, csrf = login(console_port)
    settings = dict(status(console_port, cookie, csrf)["current"]["artifact"]["settings"],
                    mode=args.mode, blocking_paranoia=4, detection_paranoia=4,
                    work_budget=args.work_budget)
    identifier, revision = prepare(console_port, cookie, csrf, settings)
    select_candidate(console_port, cookie, csrf, identifier, revision, args.mode)
    calibration = exchange(port, "127.0.0.1", b"GET / HTTP/1.1\r\nHost: localhost\r\n"
                           b"User-Agent: OWASP CRS test agent\r\nAccept: text/xml,application/"
                           b"xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,"
                           b"image/png,*/*;q=0.5\r\nConnection: close\r\n\r\n", args.timeout)
    assert calibration == (200, None), calibration
    rows = run(tests, port, relay, args.timeout)
    counters = drain(port, settled=10)
    sessions = Sessions(console_port, args.sessions)
    results = [evaluate(test, row, findings(sessions, row["address"]))
               for test, row in zip(tests, rows)]
    counters["console_unavailable_retries"] = sessions.unavailable
    return results, counters


def report(args, tests, results, counters):
    classes = classify(results, engine_rows(args.engine_report), args.work_budget)
    slowest = sorted(results, key=lambda result: -result["seconds"])[:10]
    summary = dict(
        commit=COMMIT, source_sha256=SOURCE_DIGEST, inventory=len(results), mode=args.mode,
        paranoia=4, work_budget=args.work_budget, classes=classes,
        passed=classes["passed"], status_assertions=sum(
            bool(item["status"]) for test in tests for item in test["stages"]),
        regex_gaps=sum(bool(result["gaps"]) for result in results),
        dropped_incidents=counters.get("sibuna_incidents_dropped_total"),
        console_unavailable_retries=counters.get("console_unavailable_retries"),
        crs_counters={name: value for name, value in counters.items() if "_crs_" in name},
        slowest=[dict(test=row["test"], seconds=row["seconds"]) for row in slowest])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(dict(summary, rows=results), indent=1) + "\n")
    print(f"Daemon FTW ({args.mode}, PL4, work {args.work_budget}): "
          f"{summary['passed']}/{len(results)} passed; classes {dict(classes)}")
    print(f"Dropped incidents: {summary['dropped_incidents']}; "
          f"regex-log gaps: {summary['regex_gaps']}; report: {args.report}")
    defects = [row for row in results if row["class"] in ("origin boundary",
                                                          "connector difference")]
    if defects or summary["dropped_incidents"]:
        print("First connector defects:", json.dumps([
            {key: row[key] for key in ("test", "class", "ids", "missing", "unexpected",
                                       "errors", "origin_bytes")}
            for row in defects[:12]], indent=1))
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    fixtures.arguments(parser)
    parser.add_argument("--albedo", type=Path, required=True, help="Albedo 0.3.0 binary")
    parser.add_argument("--source-dir", type=Path, default=Path(".zig-cache/crs-review"))
    parser.add_argument("--engine-report", type=Path, action="append",
                        help="crs-ftw-check request or response report; repeatable")
    parser.add_argument("--report", type=Path,
                        default=Path(".zig-cache/crs-review/ftw-daemon-report.json"))
    parser.add_argument("--mode", choices=("audit", "enforce"), default="audit")
    parser.add_argument("--work-budget", type=int, default=16_000_000)
    parser.add_argument("--sessions", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--limit", type=int, help="run only the first N tests")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("per-test loopback addresses require Linux")
    tests = corpus(source_bytes(args.source_dir, args.download))[:args.limit]
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-ftw-daemon-") as temporary:
        with ExitStack() as owned:
            results, counters = qualify(args, Path(temporary), tests, owned)
    raise SystemExit(report(args, tests, results, counters))


if __name__ == "__main__":
    main()
