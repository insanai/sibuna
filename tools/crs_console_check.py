"""Verify saved findings from a signed release through authenticated console reads."""
from contextlib import ExitStack
import http.client
import json
import threading
import time

import console_bootstrap_test as bootstrap
import console_e2e as helper
from proxy_e2e import exchange
from proxy_fixture import origin

HEADERS = {"Host": "example.test", "User-Agent": "Mozilla/5.0", "Accept": "text/html"}
ATTACK = "/ordinary?q=1%27%20OR%20%271%27=%271&token=private-crs-value"
PASSWORD = "CRS console qualification passphrase"


def start(binary, source, root, console_port, mode, logfile, extra=()):
    with ExitStack() as owned:
        application, worker = origin()
        owned.callback(worker.join, 5)
        owned.callback(application.server_close)
        owned.callback(application.shutdown)
        policy = root / "console-policy.json"
        policy.write_text(json.dumps({"waf": False, "default_action": "ALLOW", "rules": [
            {"name": "fixture-admission", "path": "*", "action": "ALLOW"}]}))
        process = helper.start(str(binary), str(root / "console-data"), console_port, logfile,
                               extra=("--upstream-port", str(application.server_port),
                                      "--policy-file", str(policy), "--crs-mode", mode,
                                      "--crs-dir", str(source), "--crs-slots", "2",
                                      "--console-capture-heads", *extra))
        owned.callback(helper.stop, process)
        return owned.pop_all(), process, application


def login(port):
    status, headers, body = helper.request(port, "POST", "/console/api/login", {
        "username": "crs-admin", "password": PASSWORD})
    assert status == 200, body
    return headers["Set-Cookie"].split(";", 1)[0], json.loads(body)["csrf"]


def findings(port, cookie, csrf, category):
    endpoint = "/console/api/events/query"
    assert helper.request(port, "POST", endpoint, {})[0] == 401
    assert helper.request(port, "POST", endpoint, {}, cookie)[0] == 400
    deadline = time.monotonic() + 15
    while True:
        status, _, body = helper.request(port, "POST", endpoint,
                                        {"category": category}, cookie, csrf)
        assert status == 200, body
        assert b"private-crs-value" not in body and b"secret" not in body, body
        rows = json.loads(body)["rows"]
        if any(row["crs"] and row["crs"]["would_deny"] for row in rows):
            return rows
        assert time.monotonic() < deadline, rows
        time.sleep(0.05)


def node_status(port, cookie, mode, evidence):
    status, _, body = helper.request(port, "GET", "/console/api/nodes/local", cookie=cookie)
    assert status == 200, body
    observed = json.loads(body)["crs"]
    selected, counts = observed["selection"], observed["counts"]
    assert selected["mode"] == mode and selected["profile"] == "full", selected
    assert selected["release"] == "4.30.0" and selected["revision"] == 1, selected
    assert selected["source_digest"] == evidence["source_digest"], selected
    assert len(selected["operator_digest"]) == 64, selected
    assert selected["inbound_threshold"] == 5 and selected["outbound_threshold"] == 4
    assert int(selected["reserved_bytes"]) > 0 and int(selected["compiled_peak"]) > 0
    assert selected["slots"] == 2 and selected["request_bytes"] == 4194304
    assert selected["response_bytes"] == 1048576 and selected["work_budget"] == 16000000
    assert selected["timeout_ms"] == 30000
    assert int(counts["would_deny" if mode == "audit" else "denied"]) == 1, counts


def tuned(binary, source, root, port):
    with (root / "console-tuned.log").open("w+") as logfile:
        owned, process, application = start(binary, source, root, port, "enforce", logfile,
                                           ("--crs-inbound-threshold", "9",
                                            "--crs-outbound-threshold", "8"))
        with owned:
            cookie, csrf = login(port)
            data_port = int(process.args[process.args.index("--port") + 1])
            status, _, body = exchange(data_port, ATTACK, HEADERS)
            assert status == 200 and len(application.requests) == 1, (status, body[:128])
            status, _, body = helper.request(port, "GET", "/console/api/nodes/local",
                                             cookie=cookie)
            assert status == 200, body
            observed = json.loads(body)["crs"]
            selection = observed["selection"]
            assert selection["mode"] == "enforce" and selection["revision"] == 1
            assert selection["inbound_threshold"] == 9 and selection["outbound_threshold"] == 8
            assert observed["counts"]["denied"] == 0
            assert observed["counts"]["inspected"] == 1
            assert helper.request(port, "POST", "/console/api/logout", {}, cookie, csrf)[0] == 200


def stop_while_reading(process, port, cookie):
    """The storage owner is a publisher reader through the final shutdown tick."""
    finished = threading.Event()
    started = threading.Event()
    failures = []

    def read():
        while not finished.wait(0.02):
            try:
                status, _, body = helper.request(port, "GET", "/console/api/nodes/local",
                                                 cookie=cookie)
                if status == 200:
                    assert json.loads(body)["crs"]["selection"] is not None
                    started.set()
                else:
                    assert status in (429, 503), (status, body[:128])
            except (OSError, http.client.HTTPException):
                # Listener cancellation may interrupt a read; a crash is checked by stop().
                pass
            except Exception as error:
                failures.append(error)
                return

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        assert started.wait(5), "CRS status observation never started"
        helper.stop(process)
    finally:
        finished.set()
        reader.join(5)
    assert not reader.is_alive() and not failures, failures


def qualify(binary, source, root):
    credentials = bootstrap.initialize(str(binary), str(root / "console-data"), "crs-admin")
    port = helper.port()
    audit_ids = set()
    for mode in ("audit", "enforce"):
        with (root / f"console-{mode}.log").open("w+") as logfile:
            owned, process, application = start(binary, source, root, port, mode, logfile)
            with owned:
                if mode == "audit":
                    bootstrap.change(helper, port, credentials, PASSWORD)
                cookie, csrf = login(port)
                data_port = int(process.args[process.args.index("--port") + 1])
                status, _, body = exchange(data_port, ATTACK, HEADERS)
                assert status == (200 if mode == "audit" else 403), (status, body[:128])
                assert len(application.requests) == (1 if mode == "audit" else 0)
                category = "audit:crs" if mode == "audit" else "waf:crs"
                rows = findings(port, cookie, csrf, category)
                node_status(port, cookie, mode, rows[0]["crs"])
                for row in rows:
                    evidence = row["crs"]
                    assert evidence is not None and row["path"] == "/ordinary", row
                    assert evidence["enforcing"] == (mode == "enforce"), evidence
                    assert evidence["denied"] == (mode == "enforce"), evidence
                    assert evidence["coverage"] == (
                        "inspected" if mode == "audit" else "local_response"), evidence
                    assert evidence["revision"] == "1" and len(evidence["source_digest"]) == 64
                    assert row["campaign"] is None and row["capture"] is None
                    status, _, body = helper.request(port, "POST", "/console/api/events/heads",
                                                    {"id": row["id"]}, cookie, csrf)
                    assert status == 200, body
                    captured = json.loads(body)
                    request = bytes.fromhex(captured["request"])
                    response = bytes.fromhex(captured["response"])
                    assert captured["recorded"] and b"private-crs-value" not in request
                    assert b"[redacted]" in request and b"private-crs-value" not in response
                    assert captured["response_state"] == (
                        "captured" if mode == "audit" else "local"), captured
                if mode == "audit":
                    audit_ids = {row["id"] for row in rows}
                else:
                    retained = findings(port, cookie, csrf, "audit:crs")
                    saved_audit = {row["id"] for row in retained if not row["crs"]["enforcing"]}
                    assert audit_ids == saved_audit, retained
                if mode == "enforce":
                    stop_while_reading(process, port, cookie)
                    continue
                assert helper.request(port, "POST", "/console/api/logout", {},
                                      cookie, csrf)[0] == 200
                assert helper.request(port, "POST", "/console/api/events/query", {},
                                      cookie, csrf)[0] == 401
    tuned(binary, source, root, port)
    print("Signed CRS audit/denial evidence, threshold tuning, local status, "
          "secret omission, restart and revocation pass.")
