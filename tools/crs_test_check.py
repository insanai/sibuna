#!/usr/bin/env python3
"""Qualify owned, private phased tests against signed candidates and the real daemon."""
import argparse
import crs_fixture_source as fixtures
import gzip
import json
from pathlib import Path
import tempfile
import time

import console_bootstrap_test as bootstrap
import console_e2e as helper
from crs_console_check import ATTACK, HEADERS, PASSWORD, login
from crs_management_check import request, status
from crs_restart_check import launch
from proxy_e2e import exchange


def sample(target=ATTACK):
    return {"request": {"target": target, "headers": [
        {"name": key, "value": value} for key, value in HEADERS.items()]},
        "response": {"entity": {"body": "ordinary page"}}}


def submit(port, cookie, csrf, source, case, mode="enforce", revision="1"):
    code, _, body = request(port, cookie, csrf, "test", {
        "source": source, "expected_revision": revision, "mode": mode, "sample": case})
    assert code == 200, (code, body)
    return json.loads(body)["id"]


def result(port, cookie, csrf, identifier):
    deadline = time.monotonic() + 90
    while True:
        code, _, body = request(port, cookie, csrf, "test/result", {"id": identifier})
        assert code == 200, (code, body)
        observed = json.loads(body)
        if observed["state"] in ("complete", "failed"):
            return observed
        assert time.monotonic() < deadline, observed
        time.sleep(1)


def qualify(binary, source, root):
    credentials = bootstrap.initialize(str(binary), str(root / "data"), "crs-admin")
    owned, process, origin, port = launch(binary, root, source)
    with owned:
        bootstrap.change(helper, port, credentials, PASSWORD)
        cookie, csrf = login(port)
        before = status(port, cookie, csrf)
        identifier = before["current"]["id"]
        assert request(port, None, None, "test", {})[0] == 401
        assert request(port, cookie, None, "test", {})[0] == 400
        for mode in ("off", "audit", "enforce"):
            receipt = submit(port, cookie, csrf, identifier, sample(), mode)
            observed = result(port, cookie, csrf, receipt)
            assert observed["state"] == "complete", observed
            report = observed["report"]
            assert report["mode"] == mode and report["failure"] is None, report
            assert report["denied"] == (mode == "enforce"), report
            assert report["would_deny"] == (mode != "off"), report
            if mode != "off":
                assert report["inbound_score"] >= 5, report
                assert report["unlogged_matches"] > 0, report
                assert report["omitted_events"] == 0, report
                assert report["event_count"] < 16, report
            assert observed["source"] == identifier, observed
            assert observed["expected_revision"] == before["revision"], observed
            assert observed["artifact"]["source_digest"] == before["current"][
                "artifact"]["source_digest"], observed
            assert ATTACK not in json.dumps(observed) and "ordinary page" not in json.dumps(observed)
            assert result(port, cookie, csrf, receipt) == observed
            assert not origin.requests, "private test contacted the origin"
            assert status(port, cookie, csrf)["revision"] == before["revision"]
        compressed = sample("/ordinary")
        compressed["request"].update({"method": "POST", "entity": {
            "body_hex": gzip.compress(b"q=1%27%20OR%20%271%27=%271", mtime=0).hex()}})
        compressed["request"]["headers"] += [
            {"name": "Content-Type", "value": "application/x-www-form-urlencoded"},
            {"name": "Content-Encoding", "value": "gzip"}]
        receipt = submit(port, cookie, csrf, identifier, compressed)
        assert result(port, cookie, csrf, receipt)["report"]["denied"]
        receipt = submit(port, cookie, csrf, identifier, sample(), revision="0")
        failed = result(port, cookie, csrf, receipt)
        assert failed["state"] == "failed" and failed["failure"] == "CrsSelectionConflict", failed
        invalid = sample()
        invalid["request"]["headers"][0]["value"] = "private-sample\r\nInjected: bad"
        receipt = submit(port, cookie, csrf, identifier, invalid)
        failed = result(port, cookie, csrf, receipt)
        assert failed["state"] == "failed" and failed["failure"] == "InvalidRequest", failed
        assert "private-sample" not in json.dumps(failed)
        # A second valid administrator session cannot read this caller's result.
        other, other_csrf = login(port)
        assert request(port, other, other_csrf, "test/result", {"id": receipt})[0] == 400
        code, _, audit = helper.request(port, "POST", "/console/api/audit/query",
                                        {"action": "crs.test"}, cookie, csrf)
        assert code == 200, (code, audit)
        rows = json.loads(audit)["rows"]
        assert len(rows) == 4 and all(row["target"] == identifier for row in rows), rows
        assert "private-sample" not in audit.decode() and "ordinary page" not in audit.decode()
        data_port = int(process.args[process.args.index("--port") + 1])
        assert exchange(data_port, ATTACK, HEADERS)[0] == 200
        assert len(origin.requests) == 1 and status(port, cookie, csrf)["local"][
            "selection"]["mode"] == "audit"
        assert helper.request(port, "POST", "/console/api/logout", {}, cookie, csrf)[0] == 200
        assert request(port, cookie, csrf, "test/result", {"id": receipt})[0] == 401


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    fixtures.arguments(parser)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-test-") as temporary:
        root = Path(temporary)
        binary = args.binary.resolve()
        qualify(binary, fixtures.resolve(binary, args, root), root)
    print("Private CRS tests: signed sources, phased modes, compressed bodies, "
          "redacted audit, unchanged publication, isolated sessions and revocation pass.")


if __name__ == "__main__":
    main()
