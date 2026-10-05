#!/usr/bin/env python3
"""Qualify session-bound rule comparisons without changing active protection."""
import argparse
import crs_fixture_source as fixtures
import json
from pathlib import Path
import tempfile
import time
import uuid

import console_bootstrap_test as bootstrap
import console_e2e as helper
from crs_console_check import ATTACK, HEADERS, PASSWORD, login
from crs_management_check import prepare, request, status
from crs_restart_check import launch
from proxy_e2e import exchange


def review(port, cookie, csrf, source, revision):
    code, _, body = request(port, cookie, csrf, "review", {
        "source": source, "expected_revision": str(revision)})
    assert code == 200, (code, body)
    identifier = json.loads(body)["id"]
    deadline = time.monotonic() + 90
    while True:
        code, _, body = request(port, cookie, csrf, "review/result", {"id": identifier})
        assert code == 200, (code, body)
        result = json.loads(body)
        if result["state"] in ("complete", "failed"):
            return identifier, result
        assert time.monotonic() < deadline, result
        time.sleep(1)


def updated(port, cookie, csrf):
    identifier = uuid.uuid4().hex
    configuration = ('SecRuleUpdateTargetById 942100 "!ARGS:application_field"\n'
                     'SecRule REQUEST_URI "@streq /operator-test" '
                     '"id:123457,phase:1,deny,status:418"\n')
    code, _, body = request(port, cookie, csrf, "prepare", {
        "id": identifier, "kind": "update", "expected_revision": "1",
        "version": "4.30.0", "configuration": configuration})
    assert code == 200, (code, body)
    deadline = time.monotonic() + 90
    while True:
        observed = status(port, cookie, csrf)
        assert observed["revision"] == 1, observed
        candidate = next(row for row in observed["candidates"] if row and row["id"] == identifier)
        if candidate["state"] == "verified":
            return identifier
        assert candidate["state"] == "preparing", candidate
        assert time.monotonic() < deadline, candidate
        time.sleep(1)


def qualify(binary, source, root):
    credentials = bootstrap.initialize(str(binary), str(root / "data"), "crs-admin")
    owned, process, origin, port = launch(binary, root, source)
    with owned:
        bootstrap.change(helper, port, credentials, PASSWORD)
        cookie, csrf = login(port)
        before = status(port, cookie, csrf)
        current = before["current"]["id"]
        assert request(port, None, None, "review", {})[0] == 401
        assert request(port, cookie, None, "review", {})[0] == 400
        receipt, result = review(port, cookie, csrf, current, 1)
        assert result["kind"] == "review" and result["state"] == "complete", result
        comparison = result["comparison"]
        assert comparison["unchanged"] == 628 and comparison["count"] == 0, comparison
        assert result["baseline"] == before["current"]["artifact"], result
        candidate = prepare(port, cookie, csrf, before, "enforce")
        receipt, result = review(port, cookie, csrf, candidate, 1)
        assert result["state"] == "complete", result
        assert result["comparison"]["unchanged"] == 628 and result["comparison"]["count"] == 0
        assert result["artifact"]["settings"]["mode"] == "enforce", result
        candidate = updated(port, cookie, csrf)
        receipt, result = review(port, cookie, csrf, candidate, 1)
        assert result["state"] == "complete", result
        comparison = result["comparison"]
        assert comparison["added"] == 1 and comparison["modified"] == 1, comparison
        assert comparison["reordered"] == 0 and comparison["removed"] == 0, comparison
        assert comparison["after"]["target_exclusions"] == comparison["before"][
            "target_exclusions"] + 1, comparison
        changes = {row["id"]: row["kind"] for row in comparison["changes"] if row}
        assert changes == {123457: "added", 942100: "modified"}, changes
        assert not origin.requests and status(port, cookie, csrf)["revision"] == 1
        assert request(port, cookie, csrf, "test/result", {"id": receipt})[0] == 400
        other, other_csrf = login(port)
        assert request(port, other, other_csrf, "review/result", {"id": receipt})[0] == 400
        receipt, result = review(port, cookie, csrf, candidate, 0)
        assert result["state"] == "failed" and result["failure"] == "CrsSelectionConflict", result
        code, _, body = helper.request(port, "POST", "/console/api/audit/query",
                                      {"action": "crs.review"}, cookie, csrf)
        assert code == 200, (code, body)
        rows = json.loads(body)["rows"]
        assert len(rows) == 3 and all(row["subject"] == 1 for row in rows), rows
        assert "application_field" not in body.decode() and "operator-test" not in body.decode()
        data_port = int(process.args[process.args.index("--port") + 1])
        assert exchange(data_port, ATTACK, HEADERS)[0] == 200
        assert len(origin.requests) == 1
        assert helper.request(port, "POST", "/console/api/logout", {}, cookie, csrf)[0] == 200
        assert request(port, cookie, csrf, "review/result", {"id": receipt})[0] == 401


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    fixtures.arguments(parser)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-review-") as temporary:
        root = Path(temporary)
        binary = args.binary.resolve()
        qualify(binary, fixtures.resolve(binary, args, root), root)
    print("Rule comparisons: exact changes, conditional exclusion counts, redacted audit, "
          "unchanged publication, revision conflicts, session isolation and revocation pass.")


if __name__ == "__main__":
    main()
