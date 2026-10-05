#!/usr/bin/env python3
"""Qualify session-bound rule comparisons without changing active protection."""
import argparse
import crs_fixture_source as fixtures
import hashlib
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


def exclusions(port, cookie, csrf, identifier, result, side):
    offset, rows = 0, []
    summary = result["comparison"][side]
    expected = summary["target_exclusions"] + summary["runtime_exclusions"]
    while True:
        code, _, body = request(port, cookie, csrf, "review/exclusions", {
            "id": identifier, "side": side, "offset": offset})
        assert code == 200 and len(body) < 16384, (code, body)
        page = json.loads(body)
        assert page["id"] == identifier and page["expected_revision"] == 1, page
        page = page["page"]
        assert page["side"] == side and page["offset"] == offset, page
        assert page["total"] == expected and 0 <= page["count"] <= 8, page
        visible = [row for row in page["rows"] if row]
        assert len(visible) == page["count"] and len(visible) == min(8, expected - offset)
        for row in visible:
            for name in (row["key"], row["tag"]):
                if name and name["bytes"] <= 256:
                    decoded = bytes.fromhex(name["hex"])
                    assert len(decoded) == name["bytes"]
                    assert hashlib.sha256(decoded).hexdigest() == name["digest"]
        rows.extend(visible)
        if page["next"] is None:
            assert len(rows) == expected
            return rows
        assert page["next"] == offset + len(visible)
        offset = page["next"]
        time.sleep(0.1)


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
        before_rows = exclusions(port, cookie, csrf, receipt, result, "before")
        after_rows = exclusions(port, cookie, csrf, receipt, result, "after")
        added = [row for row in after_rows if row not in before_rows]
        assert len(added) == 1, added
        assert added[0]["rule_id"] == 942100 and added[0]["scope"] == "static_target", added
        assert added[0]["collection"] == "args" and added[0]["selection"] == "exact", added
        assert bytes.fromhex(added[0]["key"]["hex"]) == b"application_field", added
        page_query = {"id": receipt, "side": "after", "offset": 4097}
        assert request(port, cookie, csrf, "review/exclusions", page_query)[0] == 400
        page_query["offset"] = 0
        assert request(port, None, None, "review/exclusions", page_query)[0] == 401
        assert request(port, cookie, None, "review/exclusions", page_query)[0] == 400
        assert not origin.requests and status(port, cookie, csrf)["revision"] == 1
        assert request(port, cookie, csrf, "test/result", {"id": receipt})[0] == 400
        other, other_csrf = login(port)
        assert request(port, other, other_csrf, "review/result", {"id": receipt})[0] == 400
        assert request(port, other, other_csrf, "review/exclusions", page_query)[0] == 400
        receipt, result = review(port, cookie, csrf, candidate, 0)
        assert result["state"] == "failed" and result["failure"] == "CrsSelectionConflict", result
        assert request(port, cookie, csrf, "review/exclusions", page_query)[0] == 400
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
    print("Rule comparisons: exact changes, complete named exclusion pages, redacted audit, "
          "unchanged publication, revision conflicts, session isolation and revocation pass.")


if __name__ == "__main__":
    main()
