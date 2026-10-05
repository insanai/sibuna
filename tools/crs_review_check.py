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
    for index in range(8):
        configuration += (f'SecAction "id:{123458 + index},phase:1,'
                          f'ctl:ruleRemoveTargetByTag={"T" * 1024};ARGS:{"K" * 1024}"\n')
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


def qualify_exclusions(port, cookie, csrf, receipt, result):
    before_rows = exclusions(port, cookie, csrf, receipt, result, "before")
    after_rows = exclusions(port, cookie, csrf, receipt, result, "after")
    added = [row for row in after_rows if row not in before_rows]
    assert len(added) == 9, added
    narrow = next(row for row in added if row["scope"] == "static_target")
    assert narrow["rule_id"] == 942100, narrow
    assert narrow["collection"] == "args" and narrow["selection"] == "exact", narrow
    assert bytes.fromhex(narrow["key"]["hex"]) == b"application_field", narrow
    wide = [row for row in added if row["scope"] == "conditional_target"]
    assert len(wide) == 8, wide
    for row in wide:
        for name, byte in ((row["tag"], b"T"), (row["key"], b"K")):
            assert name["bytes"] == 1024 and bytes.fromhex(name["hex"]) == byte * 256
            assert name["digest"] == hashlib.sha256(byte * 1024).hexdigest()
    start = after_rows.index(wide[0])
    code, _, body = request(port, cookie, csrf, "review/exclusions", {
        "id": receipt, "side": "after", "offset": start})
    assert code == 200 and len(body) < 16384, (code, body)
    assert json.loads(body)["page"]["rows"] == wide
    page_query = {"id": receipt, "side": "after", "offset": 4097}
    assert request(port, cookie, csrf, "review/exclusions", page_query)[0] == 400
    page_query["offset"] = 0
    assert request(port, None, None, "review/exclusions", page_query)[0] == 401
    assert request(port, cookie, None, "review/exclusions", page_query)[0] == 400
    return page_query


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
        assert comparison["added"] == 9 and comparison["modified"] == 1, comparison
        assert comparison["reordered"] == 0 and comparison["removed"] == 0, comparison
        assert comparison["after"]["target_exclusions"] == comparison["before"][
            "target_exclusions"] + 1, comparison
        changes = {row["id"]: row["kind"] for row in comparison["changes"] if row}
        expected_changes = {942100: "modified", **{id: "added" for id in range(123457, 123466)}}
        assert changes == expected_changes, changes
        page_query = qualify_exclusions(port, cookie, csrf, receipt, result)
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
