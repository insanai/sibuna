#!/usr/bin/env python3
"""Exercise reviewed CRS changes against a signed package and a real daemon."""
import argparse
import json
from pathlib import Path
import tempfile
import time
import uuid

import console_bootstrap_test as bootstrap
import console_e2e as helper
from crs_console_check import ATTACK, HEADERS, PASSWORD, login
from crs_restart_check import launch
from proxy_e2e import exchange


def request(port, cookie, csrf, leaf, body=None):
    return helper.request(port, "GET" if body is None else "POST",
                          f"/console/api/crs/{leaf}", body, cookie, csrf)


def status(port, cookie, csrf):
    code, _, body = request(port, cookie, csrf, "status")
    assert code == 200, (code, body)
    return json.loads(body)


def prepare(port, cookie, csrf, desired, mode=None, kind="mode"):
    identifier = uuid.uuid4().hex
    revision = desired["revision"]
    body = {"id": identifier, "kind": kind, "expected_revision": str(revision)}
    if mode is not None:
        body["settings"] = dict(desired["current"]["artifact"]["settings"], mode=mode)
    code, _, reply = request(port, cookie, csrf, "prepare", body)
    assert code == 200 and json.loads(reply)["id"] == identifier, (code, reply)
    deadline = time.monotonic() + 90
    while True:
        observed = status(port, cookie, csrf)
        assert observed["revision"] == revision, observed
        job = next((row for row in observed["candidates"] if row and row["id"] == identifier), None)
        assert job is not None, observed
        if job["state"] == "verified":
            assert job["artifact"]["revision"] == revision + 1, job
            return identifier
        assert job["state"] == "preparing", job
        assert time.monotonic() < deadline, job
        time.sleep(1)


def select(port, cookie, csrf, identifier, revision, mode):
    body = {"id": identifier, "expected_revision": str(revision)}
    code, _, reply = request(port, cookie, csrf, "select", body)
    committed = json.loads(reply)
    assert code == 200 and committed == {
        "committed": True, "revision": revision + 1, "application": "unconfirmed"}, (code, reply)
    # Retrying the same intent acknowledges its existing commit.
    assert request(port, cookie, csrf, "select", body)[0] == 200
    assert request(port, cookie, csrf, "select", dict(body, expected_revision="0"))[0] == 409
    deadline = time.monotonic() + 90
    while True:
        observed = status(port, cookie, csrf)
        assert observed["revision"] == revision + 1, observed
        local = observed["local"]["selection"]
        receipt = next((node for node in observed["nodes"] if node), None)
        if local["revision"] == revision + 1 and receipt and receipt["applied"]:
            assert receipt["revision"] == revision + 1, receipt
            assert local["mode"] == mode, local
            return observed
        assert time.monotonic() < deadline, observed
        time.sleep(1)


def qualify(binary, source, root):
    credentials = bootstrap.initialize(str(binary), str(root / "data"), "crs-admin")
    owned, process, _, port = launch(binary, root, source)
    with owned:
        bootstrap.change(helper, port, credentials, PASSWORD)
        cookie, csrf = login(port)
        data_port = int(process.args[process.args.index("--port") + 1])
        assert request(port, None, None, "status")[0] == 401
        assert request(port, cookie, None, "prepare", {})[0] == 400
        assert request(port, cookie, csrf, "verify", {})[0] == 404
        assert request(port, cookie, csrf, "source")[0] == 404
        observed = status(port, cookie, csrf)
        assert observed["available"] and observed["revision"] == 1, observed
        assert observed["current"]["artifact"]["release"] == "4.30.0", observed
        code, _, body = request(port, cookie, csrf, "configuration")
        assert code == 200 and json.loads(body) == {"revision": 1, "configuration": ""}, body
        identifier = prepare(port, cookie, csrf, observed, "enforce")
        assert exchange(data_port, ATTACK, HEADERS)[0] == 200, "preparation activated rules"
        observed = select(port, cookie, csrf, identifier, 1, "enforce")
        assert exchange(data_port, ATTACK, HEADERS)[0] == 403
        invalid = {"id": uuid.uuid4().hex, "kind": "mode", "expected_revision": "1"}
        assert request(port, cookie, csrf, "prepare", invalid)[0] == 409
        identifier = prepare(port, cookie, csrf, observed, "off")
        observed = select(port, cookie, csrf, identifier, 2, "off")
        assert observed["local"]["selection"]["reserved_bytes"] == 0
        assert exchange(data_port, ATTACK, HEADERS)[0] == 200
        overridden = {"id": uuid.uuid4().hex, "kind": "rollback",
                      "expected_revision": "3", "settings":
                      dict(observed["current"]["artifact"]["settings"], mode="audit")}
        assert request(port, cookie, csrf, "prepare", overridden)[0] == 400
        identifier = prepare(port, cookie, csrf, observed, kind="rollback")
        observed = select(port, cookie, csrf, identifier, 3, "enforce")
        assert exchange(data_port, ATTACK, HEADERS)[0] == 403
        identifier = prepare(port, cookie, csrf, observed, "audit")
        body = {"id": identifier, "expected_revision": "4"}
        assert request(port, cookie, csrf, "discard", body)[0] == 200
        assert request(port, cookie, csrf, "select", body)[0] == 409
        assert status(port, cookie, csrf)["revision"] == 4
        assert helper.request(port, "POST", "/console/api/logout", {}, cookie, csrf)[0] == 200
        assert request(port, cookie, csrf, "status")[0] == 401
        assert request(port, cookie, csrf, "select", body)[0] == 401
    owned, process, _, port = launch(binary, root, None)
    with owned:
        cookie, csrf = login(port)
        observed = status(port, cookie, csrf)
        assert observed["revision"] == 4 and observed["local"]["selection"]["mode"] == "enforce"
        data_port = int(process.args[process.args.index("--port") + 1])
        assert exchange(data_port, ATTACK, HEADERS)[0] == 403


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-management-") as temporary:
        qualify(args.binary.resolve(), args.candidate.resolve(), Path(temporary))
    print("Authenticated preparation, separate reviewed selection, Off/Enforce, rollback, "
          "conflicts, discard, applied receipts, revocation and restart pass.")


if __name__ == "__main__":
    main()
