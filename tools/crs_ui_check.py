#!/usr/bin/env python3
"""Drive the shipped CRS Wasm page against authenticated native management."""
import argparse
import json
from pathlib import Path
import re
import tempfile
import time

import console_bootstrap_test as bootstrap
import console_e2e as helper
from console_ui_live_test import Interface
from crs_console_check import ATTACK, HEADERS, PASSWORD, login
from crs_restart_check import launch
from proxy_e2e import exchange


def action(ui, name, fields=None):
    ui.event(1, {"action": name, "fields": fields or {}})


def snapshot(ui):
    code, _, body = helper.request(ui.port, "GET", "/console/api/crs/status",
                                   cookie=ui.cookie)
    assert code == 200, (code, body)
    return json.loads(body)


def candidate(ui, revision, mode):
    deadline = time.monotonic() + 120
    while True:
        action(ui, "crs-refresh")
        observed = snapshot(ui)
        assert observed["revision"] == revision, "preparation selected protection"
        pending = next((row for row in observed["candidates"] if row and
                        row["state"] == "verified"), None)
        if pending:
            assert pending["artifact"]["settings"]["mode"] == mode, pending
            match = re.search(r'data-action="(crs-review-\d+)"', ui.html)
            assert match, ui.html[-3000:]
            action(ui, match[1])
            assert 'id="crs-review"' in ui.html and "Select candidate" in ui.html
            return pending
        assert observed["stage"] not in ("failed", "canceled"), observed
        assert time.monotonic() < deadline, observed
        time.sleep(1)


def select(ui, revision, mode):
    action(ui, "crs-select")
    deadline = time.monotonic() + 90
    while True:
        action(ui, "crs-refresh")
        observed = snapshot(ui)
        assert observed["revision"] == revision, observed
        local = observed["local"]["selection"]
        if local["revision"] == revision:
            assert local["mode"] == mode, observed
            assert "Selection committed" not in ui.html or "node receipts" in ui.html
            assert f"Serving node: revision {revision}" in ui.html
            return observed
        assert time.monotonic() < deadline, observed
        time.sleep(1)


def private_test(ui):
    action(ui, "crs-test", {
        "mode": "enforce", "request_method": "GET", "request_target": ATTACK,
        "client": "192.0.2.1", "request_headers": "Host: example.test\n"
        "User-Agent: Mozilla/5.0\nAccept: text/html", "request_body": "",
        "request_encoding": "text", "response_status": "200", "response_headers": "",
        "response_body": "ordinary page", "response_encoding": "text",
        "response_ending": "complete"})
    deadline = time.monotonic() + 90
    while "Enforcing denial: yes" not in ui.html:
        assert time.monotonic() < deadline, ui.html[-7000:]
        time.sleep(1)
        action(ui, "crs-test-poll")
    assert "Would deny: yes" in ui.html and "Blocking inbound score:" in ui.html
    assert "Origin contacted: no" in ui.html and "Active protection: unchanged" in ui.html
    assert "Tested candidate:" in ui.html and "unlogged matches excluded" in ui.html
    assert "0 additional findings omitted" in ui.html
    assert snapshot(ui)["revision"] == 1


def modes(ui, data_port):
    revision = 1
    for mode, expected in (("enforce", 403), ("off", 200)):
        before = exchange(data_port, ATTACK, HEADERS)[0]
        action(ui, "crs-mode", {"mode": mode})
        candidate(ui, revision, mode)
        assert exchange(data_port, ATTACK, HEADERS)[0] == before
        revision += 1
        observed = select(ui, revision, mode)
        assert exchange(data_port, ATTACK, HEADERS)[0] == expected
        if mode == "off":
            assert observed["local"]["selection"]["slots"] == 0
            assert observed["local"]["selection"]["reserved_bytes"] == 0
    # Real browser buttons include their parent form, even on a rollback click.
    action(ui, "crs-rollback", {"mode": "off"})
    restored = candidate(ui, revision, "enforce")
    assert restored["artifact"]["settings"] == observed["previous"]["artifact"]["settings"]
    select(ui, 4, "enforce")
    assert exchange(data_port, ATTACK, HEADERS)[0] == 403


def editor(ui, data_port):
    action(ui, "crs-reload-editor")
    configuration = ('SecRule REQUEST_URI "@streq /operator-test" '
                     '"id:100001,phase:1,deny,status:418"\n')
    action(ui, "crs-update", {"version": "4.30.0", "configuration": configuration})
    prepared = candidate(ui, 4, "enforce")
    assert prepared["artifact"]["operator_digest"] != snapshot(ui)["current"][
        "artifact"]["operator_digest"]
    assert exchange(data_port, "/operator-test", HEADERS)[0] == 200
    select(ui, 5, "enforce")
    assert exchange(data_port, "/operator-test", HEADERS)[0] == 418
    action(ui, "crs-reload-editor")
    assert "id:100001" in ui.html
    action(ui, "crs-check", {"version": "4.30.0", "configuration": "# location check\nInvalidDirective secret-value\n"})
    deadline = time.monotonic() + 120
    while snapshot(ui)["stage"] != "failed":
        assert time.monotonic() < deadline
        time.sleep(1)
        action(ui, "crs-refresh")
    observed = snapshot(ui)
    assert observed["revision"] == 5
    failed = next(row for row in observed["candidates"] if row and row["state"] == "failed")
    diagnostic = failed["diagnostic"]
    assert diagnostic["path"] == "sibuna-operator.conf" and diagnostic["line"] == 2, failed
    assert "sibuna-operator.conf" in ui.html and "Line: 2" in ui.html
    assert "CRSCOMPILE/" in ui.html and "Hint:" in ui.html
    assert "secret-value" not in json.dumps(diagnostic)
    assert exchange(data_port, "/operator-test", HEADERS)[0] == 418


def qualify(binary, source, root):
    credentials = bootstrap.initialize(str(binary), str(root / "data"), "crs-admin")
    owned, process, _, port = launch(binary, root, source)
    with owned:
        bootstrap.change(helper, port, credentials, PASSWORD)
        cookie, _ = login(port)
        code, _, shell = helper.request(port, "GET", "/console/")
        assert code == 200
        path = re.search(rb'name="sibuna-console-wasm" content="([^"]+)"', shell)[1].decode()
        code, _, bytes_value = helper.request(port, "GET", path, cookie=cookie)
        assert code == 200
        wasm = root / "console.wasm"
        wasm.write_bytes(bytes_value)
        ui = Interface(port, cookie, wasm)
        try:
            ui.event(init=True)
            ui.topic("stats")
            action(ui, "crs")
            assert "Core Rule Set" in ui.html and 'id="console-navigation"' in ui.html
            data_port = int(process.args[process.args.index("--port") + 1])
            private_test(ui)
            modes(ui, data_port)
            editor(ui, data_port)
            action(ui, "logout")
            assert "Welcome back" in ui.html and "id:100001" not in ui.html
            assert ui.stream is None and "Core Rule Set" not in ui.html
        finally:
            ui.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-ui-") as temporary:
        qualify(args.binary.resolve(), args.candidate.resolve(), Path(temporary))
    print("Shipped CRS Wasm: private phased tests, reviewed modes, exact rollback, operator edits, failed "
          "preparation and sign-out pass against the live daemon.")


if __name__ == "__main__":
    main()
