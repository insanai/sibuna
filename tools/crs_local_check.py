#!/usr/bin/env python3
"""Qualify engine CRS updates without a console, storage owner or management listener."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

import console_e2e as helper
import process_control
from crs_daemon_check import HEADERS, candidate as download_candidate
from proxy_e2e import exchange
from proxy_fixture import origin
from run import ready

ATTACK = "/ordinary?q=1%27%20OR%20%271%27=%271"


def command(binary, store, operation, *flags, failure=None):
    result = subprocess.run([str(binary), "crs", operation, "--directory", str(store), *flags],
                            capture_output=True, text=True, timeout=150)
    if failure:
        assert result.returncode == 1 and failure in result.stderr, result
        return result.stderr
    assert result.returncode == 0 and not result.stderr, result
    return json.loads(result.stdout)


def applied(binary, store, revision):
    deadline = time.monotonic() + 60
    while True:
        result = subprocess.run([str(binary), "crs", "status", "--directory", str(store)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            observed = json.loads(result.stdout)
            receipt = observed["last_application_observation"]
            assert observed["saved_selection"]["current"]["revision"] == revision, observed
            if receipt and receipt["state"] == "applied" and receipt["source"]["revision"] == revision:
                assert receipt["source"] == observed["saved_selection"]["current"], observed
                assert any(receipt["boot"]), observed
                return observed
        else:
            assert "LocalStoreBusy" in result.stderr, result
        assert time.monotonic() < deadline, result
        time.sleep(0.25)


def launch(binary, root, store, expected_error=None, mode="reverse_proxy"):
    with ExitStack() as owned:
        application, worker = origin()
        owned.callback(worker.join, 5)
        owned.callback(application.server_close)
        owned.callback(application.shutdown)
        policy = root / "policy.json"
        policy.write_text(json.dumps({"waf": False, "default_action": "ALLOW", "rules": [
            {"name": "fixture", "path": "*", "action": "ALLOW"}]}))
        port = helper.port()
        logfile = owned.enter_context((root / f"daemon-{port}.log").open("w+"))
        process = process_control.spawn([
            str(binary), "--host", "127.0.0.1", "--port", str(port), "--workers", "2",
            "--upstream-port", str(application.server_port), "--policy-file", str(policy),
            "--mode", mode, "--crs-reload", "--crs-dir", str(store),
        ], stdout=logfile, stderr=logfile)
        if expected_error:
            try:
                process.wait(timeout=60)
            finally:
                if process.poll() is None:
                    process_control.terminate(process)
                    process.wait(timeout=10)
            logfile.flush()
            logfile.seek(0)
            log = logfile.read()
            assert process.returncode != 0 and expected_error in log, log
            return None
        owned.callback(helper.stop, process)
        try:
            ready(process, port)
        except Exception as error:
            logfile.flush()
            logfile.seek(0)
            raise AssertionError(logfile.read()) from error
        return owned.pop_all(), process, application, port


def failed_application(binary, store, process, port):
    # Stop this owned daemon between reload polls, so the fault lands after a
    # valid intent commit but before native authentication. The common fixture
    # separately exercises corruption refusal at startup on every platform.
    import fcntl
    with (store / ".writer.lock").open("r+b") as guard:
        deadline = time.monotonic() + 10
        while True:
            try:
                fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                assert time.monotonic() < deadline
                time.sleep(0.05)
        os.kill(process.pid, signal.SIGSTOP)
        time.sleep(0.1)
    original = None
    try:
        desired = command(binary, store, "mode", "--revision", "4", "--mode", "audit")
        current = desired["saved_selection"]["current"]
        archive = store / ("generation-" + bytes(current["id"]).hex()) / "archive.tar.gz"
        original = archive.read_bytes()
        changed = bytearray(original)
        changed[len(changed) // 2] ^= 1
        archive.write_bytes(changed)
    finally:
        os.kill(process.pid, signal.SIGCONT)
    try:
        deadline = time.monotonic() + 60
        while True:
            result = subprocess.run([str(binary), "crs", "status", "--directory", str(store)],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode:
                assert "LocalStoreBusy" in result.stderr and time.monotonic() < deadline, result
                time.sleep(0.25)
                continue
            observed = json.loads(result.stdout)
            receipt = observed["last_application_observation"]
            if receipt["source"]["revision"] == 5 and receipt["state"] == "failed":
                break
            assert time.monotonic() < deadline, observed
            time.sleep(0.25)
        assert exchange(port, ATTACK, HEADERS)[0] == 403, "failed effect replaced active protection"
    finally:
        if original is not None:
            archive.write_bytes(original)
    applied(binary, store, 5)
    assert exchange(port, ATTACK, HEADERS)[0] == 200
    command(binary, store, "rollback", "--revision", "5")
    applied(binary, store, 6)
    assert exchange(port, "/operator-local", HEADERS)[0] == 418


def qualify(binary, candidate, root):
    store = root / "store"
    store.mkdir(mode=0o700)
    source = root / "candidate"
    shutil.copytree(candidate, source)
    before = {file.name: hashlib.sha256(file.read_bytes()).hexdigest() for file in source.iterdir()}
    empty = command(binary, store, "status")
    assert empty["saved_selection"] is None and empty["last_application_observation"] is None
    configuration = root / "operator.conf"
    configuration.write_text('SecRule REQUEST_URI "@streq /operator-local" '
                             '"id:123456,phase:1,deny,status:418"\n')
    observed = command(binary, store, "update", "--revision", "0", "--from", str(source),
                       "--configuration", str(configuration), "--mode", "audit", "--crs-slots", "2")
    assert observed["saved_selection"]["current"]["revision"] == 1, observed
    assert observed["last_application_observation"]["state"] == "pending", observed
    assert before == {file.name: hashlib.sha256(file.read_bytes()).hexdigest()
                      for file in source.iterdir()}, "local selection modified the reviewed candidate"
    shutil.rmtree(source)
    owned, process, application, port = launch(binary, root, store)
    with owned:
        first = applied(binary, store, 1)
        assert exchange(port, ATTACK, HEADERS)[0] == 200
        assert exchange(port, "/operator-local", HEADERS)[0] == 200
        launch(binary, root, store, expected_error="LocalStoreBusy")
        command(binary, store, "mode", "--revision", "1", "--mode", "enforce")
        applied(binary, store, 2)
        count = len(application.requests)
        assert exchange(port, ATTACK, HEADERS)[0] == 403
        assert exchange(port, "/operator-local", HEADERS)[0] == 418
        assert len(application.requests) == count, "denied requests reached the origin"
        command(binary, store, "mode", "--revision", "1", "--mode", "off",
                failure="LocalStoreConflict")
        selected = (store / "selection.bin").read_bytes()
        current = command(binary, store, "status")["saved_selection"]["current"]
        name = "generation-" + bytes(current["id"]).hex()
        invalid = root / "invalid.conf"
        invalid.write_text("# location check\nUnrecognizedDirective secret-value\n")
        report = command(binary, store, "update", "--revision", "2", "--from", str(store / name),
                         "--configuration", str(invalid), failure="CRSLOCALCOMMAND")
        assert "CRSCOMPILE/" in report and "sibuna-operator.conf" in report and "Line: 2" in report
        assert "secret-value" not in report
        assert selected == (store / "selection.bin").read_bytes()
        assert exchange(port, ATTACK, HEADERS)[0] == 403
        command(binary, store, "mode", "--revision", "2", "--mode", "off")
        applied(binary, store, 3)
        assert exchange(port, ATTACK, HEADERS)[0] == 200
        command(binary, store, "rollback", "--revision", "3")
        final = applied(binary, store, 4)
        assert final["settings"]["activation"]["mode"] == "enforce", final
        assert final["settings"]["slots"] == 2, final
        assert exchange(port, "/operator-local", HEADERS)[0] == 418
        assert len(list(store.glob("generation-*"))) <= 4
        revision = 4
        if os.name == "posix":
            failed_application(binary, store, process, port)
            revision = 6
    owned, _, _, port = launch(binary, root, store)
    with owned:
        restarted = applied(binary, store, revision)
        assert restarted["last_application_observation"]["boot"] != first[
            "last_application_observation"]["boot"], restarted
        assert exchange(port, ATTACK, HEADERS)[0] == 403
        assert exchange(port, "/operator-local", HEADERS)[0] == 418
    current = restarted["saved_selection"]["current"]
    directory = store / ("generation-" + bytes(current["id"]).hex())
    archive = directory / "archive.tar.gz"
    original = archive.read_bytes()
    changed = bytearray(original)
    changed[len(changed) // 2] ^= 1
    archive.write_bytes(changed)
    launch(binary, root, store, expected_error="CRSSTART001")
    archive.write_bytes(original)
    selector = store / "selection.bin"
    original_selection = selector.read_bytes()
    selector.unlink()
    launch(binary, root, store, expected_error="InvalidLocalSource")
    selector.write_bytes(original_selection)
    owned, _, _, port = launch(binary, root, store)
    with owned:
        applied(binary, store, revision)
        assert exchange(port, ATTACK, HEADERS)[0] == 403
    header_store = root / "header-store"
    header_store.mkdir(mode=0o700)
    command(binary, header_store, "update", "--revision", "0", "--from", str(directory),
            "--crs-profile", "headers")
    owned, _, application, port = launch(binary, root, header_store, mode="forward_auth")
    with owned:
        applied(binary, header_store, 1)
        assert exchange(port, "/ordinary", HEADERS)[0] == 200
        assert exchange(port, "/operator-local", HEADERS)[0] == 418
        assert not application.requests, "forward-auth called the origin"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--candidate", type=Path)
    source.add_argument("--download", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-local-") as temporary:
        root = Path(temporary)
        binary = args.binary.resolve()
        candidate = args.candidate.resolve() if args.candidate else download_candidate(binary, root)
        # Download preparation owns a different name from the copy used to prove
        # later restoration does not depend on the original candidate directory.
        if args.download:
            renamed = root / "downloaded"
            candidate.rename(renamed)
            candidate = renamed
        qualify(binary, candidate, root)
    print("Local CRS: signed adoption, reviewed modes, rollback, rejected edits, daemon ownership, "
          "restart, corruption refusal and forward-auth pass; all daemons stopped cleanly.")


if __name__ == "__main__":
    main()
