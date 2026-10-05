#!/usr/bin/env python3
"""Qualify signed source adoption, durable restoration and conflicting startup input."""
import argparse
import crs_fixture_source as fixtures
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import tempfile

import console_bootstrap_test as bootstrap
import console_e2e as helper
from crs_console_check import HEADERS, ATTACK, PASSWORD, login
from proxy_e2e import exchange
from proxy_fixture import origin
import process_control


def launch(binary, root, source, extra=()):
    with ExitStack() as owned:
        application, worker = origin()
        owned.callback(worker.join, 5)
        owned.callback(application.server_close)
        owned.callback(application.shutdown)
        policy = root / "policy.json"
        policy.write_text(json.dumps({"waf": False, "default_action": "ALLOW", "rules": [
            {"name": "fixture", "path": "*", "action": "ALLOW"}]}))
        port = helper.port()
        logfile = owned.enter_context((root / f"launch-{port}.log").open("w+"))
        flags = ("--upstream-port", str(application.server_port), "--policy-file", str(policy))
        if source is not None:
            flags += ("--crs-mode", "audit", "--crs-dir", str(source), "--crs-slots", "2")
        process = helper.start(str(binary), str(root / "data"), port, logfile,
                               extra=(*flags, *extra))
        owned.callback(helper.stop, process)
        return owned.pop_all(), process, application, port


def status(port, cookie):
    code, _, body = helper.request(port, "GET", "/console/api/nodes/local", cookie=cookie)
    assert code == 200, body
    selected = json.loads(body)["crs"]["selection"]
    assert selected["mode"] == "audit" and selected["revision"] == 1, selected
    assert selected["slots"] == 2 and selected["release"] == "4.30.0", selected
    # Compiler allocator peaks are observations, not signed identity. The loader
    # may reach a different peak when compiling the same authenticated source.
    assert int(selected.pop("compiled_peak")) > 0, selected
    return selected


def qualify(binary, source, root):
    credentials = bootstrap.initialize(str(binary), str(root / "data"), "crs-admin")
    owned, process, application, port = launch(binary, root, source)
    with owned:
        bootstrap.change(helper, port, credentials, PASSWORD)
        cookie, _ = login(port)
        before = status(port, cookie)
        data_port = int(process.args[process.args.index("--port") + 1])
        assert exchange(data_port, ATTACK, HEADERS)[0] == 200
        assert len(application.requests) == 1
    # Restoration needs neither the original directory nor activation flags.
    owned, process, application, port = launch(binary, root, None)
    with owned:
        cookie, _ = login(port)
        after = status(port, cookie)
        assert before == after, (before, after)
        data_port = int(process.args[process.args.index("--port") + 1])
        assert exchange(data_port, ATTACK, HEADERS)[0] == 200
        assert len(application.requests) == 1
    for flags in (("--no-crs",), ("--crs-inbound-threshold", "9")):
        command = [str(binary), "--data-dir", str(root / "data"), "--host", "127.0.0.1",
                   "--port", str(helper.port()), "--console", f"127.0.0.1:{helper.port()}",
                   *flags]
        process = process_control.spawn(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            output, error = process.communicate(timeout=90)
        finally:
            if process.poll() is None:
                process_control.terminate(process)
                process.wait(timeout=10)
        assert process.returncode != 0 and b"CrsStartupConflict" in error, (output, error)
    # Refused process input did not rewrite the durable selection.
    owned, _, _, port = launch(binary, root, None)
    with owned:
        cookie, _ = login(port)
        assert status(port, cookie) == before


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    fixtures.arguments(parser)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-restart-") as temporary:
        root = Path(temporary)
        binary = args.binary.resolve()
        qualify(binary, fixtures.resolve(binary, args, root), root)
    print("Signed filesystem adoption, durable restart, conflicting mode/bounds refusal "
          "and clean worker shutdown pass.")


if __name__ == "__main__":
    main()
