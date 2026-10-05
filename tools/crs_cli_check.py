#!/usr/bin/env python3
"""Qualify native CRS commands using private credentials and a signed live fixture."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time

import console_bootstrap_test as bootstrap
import console_e2e as helper
from console_cli_test import private
from crs_console_check import ATTACK, HEADERS, PASSWORD, login
from crs_management_check import status
from crs_restart_check import launch
from proxy_e2e import exchange


def command(binary, auth, operation, *options, failure=None):
    result = subprocess.run([str(binary), "crs", operation, *auth, *options],
                            capture_output=True, text=True, timeout=150)
    if "RateLimited" in result.stderr:
        # Each CLI command intentionally owns and closes a fresh authenticated
        # session. Honor the real address-based login limit, including bootstrap.
        time.sleep(61)
        result = subprocess.run([str(binary), "crs", operation, *auth, *options],
                                capture_output=True, text=True, timeout=150)
    assert PASSWORD not in result.stdout + result.stderr
    if failure:
        assert result.returncode == 1 and failure in result.stderr, result
        return result.stderr
    assert result.returncode == 0 and not result.stderr, result
    return json.loads(result.stdout)


def private_tests(binary, source, root):
    sample = root / "private-case.json"
    headers = [{"name": name, "value": value} for name, value in
               (("Host", "example.test"), ("User-Agent", "Mozilla/5.0"),
                ("Accept", "text/html"))]
    case = {"request": {"target": ATTACK, "headers": headers},
            "response": {"entity": {"body": "ordinary page"}}}
    sample.write_text(json.dumps(case))
    original = {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()}
    for mode in ("off", "audit", "enforce"):
        result = subprocess.run([str(binary), "crs", "test", "--directory", str(source),
                                 "--case", str(sample), "--mode", mode],
                                capture_output=True, text=True, timeout=90)
        assert result.returncode == 0 and not result.stderr, result
        report = json.loads(result.stdout)
        assert report["private_test"] and not report["origin_contacted"], report
        assert report["active_protection"] == "unchanged", report
        assert report["report"]["mode"] == mode, report
        assert not report["report"]["failure"], report
        assert report["report"]["denied"] == (mode == "enforce"), report
        assert report["report"]["would_deny"] == (mode != "off"), report
        if mode != "off":
            assert report["report"]["inbound_score"] >= 5, report
        assert ATTACK not in result.stdout and "ordinary page" not in result.stdout
    assert original == {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()}
    case["request"]["headers"][0]["value"] = "private-value\r\nInjected: bad"
    sample.write_text(json.dumps(case))
    result = subprocess.run([str(binary), "crs", "test", "--directory", str(source),
                             "--case", str(sample), "--mode", "enforce"],
                            capture_output=True, text=True, timeout=90)
    assert result.returncode == 1 and "InvalidSample" in result.stderr, result
    assert "private-value" not in result.stdout + result.stderr


def applied(port, cookie, csrf, revision, mode):
    deadline = time.monotonic() + 90
    while True:
        observed = status(port, cookie, csrf)
        local = observed["local"]["selection"]
        if local["revision"] == revision:
            assert local["mode"] == mode, observed
            return observed
        assert time.monotonic() < deadline, observed
        time.sleep(1)


def qualify(binary, source, root):
    private_tests(binary, source, root)
    # Offline validation verifies the signed restart bytes without any daemon.
    validation = subprocess.run([str(binary), "crs", "validate", "--directory", str(source)],
                                capture_output=True, text=True, timeout=90)
    assert validation.returncode == 0 and "verified candidate" in validation.stdout, validation
    credentials = bootstrap.initialize(str(binary), str(root / "data"), "crs-admin")
    owned, process, _, port = launch(binary, root, source)
    with owned:
        bootstrap.change(helper, port, credentials, PASSWORD)
        cookie, csrf = login(port)
        credential = private(root / "credential", PASSWORD)
        auth = ("--origin", f"http://127.0.0.1:{port}", "--username", "crs-admin",
                "--password-file", str(credential))
        data_port = int(process.args[process.args.index("--port") + 1])
        observed = command(binary, auth, "status")
        assert int(observed["revision"]) == 1 and observed["current"]["artifact"][
            "settings"]["mode"] == "audit", observed
        private_case = root / "remote-case.json"
        private_case.write_text(json.dumps({"request": {"target": ATTACK, "headers": [
            {"name": key, "value": value} for key, value in HEADERS.items()]}}))
        view = command(binary, auth, "status")
        tested = command(binary, auth, "test", "--id", view["current"]["id"],
                         "--revision", "1", "--case", str(private_case), "--mode", "enforce")
        assert tested["private_test"] and not tested["origin_contacted"], tested
        assert tested["result"]["report"]["denied"], tested
        assert status(port, cookie, csrf)["revision"] == 1
        prepared = command(binary, auth, "mode", "--mode", "enforce", "--revision", "1")
        assert prepared["protection"] == "unchanged"
        assert prepared["candidate"]["artifact"]["settings"]["mode"] == "enforce"
        assert exchange(data_port, ATTACK, HEADERS)[0] == 200
        identifier = prepared["candidate"]["id"]
        reviewed = command(binary, auth, "review", "--id", identifier, "--revision", "1")
        comparison = reviewed["result"]["comparison"]
        assert reviewed["rule_review"] and not reviewed["private_test"], reviewed
        assert comparison["unchanged"] == 628 and comparison["count"] == 0, comparison
        assert not reviewed["origin_contacted"] and reviewed["active_protection"] == "unchanged"
        assert status(port, cookie, csrf)["revision"] == 1
        command(binary, auth, "select", "--id", identifier, "--revision", "1")
        applied(port, cookie, csrf, 2, "enforce")
        assert exchange(data_port, ATTACK, HEADERS)[0] == 403
        command(binary, auth, "mode", "--mode", "off", "--revision", "1", failure="Conflict")
        prepared = command(binary, auth, "mode", "--mode", "off", "--revision", "2")
        command(binary, auth, "select", "--id", prepared["candidate"]["id"], "--revision", "2")
        assert applied(port, cookie, csrf, 3, "off")["local"]["selection"]["slots"] == 0
        prepared = command(binary, auth, "rollback", "--revision", "3")
        assert prepared["candidate"]["artifact"]["settings"]["mode"] == "enforce"
        command(binary, auth, "select", "--id", prepared["candidate"]["id"], "--revision", "3")
        applied(port, cookie, csrf, 4, "enforce")
        assert exchange(data_port, ATTACK, HEADERS)[0] == 403
        prepared = command(binary, auth, "mode", "--mode", "audit", "--revision", "4")
        identifier = prepared["candidate"]["id"]
        command(binary, auth, "discard", "--id", identifier, "--revision", "4")
        command(binary, auth, "select", "--id", identifier, "--revision", "4", failure="Conflict")
        configuration = root / "operator.conf"
        rule = ('SecRule REQUEST_URI "@streq /operator-test" '
                '"id:123457,phase:1,deny,status:418"\n')
        remaining = 65536 - len(rule)
        # A maximum-size editor crosses the shared client's former 2 KiB bound.
        # Comments remain short logical lines and do not add executable rules.
        configuration.write_text(rule + "# pad\n" * (remaining // 6) +
                                 "#" * (remaining % 6))
        assert configuration.stat().st_size == 65536
        prepared = command(binary, auth, "update", "--revision", "4", "--version", "4.30.0",
                           "--configuration", str(configuration))
        assert exchange(data_port, "/operator-test", HEADERS)[0] == 200
        identifier = prepared["candidate"]["id"]
        command(binary, auth, "select", "--id", identifier, "--revision", "4")
        applied(port, cookie, csrf, 5, "enforce")
        assert exchange(data_port, "/operator-test", HEADERS)[0] == 418
        invalid = root / "invalid-settings.json"
        invalid.write_text('{"inbound_threshhold":1}')
        command(binary, auth, "update", "--revision", "5", "--settings", str(invalid),
                failure="InvalidConfiguration")
        invalid_rules = root / "invalid.conf"
        invalid_rules.write_text("# location check\nInvalidDirective secret-value\n")
        report = command(binary, auth, "check", "--revision", "5", "--version", "4.30.0",
                         "--configuration", str(invalid_rules), failure="PreparationFailed")
        assert "CRSCOMPILE/" in report and "sibuna-operator.conf" in report and "Line: 2" in report
        assert "secret-value" not in report
        assert status(port, cookie, csrf)["revision"] == 5
        assert exchange(data_port, ATTACK, HEADERS)[0] == 403


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-cli-") as temporary:
        qualify(args.binary.resolve(), args.candidate.resolve(), Path(temporary))
    print("Native CRS CLI: private tests, offline validation, authenticated status, reviewed modes, "
          "rollback, conflicts, discard, full-size operator rules and strict settings pass.")


if __name__ == "__main__":
    main()
