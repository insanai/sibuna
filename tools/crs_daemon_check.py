#!/usr/bin/env python3
"""Qualify authenticated CRS startup through the actual daemon and a loopback origin."""
import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import console_e2e as helper
import process_control
from proxy_e2e import exchange
from proxy_fixture import origin, WebSocket, frame, receive
from run import ready

HEADERS = {"Host": "example.test", "User-Agent": "Mozilla/5.0", "Accept": "text/html"}


def candidate(binary, root):
    destination = root / "candidate"
    command = [str(binary), "crs", "check", "--version", "4.30.0", "--output", str(destination)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=150)
    if result.returncode:
        raise AssertionError(f"candidate preparation failed: {result.stderr[:2048]}")
    provenance = json.loads(Path("vendor/crs/provenance.json").read_text())
    assert f"SHA-256: {provenance['archive_sha256']}" in result.stdout, result.stdout
    assert "Active protection: unchanged" in result.stdout, result.stdout
    before = digest(destination)
    result = subprocess.run(command, capture_output=True, text=True, timeout=150)
    assert result.returncode == 1 and "PathAlreadyExists" in result.stderr, result.stderr
    assert before == digest(destination), "candidate overwrite changed existing files"
    return destination


def digest(directory):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in directory.iterdir()}


def qualify(binary, source, root, mode="reverse_proxy"):
    with ExitStack() as owned:
        application, worker = origin()
        owned.callback(worker.join, 5)
        owned.callback(application.server_close)
        owned.callback(application.shutdown)
        policy = root / "policy.json"
        policy.write_text(json.dumps({"waf": False, "default_action": "ALLOW", "rules": [
            {"name": "fixture-admission", "path": "*", "action": "ALLOW"}]}))
        port = helper.port()
        logfile = owned.enter_context((root / f"{mode}.log").open("w+"))
        command = [str(binary), "--host", "127.0.0.1", "--port", str(port),
                   "--upstream-port", str(application.server_port), "--workers", "2",
                   "--policy-file", str(policy), "--mode", mode, "--crs", "--crs-dir",
                   str(source), "--crs-slots", "2"]
        if mode == "forward_auth":
            command += ["--crs-profile", "headers"]
        daemon = process_control.spawn(command, stdout=logfile, stderr=logfile)
        owned.callback(helper.stop, daemon)
        try:
            ready(daemon, port)
            normal, _, body = exchange(port, "/ordinary", HEADERS)
            assert normal == 200, (normal, body[:128])
            if mode == "reverse_proxy":
                assert json.loads(body)["path"] == "/ordinary"
                attack = "/ordinary?q=1%27%20OR%20%271%27=%271"
                status, _, body = exchange(port, attack, HEADERS)
                assert status == 403, (status, body[:128])
                assert len(application.requests) == 1, application.requests
                socket = WebSocket(port, HEADERS)
                try:
                    assert receive(socket.reader, False) == (1, b"origin ready", True)
                    status, _, _ = exchange(port, "/after-upgrade", HEADERS)
                    assert status == 200
                    payload = b"CRS inspects the handshake, not frames"
                    socket.socket.sendall(frame(1, payload, masked=True))
                    assert receive(socket.reader, False) == (1, payload, True)
                    socket.socket.sendall(frame(8, b"\x03\xe8", masked=True))
                    assert receive(socket.reader, False) == (8, b"\x03\xe8", True)
                finally:
                    socket.close()
                expected = ("sibuna_crs_inspected_total 2\n", "sibuna_crs_handshake_total 1\n",
                            "sibuna_crs_denied_total 1\n")
            else:
                assert body == b"OK" and not application.requests
                expected = ("sibuna_crs_headers_total 1\n", "sibuna_crs_inspected_total 0\n")
            status, _, metrics = exchange(port, "/__sibuna/metrics", {})
            assert status == 200
            for value in expected:
                assert value.encode() in metrics, metrics
        except Exception as error:
            logfile.flush()
            logfile.seek(0)
            raise AssertionError(logfile.read(8192)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--candidate", type=Path)
    args = parser.parse_args()
    if args.download and args.candidate is not None:
        parser.error("choose --download or --candidate, not both")
    if not args.download and args.candidate is None:
        parser.error("use --download for the pinned signed release, or --candidate <directory>")
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-daemon-") as temporary:
        root = Path(temporary)
        binary = args.binary.resolve()
        source = args.candidate.resolve() if args.candidate else candidate(binary, root)
        qualify(binary, source, root)
        qualify(binary, source, root, "forward_auth")
    print("Signed CRS startup, ordinary traffic, SQL refusal, WebSocket coverage, "
          "forward-auth headers, overwrite refusal and clean shutdown pass.")


if __name__ == "__main__":
    main()
