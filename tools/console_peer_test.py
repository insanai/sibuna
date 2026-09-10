"""Live daemon peer authentication, TLS verification, receipt fencing and clean cancellation."""
import base64
import http.client
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import time
from types import SimpleNamespace
import console_bootstrap_test as bootstrap
import console_peer_fixture as fixture
import console_totp_test as totp
from console_ws_test import Stream
from console_topics_client import Client


def wait(predicate, label, seconds=35):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(1)
    raise AssertionError(f"peer deadline: {label}; last={last}")


def incoming(port, key, transcript=None, proof_override=None, tls=None):
    ws_key = os.urandom(16) if transcript is None else transcript[48:]
    transcript = transcript or struct.pack("!IIQ", 2, 1, int(time.time())) + os.urandom(32) + ws_key
    signature = proof_override or fixture.proof(key, b"client", transcript)
    stream = Stream.__new__(Stream)
    stream.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    if tls:
        stream.sock = tls.wrap_socket(stream.sock, server_hostname="localhost")
    stream.file = stream.sock.makefile("rb")
    stream.sock.sendall((f"GET /console/peer HTTP/1.1\r\nHost: console.test\r\n"
                         "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                         "X-Forwarded-Proto: https\r\nSec-WebSocket-Version: 13\r\n"
                         f"Sec-WebSocket-Key: {base64.b64encode(ws_key).decode()}\r\n"
                         f"X-Sibuna-Peer: {transcript.hex()}\r\n"
                         f"X-Sibuna-Proof: {signature.hex()}\r\n\r\n").encode())
    status = int(stream.file.readline().split()[1])
    headers = {}
    while (line := stream.file.readline()) != b"\r\n":
        assert line
        name, value = line.decode().split(":", 1)
        headers[name.lower()] = value.strip()
    if status == 101:
        identity = bytes.fromhex(headers["x-sibuna-peer"])
        assert bytes.fromhex(headers["x-sibuna-proof"]) == fixture.proof(
            key, b"server", transcript + identity)
    return stream, status, transcript


def admission(port, key):
    first, status, transcript = incoming(port, key)
    try:
        assert status == 101
        second, status, _ = incoming(port, key)
        second.close()
        assert status == 403, "one inbound connection per configured member"
        first.send(1, b'{"op":"sub","topic":"audit","args":{}}')
        assert first.receive()[0] == 8, "peer key must not grant audit/browser access"
    finally:
        first.close()
    time.sleep(0.3)
    replay, status, _ = incoming(port, key, transcript)
    replay.close()
    assert status == 403, "used proof must not be replayable"
    bad, status, _ = incoming(port, key, proof_override=bytes(32))
    bad.close()
    assert status == 403


def dashboard(port, cookie):
    client = Client.from_stream(Stream(port, cookie, "/console/ws",
                                       origin="https://console.test",
                                       extra_headers={"X-Forwarded-Proto": "https"}))
    try:
        client.command("sub", "stats")
        client.until(lambda: client.states.get("stats", {}).get("scope", {})
                     .get("contributing") == 2)
        combined = client.states["stats"]
        assert combined["node"] == 0 and combined["requests"] >= 12345, combined
        assert combined["countries"][0] == {"code": 0x5553, "samples": 3}
        assert combined["incident_geo"]["countries"][0] == {"code": 0x4155, "samples": 2}
        epoch = client.epochs["stats"]
        client.command("filter", "stats", {"node": 2})
        client.until(lambda: client.epochs["stats"] != epoch and "stats" not in client.pending)
        selected = client.states["stats"]
        assert selected["node"] == 2 and selected["requests"] == 12345, selected
        assert selected["scope"]["selected"] == 2 and not selected["scope"]["stale"]
        epoch = client.epochs["stats"]
        client.command("filter", "stats", {"node": 99})
        client.until(lambda: client.epochs["stats"] != epoch and "stats" not in client.pending)
        missing = client.states["stats"]
        assert missing["available"] is False and "requests" not in missing, missing
        assert not client.gaps
    finally:
        client.close()


def check(binary, h):
    headers = {"Origin": "https://console.test", "X-Forwarded-Proto": "https"}
    trusted = SimpleNamespace(request=lambda *a, **kw: h.request(*a, **kw, extra_headers=headers))
    with tempfile.TemporaryDirectory(prefix="sibuna-peer-") as directory:
        root = Path(directory)
        cert, tls_key = fixture.certificate(root)
        master = os.urandom(32)
        key_file, console_key = root / "peer.key", root / "console.key"
        for path, value in ((key_file, master), (console_key, os.urandom(32))):
            path.write_text(value.hex())
            path.chmod(0o600)
        peer_port, port = h.port(), h.port()
        peer = fixture.Peer(peer_port, cert, tls_key, master)
        temporary = bootstrap.initialize(binary, str(root / "data"), "peer-admin")
        extra = ("--console-peer", f"2=https://localhost:{peer_port}",
                 "--console-peer-key-file", str(key_file), "--console-peer-ca-file", str(cert))
        proc = None
        observed = []
        try:
            with (root / "daemon.log").open("w+") as log:
                proc = h.start(binary, str(root / "data"), port, log, str(console_key), True,
                               extra=extra)
                credentials, _, _, recovery = totp.enroll(trusted, port, temporary, True)
                # Password change and factor setup intentionally consume verification slots.
                h.stop(proc)
                proc = None
                proc = h.start(binary, str(root / "data"), port, log, str(console_key), True,
                               extra=extra)
                status, response, body = trusted.request(port, "POST", "/console/api/login",
                                                       dict(credentials, code=recovery[0]))
                assert status == 200, body
                cookie = response["Set-Cookie"].split(";", 1)[0]
                peer.snapshot = json.loads(trusted.request(port, "GET", "/console/api/stats",
                                                          cookie=cookie)[2])
                peer.snapshot["geoip_available"] = True
                peer.snapshot["countries"][0] = {"code": 0x5553, "samples": 3}
                peer.snapshot["incident_geo"]["countries"][0] = {"code": 0x4155, "samples": 2}
                def report():
                    status, _, body = trusted.request(port, "GET", "/console/api/nodes", cookie=cookie)
                    assert status == 200, body
                    rows = json.loads(body)["peers"]
                    assert len(rows) == 1 and rows[0]["node"] == 2
                    observed.append(rows[0])
                    return rows[0]
                current = wait(lambda: (row if (row := report())["status"] == "current" else None),
                               "certificate and HMAC verified snapshot")
                assert current["requests"] == 12345 and current["age_seconds"] <= 2
                assert current["geoip_available"] is True
                mark = current["watermark"]
                wait(lambda: report()["watermark"] > mark, "unsolicited delta")
                dashboard(port, cookie)
                admission(port, peer.key)
                peer.mode = "silent"
                stale = wait(lambda: (row if (row := report())["status"] == "stale" and
                                       row["age_seconds"] >= 10 else None),
                             "silent peer becomes stale", 20)
                assert stale["requests"] == 12345 and stale["age_seconds"] >= 10, stale
                peer.boot = os.urandom(16)
                peer.mode = "current"
                changed = wait(lambda: (row if (row := report())["status"] == "current" and
                                        row["boot"] == peer.boot.hex() else None), "boot recovery")
                assert changed["resets"] == 1
                peer.mode = "disconnect"
                wait(lambda: report()["status"] == "stale", "closed connection")
                peer.mode = "wrong-proof"
                rejected = wait(lambda: (row if (row := report())["status"] == "rejected"
                                         else None), "forged server proof")
                assert rejected["requests"] == 12345
                peer.mode = "current"
                # Stop cancels an active connection or an in-flight reconnect before freeing state.
                h.stop(proc)
                proc = None
                # Numeric hostname fails the localhost-only certificate even under this CA.
                wrong_host = list(extra)
                wrong_host[1] = f"2=https://127.0.0.1:{peer_port}"
                before = peer.authenticated
                rejected_tls = peer.tls_rejected
                proc = h.start(binary, str(root / "data"), port, log, str(console_key), True,
                               extra=wrong_host)
                wait(lambda: peer.tls_rejected > rejected_tls, "hostname rejection", 15)
                assert peer.authenticated == before, "hostname verification was bypassed"
                h.stop(proc)
                proc = None
                # Omitting the private trust anchor must also reject the self-signed peer.
                rejected_tls = peer.tls_rejected
                proc = h.start(binary, str(root / "data"), port, log, str(console_key), True,
                               extra=extra[:-2])
                wait(lambda: peer.tls_rejected > rejected_tls, "untrusted CA rejection", 20)
                assert peer.authenticated == before
                h.stop(proc)
                proc = None
                assert not peer.errors, peer.errors
        except BaseException:
            text = (root / "daemon.log").read_text()
            print(text[-5000:])
            print("last peer reports:", observed[-5:])
            print("fixture failures:", peer.errors)
            raise
        finally:
            if proc is not None:
                h.stop(proc)
            peer.close()
    print("console-e2e: TLS peer proof, masking, quota, replay, stale, boot and cancellation passed")


if __name__ == "__main__":
    import sys
    import console_e2e as harness
    check(sys.argv[1], harness)
