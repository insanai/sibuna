"""Real socket checks for unsolicited delivery, framing, and revocation."""
import base64
import hashlib
import json
import os
import socket
import struct
import time


class Stream:
    def __init__(self, port, cookie, path="/console/stream", origin=None, extra_headers=None):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.file = self.sock.makefile("rb")
        key = base64.b64encode(os.urandom(16)).decode()
        origin = origin or f"http://127.0.0.1:{port}"
        extra = "".join(f"{key}: {value}\r\n" for key, value in (extra_headers or {}).items())
        head = (f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                f"Origin: {origin}\r\nCookie: {cookie}\r\n{extra}"
                "Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n"
                f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n")
        self.sock.sendall(head.encode())
        assert b" 101 " in self.file.readline()
        headers = {}
        while (line := self.file.readline()) != b"\r\n":
            assert line
            name, value = line.decode().split(":", 1)
            headers[name.lower()] = value.strip()
        expected = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        assert headers["sec-websocket-accept"] == expected

    def send(self, opcode, payload, final=True):
        assert len(payload) <= 4096
        mask = os.urandom(4)
        length = len(payload)
        frame = bytes([(128 if final else 0) | opcode,
                       128 | (length if length < 126 else 126)])
        if length >= 126:
            frame += struct.pack("!H", length)
        frame += mask
        self.sock.sendall(frame + bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload)))

    def receive(self):
        head = self.file.read(2)
        assert len(head) == 2, "stream ended without close frame"
        assert head[0] & 128 and not head[1] & 128
        length = head[1] & 127
        if length == 126:
            length = struct.unpack("!H", self.file.read(2))[0]
        assert length <= 8192
        body = self.file.read(length)
        assert len(body) == length
        return head[0] & 15, body

    def close(self):
        self.file.close()
        self.sock.close()


def delivery(port, cookie):
    stream = Stream(port, cookie)
    try:
        # Control frames may interrupt a fragmented subscription message.
        stream.send(1, b'{"op":"subscribe",', final=False)
        stream.send(9, b"probe")
        stream.send(0, b'"topics":["stats"]}')
        messages = []
        pong = False
        while len(messages) < 2 or not pong:
            opcode, body = stream.receive()
            if opcode == 10:
                assert body == b"probe"
                pong = True
            else:
                assert opcode == 1, (opcode, body)
                messages.append(json.loads(body))
        assert messages[0]["op"] == "snapshot" and messages[0]["seq"] == 0
        assert messages[1]["op"] == "delta" and messages[1]["seq"] == 1
        assert messages[0]["epoch"] == messages[1]["epoch"]
        assert messages[1]["data"]["timestamp"] > messages[0]["data"]["timestamp"]
        before, after = (message["data"] for message in messages[:2])
        assert before["boot"] == after["boot"] and any(before["boot"])
        assert after["uptime_ms"] > before["uptime_ms"]
        assert before["outcomes_version"] == after["outcomes_version"] == 1
        for data in (before, after):
            assert data["requests"] == sum(data[key] for key in (
                "admitted", "challenged", "denied", "banned", "rate_limited", "other"))
        return stream
    except BaseException:
        stream.close()
        raise


def revoked(stream):
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            opcode, body = stream.receive()
            if opcode == 8:
                assert struct.unpack("!H", body[:2])[0] == 1008
                return
        raise AssertionError("revoked subscriber remained connected")
    finally:
        stream.close()


def idle_delivery(port, cookie):
    stream = Stream(port, cookie)
    try:
        stream.sock.settimeout(25)
        opcode, body = stream.receive()
        assert opcode == 9 and body == b"", (opcode, body)
        stream.send(10, body)
        stream.send(1, b'{"op":"subscribe","topics":["stats"]}')
        opcode, body = stream.receive()
        assert opcode == 1 and json.loads(body)["op"] == "snapshot"
    finally:
        stream.close()


def reject_invalid_upgrades(port, cookie):
    for protocol, key in (("HTTP/1.0", "AAAAAAAAAAAAAAAAAAAAAA=="),
                          ("HTTP/1.1", "!!!!!!!!!!!!!!!!!!!!!!==")):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall((f"GET /console/ws {protocol}\r\nHost: 127.0.0.1:{port}\r\n"
                          f"Origin: http://127.0.0.1:{port}\r\nCookie: {cookie}\r\n"
                          "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                          f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n")
                         .encode())
            with sock.makefile("rb") as stream:
                status = stream.readline(256)
                assert b" 400 " in status, (protocol, status)
