"""Bounded TLS peer fixture using the documented HMAC and RFC 6455 wire contracts."""
import base64
import hashlib
import hmac
import json
import os
import socketserver
import ssl
import struct
import sys
import subprocess
import threading
import time


def proof(key, domain, data):
    return hmac.new(key, b"sibuna-console-peer-v1/" + domain + data, hashlib.sha256).digest()


def certificate(root):
    cert, key = root / "peer.pem", root / "peer-tls.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-keyout", str(key), "-out", str(cert)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


class Peer(socketserver.ThreadingTCPServer):
    daemon_threads = False
    allow_reuse_address = True

    def __init__(self, port, cert, tls_key, master):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, tls_key)
        self.key = proof(master, b"key", b"")
        self.boot = os.urandom(16)
        self.snapshot = None
        self.mode = "current"
        self.errors = []
        self.authenticated = 0
        self.tls_rejected = 0
        self.closed = threading.Event()
        super().__init__(("127.0.0.1", port), Handler)
        self.thread = threading.Thread(target=self.serve_forever)
        self.thread.start()

    def handle_error(self, request, client_address):
        error = sys.exc_info()[1]
        if isinstance(error, ssl.SSLError):
            self.tls_rejected += 1
        if not isinstance(error, (ssl.SSLError, OSError)):
            self.errors.append(repr(error))

    def close(self):
        self.closed.set()
        self.shutdown()
        self.server_close()
        self.thread.join()


class Handler(socketserver.StreamRequestHandler):
    def setup(self):
        self.request.settimeout(3)
        try:
            self.request = self.server.context.wrap_socket(self.request, server_side=True)
        except (OSError, ssl.SSLError):
            self.request.close()
            raise
        super().setup()

    def handle(self):
        try:
            self.exchange()
        except (OSError, ssl.SSLError):
            pass
        except BaseException as error:
            self.server.errors.append(repr(error))

    def exchange(self):
        assert self.rfile.readline(1024) == b"GET /console/peer HTTP/1.1\r\n"
        headers = {}
        for _ in range(32):
            line = self.rfile.readline(1024)
            if line == b"\r\n":
                break
            name, value = line.decode().strip().split(":", 1)
            assert name.lower() not in headers
            headers[name.lower()] = value.strip()
        else:
            raise AssertionError("unbounded request head")
        transcript = bytes.fromhex(headers["x-sibuna-peer"])
        assert len(transcript) == 64
        node, target, stamp = struct.unpack("!IIQ", transcript[:16])
        assert node == 1 and target == 2 and abs(time.time() - stamp) < 31
        assert transcript[48:] == base64.b64decode(headers["sec-websocket-key"])
        assert hmac.compare_digest(proof(self.server.key, b"client", transcript),
                                   bytes.fromhex(headers["x-sibuna-proof"]))
        self.server.authenticated += 1
        identity = self.server.boot + os.urandom(32)
        signature = proof(self.server.key, b"server", transcript + identity)
        if self.server.mode == "wrong-proof":
            signature = bytes(32)
        accept = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"] +
                    "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.wfile.write(("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                          "Upgrade: websocket\r\n" + f"Sec-WebSocket-Accept: {accept}\r\n"
                          f"X-Sibuna-Peer: {identity.hex()}\r\n"
                          f"X-Sibuna-Proof: {signature.hex()}\r\n\r\n").encode())
        self.wfile.flush()
        command = self.command()
        assert command == {"op": "sub", "topic": "stats", "args": {}}
        sequence = 0
        epoch = os.urandom(16).hex() + ":1"
        while not self.server.closed.wait(1):
            if self.server.mode == "silent":
                continue
            if self.server.mode == "disconnect":
                return
            value = self.server.snapshot
            if value is None:
                continue
            data = dict(value, node=2, boot=list(self.server.boot), timestamp=int(time.time()),
                        uptime_ms=int(time.monotonic() * 1000), requests=12345)
            mark = data["uptime_ms"]
            initial = sequence == 0
            payload = data if initial else {"set": data, "remove": []}
            text = json.dumps(payload, separators=(",", ":"))
            parts = [text[i:i + 480] for i in range(0, len(text), 480)]
            if initial:
                self.frame(dict(op="snapshot_begin", topic="stats", epoch=epoch, seq=0,
                                watermark=mark, snapshot=True, parts=len(parts)))
                sequence += 1
            for i, part in enumerate(parts):
                self.frame(dict(op="snapshot_chunk" if initial else "delta",
                                topic="stats", epoch=epoch, seq=sequence, watermark=mark,
                                snapshot=initial, parts=len(parts), part=i,
                                update=mark, kind="patch", data=part))
                sequence += 1
            if initial:
                self.frame(dict(op="snapshot_end", topic="stats", epoch=epoch, seq=sequence,
                                watermark=mark, snapshot=True))
                sequence += 1

    def command(self):
        head = self.rfile.read(2)
        if not head:
            raise ConnectionResetError()
        assert head[0] == 0x81 and head[1] & 128, "peer client must mask text frames"
        length = head[1] & 127
        if length == 126:
            length = struct.unpack("!H", self.rfile.read(2))[0]
        assert length <= 2048
        mask = self.rfile.read(4)
        payload = self.rfile.read(length)
        return json.loads(bytes(v ^ mask[i % 4] for i, v in enumerate(payload)))

    def frame(self, value):
        payload = json.dumps(value, separators=(",", ":")).encode()
        assert len(payload) < 2048
        header = b"\x81" + (bytes([len(payload)]) if len(payload) < 126 else
                            b"\x7e" + struct.pack("!H", len(payload)))
        self.wfile.write(header + payload)
        self.wfile.flush()
