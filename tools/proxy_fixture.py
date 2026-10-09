"""Real origin and bounded WebSocket client for reverse-proxy compatibility checks."""
import base64
import hashlib
import http.server
import json
import os
import socket
import struct
import threading
from email import policy as email_policy
from email.parser import BytesParser

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def masked_payload(payload, mask):
    assert len(mask) == 4
    # Keep large fixture frames out of Python's per-byte interpreter loop. An
    # emulated origin must still answer within the real daemon's idle deadline.
    result = bytearray(len(payload))
    for offset, key in enumerate(mask):
        table = bytes(byte ^ key for byte in range(256))
        result[offset::4] = payload[offset::4].translate(table)
    return bytes(result)


def http_response(reader):
    line = reader.readline(16385)
    status = int(line.split()[1])
    headers, length = {}, len(line)
    while (line := reader.readline(16385)) != b"\r\n":
        length += len(line)
        assert line and length <= 16384, "invalid fixture response head"
        name, value = line.decode().split(":", 1)
        headers[name.lower()] = value.strip()
    size = int(headers.get("content-length", "0"))
    assert 0 <= size <= 4 * 1024 * 1024
    body = reader.read(size)
    assert len(body) == size
    return status, headers, body


def frame(opcode, payload, masked=False, final=True):
    flag = 128 if masked else 0
    prefix = bytes([(128 if final else 0) | opcode])
    if len(payload) < 126:
        prefix += bytes([flag | len(payload)])
    elif len(payload) <= 65535:
        prefix += bytes([flag | 126]) + struct.pack("!H", len(payload))
    else:
        prefix += bytes([flag | 127]) + struct.pack("!Q", len(payload))
    if not masked:
        return prefix + payload
    mask = os.urandom(4)
    return prefix + mask + masked_payload(payload, mask)


def receive(reader, masked):
    head = reader.read(2)
    assert len(head) == 2, "unexpected end of WebSocket stream"
    assert bool(head[1] & 128) == masked
    length = head[1] & 127
    if length == 126:
        length = struct.unpack("!H", reader.read(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", reader.read(8))[0]
    assert length <= 4 * 1024 * 1024
    mask = reader.read(4) if masked else None
    payload = reader.read(length)
    assert len(payload) == length
    if masked:
        payload = masked_payload(payload, mask)
    return head[0] & 15, payload, bool(head[0] & 128)


def closed(reader, message):
    """A bounded shutdown may finish with FIN or an explicit native reset."""
    try:
        data = reader.read(1)
    except ConnectionResetError:
        return
    assert data == b"", message


class Origin(http.server.BaseHTTPRequestHandler):
    # Headers and bodies are separate writes. Avoid Nagle/delayed-ACK interactions
    # dominating the 4096-request compatibility test on macOS and Linux runners.
    disable_nagle_algorithm = True
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.requests.append((self.path, dict(self.headers)))
        if self.path.split("?", 1)[0] in ("/ws", "/bad-upgrade", "/half"):
            return self.upgrade()
        if self.path == "/browser":
            return self.reply(200, BROWSER.encode(), "text/html")
        if self.path == "/origin-error":
            return self.reply(500, b"controlled origin failure", "text/plain")
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://application.example/login?next=%2Fprivate")
            self.send_header("Set-Cookie", "application=opaque; HttpOnly; Secure; SameSite=Lax")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/early":
            self.wfile.write(b'HTTP/1.1 103 Early Hints\r\nLink: </app.css>; rel=preload\r\n\r\n')
        body = json.dumps({"path": self.path, "headers": dict(self.headers)}).encode()
        return self.reply(200, body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append((self.path, dict(self.headers)))
        if self.path == "/drop-after-post":
            self.close_connection = True
            return
        if self.path == "/multipart":
            prefix = f"Content-Type: {self.headers['Content-Type']}\r\nMIME-Version: 1.0\r\n\r\n"
            message = BytesParser(policy=email_policy.default).parsebytes(prefix.encode() + body)
            assert message.is_multipart() and not message.defects
            parts = []
            for part in message.iter_parts():
                payload = part.get_payload(decode=True)
                parts.append({"name": part.get_param("name", header="content-disposition"),
                              "filename": part.get_filename(), "type": part.get_content_type(),
                              "bytes": len(payload),
                              "sha256": hashlib.sha256(payload).hexdigest()})
            return self.reply(200, json.dumps(parts).encode())
        return self.reply(200, body, self.headers.get("Content-Type", "application/octet-stream"))

    def reply(self, status, body, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def upgrade(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        assert self.headers.get("Upgrade", "").lower() == "websocket"
        assert self.headers.get("Connection", "").lower() == "upgrade"
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        if self.path == "/bad-upgrade":
            accept = "incorrect"
        head = ("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                "Upgrade: websocket\r\nSec-WebSocket-Accept: " + accept + "\r\n")
        if self.headers.get("Sec-WebSocket-Protocol"):
            head += "Sec-WebSocket-Protocol: chat\r\n"
        self.close_connection = True
        if self.path == "/half":
            self.wfile.write((head + "\r\n").encode() + b"before")
            data = self.rfile.read()
            self.wfile.write(b"done:" + data)
            return
        self.wfile.write((head + "\r\n").encode() + frame(1, b"origin ready"))
        if self.path == "/bad-upgrade":
            return
        try:
            while True:
                opcode, payload, final = receive(self.rfile, masked=True)
                self.wfile.write(frame(10 if opcode == 9 else opcode, payload, final=final))
                if opcode == 8:
                    return
        except (OSError, AssertionError):
            return

    def log_message(self, *args):
        pass


def origin():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


class WebSocket:
    def __init__(self, port, headers, path="/ws", tls=None, extra=b"", expected=101):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=8)
        if tls:
            self.socket = tls.wrap_socket(self.socket, server_hostname="localhost")
        self.reader = self.socket.makefile("rb")
        key = base64.b64encode(os.urandom(16)).decode()
        values = {"Host": f"localhost:{port}", "Connection": "keep-alive, Upgrade",
                  "Upgrade": "websocket", "Sec-WebSocket-Version": "13",
                  "Sec-WebSocket-Key": key, "Sec-WebSocket-Protocol": "chat, other", **headers}
        head = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in values.items())
        self.socket.sendall((head + "\r\n").encode() + extra)
        try:
            status = self.reader.readline()
            assert int(status.split()[1]) == expected, status
            self.headers = {}
            while (line := self.reader.readline()) != b"\r\n":
                assert line
                name, value = line.decode().split(":", 1)
                self.headers[name.lower()] = value.strip()
            if expected == 101:
                accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
                assert self.headers["sec-websocket-accept"] == accept
                assert self.headers["upgrade"].lower() == "websocket"
                assert self.headers["sec-websocket-protocol"] == "chat"
        except BaseException:
            self.close()
            raise

    def close(self):
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.reader.close()
        self.socket.close()


BROWSER = '''<!doctype html><html lang="en"><meta charset="utf-8">
<title>Sibuna WebSocket proxy acceptance</title><h1>WebSocket proxy acceptance</h1>
<button id="run">Run WebSocket check</button><p id="result" role="status">Ready</p>
<script>
document.querySelector('#run').onclick = () => {
  const result = document.querySelector('#result');
  result.textContent = 'Connecting through Sibuna…';
  const socket = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://')
    + location.host + '/ws', 'chat');
  let greeted = false;
  const timeout = setTimeout(() => {
    result.textContent = 'FAIL: timeout'; socket.close();
  }, 5000);
  socket.onmessage = event => {
    if (event.data === 'origin ready') {
      greeted = true; socket.send('Chrome bidirectional echo');
    }
    else if (greeted && event.data === 'Chrome bidirectional echo') {
      clearTimeout(timeout);
      result.textContent = 'PASS: unsolicited origin message and browser echo through Sibuna';
      socket.close(1000, 'verified');
    }
  };
  socket.onerror = () => { clearTimeout(timeout); result.textContent = 'FAIL: WebSocket error'; };
};
</script></html>'''
