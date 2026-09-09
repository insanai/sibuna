"""Test-only bounded HTTPS ingress for real console-to-console management streams."""
import select
import socket
import socketserver
import ssl
import threading


class Ingress(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = False

    def __init__(self, port, target, certificate, private_key):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certificate, private_key)
        self.target = target
        self.closed = threading.Event()
        self.received = 0
        self.sent = 0
        self.connections = 0
        super().__init__(("127.0.0.1", port), Handler)
        self.thread = threading.Thread(target=self.serve_forever)
        self.thread.start()

    def close(self):
        self.closed.set()
        self.shutdown()
        self.server_close()
        self.thread.join()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            with self.server.context.wrap_socket(self.request, server_side=True) as front:
                with socket.create_connection(("127.0.0.1", self.server.target), timeout=3) as back:
                    self.server.connections += 1
                    self.forward_head(front, back)
                    self.relay(front, back)
        except (OSError, ssl.SSLError):
            pass

    def forward_head(self, front, back):
        data = b""
        while b"\r\n\r\n" not in data:
            if len(data) >= 16384:
                raise OSError("ingress head limit")
            part = front.recv(16384 - len(data))
            if not part:
                raise OSError("incomplete ingress head")
            data += part
        head, suffix = data.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        assert lines[0] == b"GET /console/peer HTTP/1.1"
        clean = [line for line in lines[1:] if line.split(b":", 1)[0].lower() != b"x-forwarded-proto"]
        back.sendall(b"\r\n".join([lines[0]] + clean + [b"X-Forwarded-Proto: https"]) +
                     b"\r\n\r\n" + suffix)

    def relay(self, front, back):
        while not self.server.closed.is_set():
            ready = [front] if front.pending() else select.select([front, back], [], [], 0.2)[0]
            for source in ready:
                data = source.recv(16384)
                if not data:
                    return
                if source is front:
                    back.sendall(data)
                    self.server.received += len(data)
                else:
                    front.sendall(data)
                    self.server.sent += len(data)
