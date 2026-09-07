"""Join accept workers, idle requests and a subscription before releasing shared owners."""
import json
from pathlib import Path
import socket
import tempfile
import console_bootstrap_test
import console_ws_test


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-shutdown-") as root:
        directory = str(Path(root) / "data")
        temporary = console_bootstrap_test.initialize(binary, directory, "shutdown-admin")
        policy = Path(root) / "policy.json"
        policy.write_text(json.dumps({"rules": [
            {"name": "shutdown-origin", "path": "/stall", "action": "ALLOW"}]}))
        with (Path(root) / "daemon.log").open("w+") as log, socket.socket() as origin:
            origin.bind(("127.0.0.1", 0))
            origin.listen(1)
            origin.settimeout(5)
            extra = ("--upstream-port", str(origin.getsockname()[1]),
                     "--policy-file", str(policy))
            port = h.port()
            proc = h.start(binary, directory, port, log, workers=4, extra=extra)
            clients = []
            stream = None
            try:
                credentials = console_bootstrap_test.change(
                    h, port, temporary, "shutdown verification permanent password")
                status, headers, _ = h.request(port, "POST", "/console/api/login", credentials)
                assert status == 200
                cookie = headers["Set-Cookie"].split(";", 1)[0]
                stream = console_ws_test.Stream(port, cookie)
                stream.send(1, b'{"op":"subscribe","topics":["stats"]}')
                assert stream.receive()[0] == 1
                data_port = int(proc.args[proc.args.index("--port") + 1])
                stalled = socket.create_connection(("127.0.0.1", data_port), timeout=5)
                clients.append(stalled)
                stalled.sendall(b"GET /stall HTTP/1.1\r\nHost: localhost\r\n\r\n")
                upstream, _ = origin.accept()
                clients.append(upstream)
                upstream.settimeout(5)
                assert b"/stall" in upstream.recv(8192)
                for index in range(16):
                    target = data_port if index % 2 else port
                    client = socket.create_connection(("127.0.0.1", target), timeout=5)
                    client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
                    clients.append(client)
                h.stop(proc)
                assert proc.returncode == 0
            finally:
                if proc.poll() is None:
                    h.stop(proc)
                if stream:
                    stream.close()
                for client in clients:
                    client.close()
            proc = h.start(binary, directory, port, log, workers=4, extra=extra)
            try:
                status, _, body = h.request(port, "POST", "/console/api/login", credentials)
                assert status == 200 and not json.loads(body)["must_change"]
            finally:
                h.stop(proc)
            log.seek(0)
            assert "leaked" not in log.read().lower()
    print("console-e2e: graceful multi-worker shutdown, active streams and restart passed")
