"""Owned daemon/origin/ingress stack; tests execute the book's actual configuration snippets."""
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import console_e2e as helper
from proxy_e2e import exchange
from proxy_fixture import origin
from run import ready

ROOT = Path(__file__).resolve().parents[1]


def recipe(kind, port, backend, application):
    chapter = (ROOT / "docs/book/09_operations.typ").read_text()
    section = chapter.split("=== Forward Auth Behind an Ingress", 1)[1]
    language = "caddyfile" if kind == "caddy" else "nginx"
    text = section.split(f"```{language}\n", 1)[1].split("```", 1)[0]
    text = text.replace("localhost:8080", f"127.0.0.1:{backend}")
    text = text.replace("127.0.0.1:8080", f"127.0.0.1:{backend}")
    text = text.replace("localhost:3000", f"127.0.0.1:{application}")
    text = text.replace("127.0.0.1:3000", f"127.0.0.1:{application}")
    if kind == "caddy":
        return "{\n admin off\n auto_https off\n}\n" + text.replace(
            "example.com", f"http://127.0.0.1:{port}")
    text = text.replace("listen 443 ssl;", f"listen 127.0.0.1:{port};")
    return ("daemon off; worker_processes 1; pid nginx.pid; error_log stderr;\n"
            "events { worker_connections 128; }\n"
            "http { access_log off; client_max_body_size 4m;\n" + text + "}\n")


def ingress_command(root, kind, binary, port, backend, application):
    config = root / ("Caddyfile" if kind == "caddy" else "nginx.conf")
    config.write_text(recipe(kind, port, backend, application))
    if kind == "caddy":
        return [binary, "run", "--config", str(config), "--adapter", "caddyfile"]
    return [binary, "-p", str(root) + "/", "-c", str(config)]


def healthy(proc, port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError("ingress exited before becoming healthy")
        try:
            if exchange(port, "/__sibuna/health", {})[0] == 200:
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("ingress did not become healthy")


@dataclass
class Stack:
    port: int
    backend: int
    application: object
    daemon: object


@contextmanager
def stack(binary, mode, ingress=None):
    with ExitStack() as owned:
        root = Path(owned.enter_context(tempfile.TemporaryDirectory(prefix="sibuna-mode-")))
        application, worker = origin()
        owned.callback(worker.join, 5)
        owned.callback(application.server_close)
        owned.callback(application.shutdown)
        (root / "secret").write_bytes(os.urandom(32))
        policy = {"default_action": "CHALLENGE", "waf": True, "rules": [
            {"name": "restricted", "path": "/restricted*", "action": "DENY"},
            {"name": "limited", "path": "/limited*", "action": "ALLOW",
             "limits": {"rate": 1, "window_seconds": 60}},
        ]}
        (root / "policy.json").write_text(json.dumps(policy))
        backend = helper.port()
        log = owned.enter_context((root / "sibuna.log").open("w+"))
        # Exercise both documented option spellings and forward-auth's default ingress trust.
        option = "-m" if mode == "forward_auth" else "--mode"
        daemon = subprocess.Popen([
            str(binary), "--host", "127.0.0.1", "--port", str(backend), "--workers", "1",
            option, mode, "--algorithm", "hashcash", "--difficulty", "8", "--rate-limit", "100000",
            "--upstream-port", str(application.server_port),
            "--secret-file", str(root / "secret"), "--policy-file", str(root / "policy.json"),
        ], stdout=log, stderr=log)
        owned.callback(helper.stop, daemon)
        ready(daemon, backend)
        port = backend
        if ingress:
            kind, executable = ingress
            port = helper.port()
            log = owned.enter_context((root / "ingress.log").open("w+"))
            command = ingress_command(root, kind, executable, port, backend,
                                      application.server_port)
            gateway = subprocess.Popen(command, stdout=log, stderr=log)
            owned.callback(helper.stop, gateway)
            try:
                healthy(gateway, port)
            except Exception as error:
                log.seek(0)
                raise AssertionError(log.read(8192)) from error
        yield Stack(port, backend, application, daemon)
