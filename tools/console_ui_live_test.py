#!/usr/bin/env python3
"""Run the shipped Wasm against a live daemon. Chrome separately verifies the real DOM."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import console_e2e as h
import console_bootstrap_test as bootstrap
from console_users_test import login
from console_ws_test import Stream


class Interface:
    def __init__(self, port, cookie, wasm):
        self.port, self.cookie = port, cookie
        self.stream, self.connections, self.html = None, 0, ""
        self.history = []
        self.appearance = None
        self.proc = subprocess.Popen(["node", "tools/console_ui_driver.mjs", str(wasm)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def event(self, kind=None, value=None, **options):
        if kind is not None:
            value["browser_time"] = int(time.time())
            options = {"kind": kind, "value": value}
        self.proc.stdin.write(json.dumps(options) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        assert line, "Wasm driver exited"
        result = json.loads(line)
        self.html = result["html"]
        assert self.html, "render capacity exceeded"
        assert "Could not complete the action" not in self.html
        for command in result["commands"]:
            self.command(command)

    def command(self, command):
        op = command["op"]
        if op == "appearance":
            self.appearance = command
        elif op == "history":
            self.history.append(command)
        elif op == "connect":
            assert self.stream is None, "second connection opened without closing the first"
            assert command["path"] == "/console/ws"
            self.stream = Stream(self.port, self.cookie, command["path"])
            self.connections += 1
            self.event(4, {"state": "open"})
        elif op == "disconnect":
            if self.stream:
                self.stream.close()
                self.stream = None
        elif op == "send":
            assert self.stream is not None
            self.stream.send(1, json.dumps(command["body"]).encode())
        elif op == "request":
            status, _, body = h.request(self.port, command["method"], command["path"],
                                        command.get("body"), self.cookie, command.get("csrf"))
            self.event(2, {"id": command["id"], "status": status, "body": json.loads(body)})
        elif op == "geometry":
            status, _, body = h.request(self.port, "GET", command["path"], cookie=self.cookie)
            assert status == 200
            self.event(geometry=base64.b64encode(body).decode())

    def receive(self):
        assert self.stream is not None
        opcode, body = self.stream.receive()
        if opcode == 9:
            self.stream.send(10, body)
            return None
        assert opcode == 1, (opcode, body)
        value = json.loads(body)
        self.event(4, {"state": "message", "body": value})
        return value

    def topic(self, topic, seconds=15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = self.receive()
            if not value or value.get("topic") != topic:
                continue
            if value.get("op") == "snapshot_end" or (value.get("op") == "delta" and
                                                       value["part"] + 1 == value["parts"]):
                return
        raise AssertionError(("topic did not complete", topic))

    def close(self):
        if self.stream:
            self.stream.close()
        self.proc.stdin.close()
        try:
            assert self.proc.wait(timeout=10) == 0
        finally:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
            self.proc.stdout.close()


def exercise(ui):
    ui.event(init=True)
    ui.topic("stats")
    ui.event(9, {"theme": "system", "density": "compact", "system_dark": True})
    assert ui.appearance["theme"] == "dark" and not ui.appearance["persist"]
    assert "Theme: system" in ui.html and "Spacing: compact" in ui.html
    ui.event(1, {"action": "theme", "fields": {}})
    assert ui.appearance["theme"] == "light" and ui.appearance["persist"]
    ui.event(10, {"system_dark": True})
    assert ui.appearance["theme"] == "light"
    ui.event(1, {"action": "density", "fields": {}})
    assert ui.appearance["density"] == "comfortable" and ui.appearance["persist"]
    assert "Traffic overview" in ui.html and "console-navigation" in ui.html
    for page, topic in (("events", "events"), ("policies", "policy"), ("nodes", "nodes"),
                        ("challenges", "challenges"), ("audit", "audit")):
        ui.event(1, {"action": page, "fields": {}})
        ui.topic(topic)
        assert "console-navigation" in ui.html, page
        assert ui.connections == 1, (page, ui.connections)
    assert ui.history[-1] == {"op": "history", "value": "audit", "replace": False}
    ui.event(8, {"route": "nodes"})
    ui.topic("nodes")
    assert ui.history[-1] == {"op": "history", "value": "nodes", "replace": True}
    ui.event(8, {"route": "unknown-page"})
    ui.topic("stats")
    assert ui.history[-1] == {"op": "history", "value": "dashboard", "replace": True}
    ui.event(4, {"state": "invalid", "entropy": 12345})
    assert ui.stream is None and "Disconnected" in ui.html
    ui.event(3, {"id": "live-retry"})
    ui.topic("stats")
    assert ui.connections == 2 and "Traffic overview" in ui.html
    ui.event(1, {"action": "logout", "fields": {}})
    assert ui.stream is None and "Welcome back" in ui.html
    assert "console-navigation" not in ui.html and "globe-scene" not in ui.html
    ui.event(10, {"system_dark": True})
    assert ui.appearance["theme"] == "light"
    ui.event(8, {"route": "nodes"})
    assert ui.stream is None and "Welcome back" in ui.html


def check(binary):
    with tempfile.TemporaryDirectory(prefix="sibuna-console-ui-") as directory:
        root = Path(directory)
        temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
        with (root / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, str(root / "data"), port, log)
            ui = None
            try:
                credentials = bootstrap.change(h, port, temporary, "wasm live test passphrase")
                cookie, _, _ = login(h, port, credentials)
                status, _, body = h.request(port, "GET", "/console/assets/console.wasm")
                assert status == 200
                wasm = root / "console.wasm"
                wasm.write_bytes(body)
                ui = Interface(port, cookie, wasm)
                exercise(ui)
            finally:
                try:
                    if ui:
                        ui.close()
                finally:
                    h.stop(proc)
    print("console-ui-e2e: shipped Wasm, six topics, navigation, resync and sign-out passed")


if __name__ == "__main__":
    check(str(Path(sys.argv[1]).resolve()))
