"""The console survives mode changes and identifies which origin counters are observable."""
import json
from pathlib import Path
import tempfile
import subprocess
import console_bootstrap_test as bootstrap
from console_users_test import login
from console_ws_test import Stream
from proxy_e2e import exchange
from proxy_fixture import origin


def check(binary, h):
    query_options(binary)
    application, worker = origin()
    try:
        with tempfile.TemporaryDirectory(prefix="sibuna-console-modes-") as directory:
            root = Path(directory)
            data = str(root / "data")
            temporary = bootstrap.initialize(binary, data, "admin")
            (root / "policy.json").write_text(json.dumps({
                "default_action": "ALLOW", "waf": True, "rules": [],
            }))
            credentials = None
            previous_boot = None
            for mode in ("reverse_proxy", "forward_auth"):
                port, data_port = h.port(), h.port()
                with (root / "daemon.log").open("w+") as log:
                    proc = h.start(binary, data, port, log, extra=(
                        "-m", mode, "--port", str(data_port),
                        "--console-query-steps", "8000000",
                        "--policy-file", str(root / "policy.json"),
                        "--upstream-port", str(application.server_port),
                    ))
                    try:
                        if credentials is None:
                            credentials = bootstrap.change(h, port, temporary,
                                                           "console mode test passphrase")
                        cookie, _, _ = login(h, port, credentials)
                        code, _, _ = exchange(data_port, "/origin-error", {})
                        assert code == (500 if mode == "reverse_proxy" else 200)
                        if mode == "forward_auth":
                            code, _, reply = exchange(data_port, "/auth", {
                                "X-Original-URI": "/__sibuna/health",
                            })
                            assert code == 200 and reply == b"OK"
                        status, _, body = h.request(port, "GET", "/console/api/stats",
                                                    cookie=cookie)
                        assert status == 200
                        snapshot = json.loads(body)
                        assert snapshot["proxy_mode"] == mode
                        assert int(snapshot["admitted"]) == (1 if mode == "reverse_proxy" else 2)
                        assert int(snapshot["origin_5xx"]) == (1 if mode == "reverse_proxy" else 0)
                        assert snapshot["boot"] != previous_boot
                        previous_boot = snapshot["boot"]
                        stream = Stream(port, cookie)
                        try:
                            stream.send(1, b'{"op":"subscribe","topics":["stats"]}')
                            opcode, body = stream.receive()
                            assert opcode == 1 and json.loads(body)["data"]["proxy_mode"] == mode
                        finally:
                            stream.close()
                    finally:
                        h.stop(proc)
    finally:
        application.shutdown()
        application.server_close()
        worker.join(timeout=5)
    print("console-e2e: both CLI modes, origin coverage, subscriptions and restart passed")


def query_options(binary):
    for options in (("99999",), ("50000001",), ("4M",), ("-1",), (),
                    ("100000", "--console-query-steps", "200000")):
        result = subprocess.run([binary, "--console", "127.0.0.1:9443",
                                 "--console-query-steps", *options],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 1, (options, result.returncode)
        assert "CONSOLE002" in result.stderr and "Hint:" in result.stderr, result.stderr
