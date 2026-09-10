#!/usr/bin/env python3
"""Verify eight real dashboard network clients; this is not a throughput measurement."""
import json
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import console_e2e as h  # noqa: E402
import console_bootstrap_test as bootstrap  # noqa: E402
from console_users_test import login  # noqa: E402
from console_dashboard import Dashboard, covered, difference, stop_clients  # noqa: E402


def check(binary):
    with tempfile.TemporaryDirectory(prefix="sibuna-dashboard-workload-") as directory:
        root = Path(directory)
        temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
        with (root / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, str(root / "data"), port, log)
            clients = []
            try:
                credentials = bootstrap.change(h, port, temporary, "dashboard workload test phrase")
                cookie, csrf, _ = login(h, port, credentials)
                for _ in range(8):
                    client = Dashboard(h, port, cookie, csrf)
                    clients.append(client)
                    client.start()
                before = [client.snapshot() for client in clients]
                started = time.monotonic()
                time.sleep(15)
                elapsed = time.monotonic() - started
                after = [client.snapshot() for client in clients]
                sample = {"wall_seconds": elapsed, "dashboards": difference(before, after)}
                assert covered([sample], 8), json.dumps(sample)
                assert all(client["period_scans"] > 0 and client["period_pages"] >= 2
                           for client in after), after
            finally:
                failures = stop_clients(clients)
                h.stop(proc)
                if failures:
                    raise RuntimeError("dashboard clients failed to close") from failures[0]
    print("dashboard-workload: eight streams, retained periods, rankings and timeline passed")


if __name__ == "__main__":
    check(str(Path(sys.argv[1]).resolve()))
