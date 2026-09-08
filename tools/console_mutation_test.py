"""One mutation allowance spans account, policy and GeoIP routes after authentication."""
import json
from pathlib import Path
import tempfile
import console_bootstrap_test as bootstrap
from console_users_test import login


def exercise(h, port, credentials):
    cookie, csrf, _ = login(h, port, credentials)
    # Invalid submissions count, but an outsider cannot spend a session's allowance.
    routes = (("users/create", {"username": "invalid user"}),
              ("policies/edit", {"expected_revision": "invalid", "document": "{}"}),
              ("inspection/edit", {"expected_revision": "invalid", "document": "{}"}),
              ("geoip", {"source_version": "invalid", "expected_revision": 0}))
    for route, body in routes:
        path = "/console/api/" + route
        assert h.request(port, "POST", path, body, cookie)[0] == 400
        assert h.request(port, "POST", path, body, csrf=csrf)[0] == 401
    for index in range(60):
        route, body = routes[index % len(routes)]
        status = h.request(port, "POST", "/console/api/" + route, body, cookie, csrf)[0]
        assert status == 400, (index, status)
    for route, body in routes:
        status, _, result = h.request(port, "POST", "/console/api/" + route,
                                      body, cookie, csrf)
        assert status == 429 and json.loads(result)["error"] == "CONSOLEMUTATION"
        assert "one minute" in json.loads(result)["hint"]
    # Reads retain capacity: the old per-handler count must not double-charge writes.
    assert h.request(port, "POST", "/console/api/users/query", {}, cookie, csrf)[0] == 200
    second, second_csrf, _ = login(h, port, credentials)
    assert second != cookie
    assert h.request(port, "POST", "/console/api/" + routes[0][0], routes[0][1],
                     second, second_csrf)[0] == 400


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-mutation-") as root:
        root = Path(root)
        temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
        with (root / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, str(root / "data"), port, log)
            try:
                credentials = bootstrap.change(h, port, temporary,
                                               "management rate review passphrase")
                exercise(h, port, credentials)
            finally:
                h.stop(proc)
    print("console-e2e: shared mutation allowance, CSRF isolation and read capacity passed")
