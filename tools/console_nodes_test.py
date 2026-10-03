"""Live local-node fencing, drain admission, idempotency, audit, roles and restart."""
import http.client
import json
from pathlib import Path
import socket
import tempfile
import time
import console_bootstrap_test as bootstrap
from console_users_test import login, rotate
from console_token_test import mint, bearer


def status(h, port, session):
    code, _, body = h.request(port, "GET", "/console/api/nodes/local", cookie=session[0])
    assert code == 200, code
    result = json.loads(body)
    assert len(result["operation_id"]) == 32 and int(result["operation_id"], 16) != 0
    return result


def members(h, port, session):
    code, _, body = h.request(port, "GET", "/console/api/nodes", cookie=session[0])
    assert code == 200, code
    return json.loads(body)


def command(h, port, session, fields, expected=200):
    code, _, body = h.request(port, "POST", "/console/api/nodes/command", fields, *session)
    assert code == expected, (code, expected)
    return json.loads(body)


def operation(node, kind):
    return dict(id=node["operation_id"], node=node["node"], boot=node["boot"],
                expected_revision=str(node["control_revision"]), kind=kind)


def refusal_checks(h, data_port):
    # Accept happens before the request's complete head arrives. The refusal must
    # survive the late fragment rather than becoming a reset with a lost response.
    with socket.create_connection(("127.0.0.1", data_port), timeout=2) as client:
        client.sendall(b"GET /__sibuna/health HTTP/1.1\r\n")
        time.sleep(0.02)
        client.sendall(b"Host: localhost\r\nConnection: close\r\n\r\n")
        response = http.client.HTTPResponse(client)
        response.begin()
        assert response.status == 503
        assert b"node is draining" in response.read()
        response.close()
    # A peer that sends no head must not monopolize the only acceptor. The second
    # client still receives its refusal within a bounded period, without any retry.
    with socket.create_connection(("127.0.0.1", data_port), timeout=2):
        started = time.monotonic()
        assert h.request(data_port, "GET", "/__sibuna/health")[0] == 503
        assert time.monotonic() - started < 1, "silent refusal peer held the acceptor"


def checks(h, port, data_port, admin):
    local = "/console/api/nodes/local"
    mutate = "/console/api/nodes/command"
    assert h.request(port, "GET", local)[0] == 401
    node = status(h, port, admin)
    assert not node["draining"] and len(node["boot"]) == 32
    # Membership: this node's own replicated row, a single-node storage role, and one
    # configured but unreachable probe target that must read as down, never as zero.
    # The first announcement can precede the advertised origin by one tick; wait for both.
    deadline = time.monotonic() + 15
    while True:
        page = members(h, port, admin)
        rows = page["page"]["members"]
        if rows and rows[0]["console_url"] and any(p["health"] == "down"
                                                    for p in page["probes"]):
            break
        assert time.monotonic() < deadline, page
        time.sleep(0.25)
    assert page["page"]["self"] == node["node"] and len(rows) == 1
    assert rows[0]["node"] == node["node"] and rows[0]["boot"] == node["boot"]
    assert int(rows[0]["applied_revision"]) == int(node["applied"])
    assert rows[0]["console_url"] == f"http://127.0.0.1:{port}"
    assert page["page"]["storage"]["role"] == "single" and page["page"]["storage"]["quorum"]
    assert [p["node"] for p in page["probes"]] == [9]
    assert h.request(port, "GET", "/console/api/nodes")[0] == 401
    request = operation(node, "drain")
    assert h.request(port, "POST", mutate, request, cookie=admin[0])[0] == 400
    invalid = dict(request, boot="0" * 32)
    command(h, port, admin, invalid, 400)
    command(h, port, admin, dict(request, node=node["node"] + 1), 400)
    old = http.client.HTTPConnection("127.0.0.1", data_port, timeout=10)
    try:
        old.request("GET", "/__sibuna/health")
        reply = old.getresponse()
        assert reply.status == 200
        reply.read()
        socket = old.sock
        receipt = command(h, port, admin, request)
        assert receipt["state"] == "applied" and receipt["completion_persisted"]
        assert status(h, port, admin)["draining"]
        assert h.request(data_port, "GET", "/__sibuna/health")[0] == 503
        refusal_checks(h, data_port)
        old.request("GET", "/__sibuna/health")
        reply = old.getresponse()
        assert reply.status == 200 and old.sock is socket
        reply.read()
        assert command(h, port, admin, request) == receipt
    finally:
        old.close()
    command(h, port, admin, operation(node, "resume"), 409)
    command(h, port, admin, operation(status(h, port, admin), "resume"))
    assert h.request(data_port, "GET", "/__sibuna/health")[0] == 200
    assert h.request(data_port, "GET", "/__sibuna/honeypot", extra_headers={
        "X-Forwarded-For": "8.8.8.8",
    })[0] == 403
    node = status(h, port, admin)
    assert node["active_ban_entries"] == 1
    clear = command(h, port, admin, operation(node, "clear_local_bans"))
    assert clear["cleared_entries"] == 1
    assert status(h, port, admin)["active_ban_entries"] == 0
    token = mint(h, port, admin, ["stats_read"], label="node refusal fixture")
    assert bearer(port, "GET", local, token["token"])[0] == 403
    assert bearer(port, "POST", mutate, token["token"], request)[0] == 403
    roles(h, port, admin)
    code, _, body = h.request(port, "POST", "/console/api/audit/query", {
        "action": "node.command.applied",
    }, *admin)
    assert code == 200 and len(json.loads(body)["rows"]) == 3
    # Leave the node drained; restart must expose a new boot and resume admission.
    last = operation(status(h, port, admin), "drain")
    saved = command(h, port, admin, last)
    return last, saved


def roles(h, port, admin):
    code, _, body = h.request(port, "POST", "/console/api/users/create", {
        "username": "node-viewer", "role": "viewer",
    }, *admin)
    assert code == 200
    viewer = rotate(h, port, {
        "username": "node-viewer", "password": json.loads(body)["temporary_password"],
    }, "node viewer replacement passphrase")
    node = status(h, port, viewer)
    command(h, port, viewer, operation(node, "drain"), 403)


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-node-api-") as directory:
        root = Path(directory)
        temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
        with (root / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, str(root / "data"), port, log, extra=(
                "--trust-forwarded", "--console-probe", "9=http://127.0.0.1:1"))
            try:
                credentials = bootstrap.change(h, port, temporary, "node admin private passphrase")
                cookie, csrf, _ = login(h, port, credentials)
                data_port = int(proc.args[proc.args.index("--port") + 1])
                operation_id, receipt = checks(h, port, data_port, (cookie, csrf))
            finally:
                h.stop(proc)
            proc = h.start(binary, str(root / "data"), port, log)
            try:
                cookie, csrf, _ = login(h, port, credentials)
                session = cookie, csrf
                node = status(h, port, session)
                assert not node["draining"] and node["boot"] != operation_id["boot"]
                assert command(h, port, session, operation_id) == receipt
                assert not status(h, port, session)["draining"]
                code, _, body = h.request(port, "POST", "/console/api/nodes/command/read", {
                    "id": operation_id["id"],
                }, *session)
                assert code == 200 and json.loads(body) == receipt
            finally:
                h.stop(proc)
    print("console-e2e: node drain, clear, fencing, receipt, roles and restart passed")


if __name__ == "__main__":
    import sys
    import console_e2e
    check(sys.argv[1], console_e2e)
