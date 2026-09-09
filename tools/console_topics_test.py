"""Exercise all six topics, filter epochs, watermarks, revocation and legacy coexistence."""
import json
from pathlib import Path
import tempfile
import console_bootstrap_test as bootstrap
from console_users_test import login
from console_topics_client import Client
from console_ws_test import Stream
from console_workflows_test import save


def exercise(h, port, data_port, admin):
    client = Client(port, admin[0])
    try:
        topics = ("stats", "events", "nodes", "policy", "challenges", "audit")
        for topic in topics:
            client.command("sub", topic)
        client.until(lambda: all(topic in client.states for topic in topics)
                     and "requests" in client.states["stats"]
                     and "committed" in client.states["policy"]
                     and "page" in client.states["nodes"]
                     and "configured" in client.states["challenges"])
        assert client.states["nodes"]["page"]["self"] == 1
        before = int(client.states["stats"]["requests"])
        for address in ("8.8.8.1", "8.8.8.2"):
            assert h.request(data_port, "GET", "/__sibuna/honeypot?token=private-marker",
                             extra_headers={"X-Forwarded-For": address})[0] == 403
        # Honeypot is an internal route and does not count as external web traffic.
        for address in ("8.8.8.3", "8.8.8.4"):
            h.request(data_port, "GET", "/topic-traffic", extra_headers={
                "X-Forwarded-For": address, "Accept": "application/json"})
        client.until(lambda: len(client.states["events"]["rows"]) == 2
                     and int(client.states["stats"]["requests"]) >= before + 2)
        assert "private-marker" not in json.dumps(client.states["events"])
        assert all(row["query_redacted"] for row in client.states["events"]["rows"])
        old_epoch = client.epochs["events"]
        client.command("filter", "events", {"node": 1, "ip": "8.8.8.2"})
        client.until(lambda: client.epochs["events"] != old_epoch
                     and "events" not in client.pending)
        assert [row["ip"] for row in client.states["events"]["rows"]] == ["8.8.8.2"]
        client.command("filter", "nodes", {"node": 1})
        client.command("filter", "audit", {"action": "policy.edit"})
        result = save(h, port, admin, {"id": "topic-rule", "name": "Topic rule",
                                      "action": "deny", "path": "/topic-deny"})
        client.until(lambda: int(client.states["policy"]["applied"]) == int(result["committed"])
                     and any(row["action"] == "policy.edit"
                             for row in client.states["audit"]["rows"]))
        client.command("ping")
        client.until(lambda: any(message.get("op") == "pong" for message in client.messages))
        assert not client.gaps, client.gaps
        # Revocation is checked while unsolicited updates are being written.
        assert h.request(port, "POST", "/console/api/logout", {}, *admin)[0] == 200
        for _ in range(300):
            result = client.receive()
            if result and result.get("closed"):
                assert result["code"] == 1008
                break
        else:
            raise AssertionError("multi-topic subscriber survived session revocation")
    finally:
        client.close()


def capacity(h, port, cookie):
    streams = []
    try:
        # Legacy and multi-topic connections share the browser quota; HTTP keeps 16 slots.
        streams.append(Stream(port, cookie))
        for _ in range(63):
            streams.append(Stream(port, cookie, "/console/ws"))
        status, _, _ = h.request(port, "GET", "/console/ws", cookie=cookie, extra_headers={
            "Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "AAAAAAAAAAAAAAAAAAAAAA=="})
        assert status == 503, status
        assert h.request(port, "GET", "/console/api/session", cookie=cookie)[0] == 200
    finally:
        for stream in streams:
            stream.close()


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-console-topics-") as directory:
        root = Path(directory)
        temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
        with (root / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, str(root / "data"), port, log, extra=("--trust-forwarded",))
            try:
                credentials = bootstrap.change(h, port, temporary, "topic test permanent passphrase")
                cookie, csrf, _ = login(h, port, credentials)
                data_port = int(proc.args[proc.args.index("--port") + 1])
                exercise(h, port, data_port, (cookie, csrf))
                cookie, _, _ = login(h, port, credentials)
                capacity(h, port, cookie)
            except BaseException:
                log.seek(0)
                print(log.read())
                raise
            finally:
                h.stop(proc)
    print("console-e2e: six topics, chunk watermarks, real deltas, filters, quota and revocation passed")
