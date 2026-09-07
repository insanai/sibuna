"""Query incidents produced by real requests; cursors must preserve every stored event."""
import json
from pathlib import Path
import tempfile
import time
import console_bootstrap_test


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-events-") as root:
        directory = str(Path(root) / "data")
        temporary = console_bootstrap_test.initialize(binary, directory, "events-admin")
        with (Path(root) / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, directory, port, log, extra=("--trust-forwarded",))
            try:
                credentials = console_bootstrap_test.change(
                    h, port, temporary, "event investigation permanent password")
                status, headers, body = h.request(port, "POST", "/console/api/login", credentials)
                assert status == 200
                cookie = headers["Set-Cookie"].split(";", 1)[0]
                csrf = json.loads(body)["csrf"]
                endpoint = "/console/api/events/query"
                assert h.request(port, "POST", endpoint, {})[0] == 401
                assert h.request(port, "POST", endpoint, {}, cookie)[0] == 400
                assert h.request(port, "POST", endpoint, {"limit": 11}, cookie, csrf)[0] == 400
                data_port = int(proc.args[proc.args.index("--port") + 1])
                for index in range(15):
                    assert h.request(data_port, "GET", "/__sibuna/honeypot?token=hidden-value",
                                     extra_headers={"X-Forwarded-For": f"8.8.8.{index+1}",
                                                    "User-Agent": "<script>review</script>"})[0] == 403
                deadline = time.monotonic() + 10
                while True:
                    stats = json.loads(h.request(port, "GET", "/console/api/stats", cookie=cookie)[2])
                    if stats["incidents"] == 15:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(0.05)
                seen = set()
                query = {"category": "honeypot", "path_prefix": "/__sibuna/", "limit": 3}
                while True:
                    status, _, body = h.request(port, "POST", endpoint, query, cookie, csrf)
                    assert status == 200 and len(body) <= 4096
                    assert b"hidden-value" not in body
                    page = json.loads(body)
                    for row in page["rows"]:
                        assert isinstance(row["id"], str) and row["id"] not in seen
                        assert row["evidence_version"] == 1 and row["country"] is None
                        assert row["capture"]["selected_status"] == 403
                        assert row["capture"]["query_bytes"] == len("token=hidden-value")
                        assert row["query_redacted"]
                        assert row["response_status"] is None
                        seen.add(row["id"])
                    if page["next"] is None:
                        break
                    query["before"] = page["next"]
                assert len(seen) == 15
                query = {"ip": "8.8.8.1"}
                page = json.loads(h.request(port, "POST", endpoint, query, cookie, csrf)[2])
                assert len(page["rows"]) == 1
                grouped = {"view": "source", "ip": "8.8.8.1"}
                page = json.loads(h.request(port, "POST", endpoint, grouped, cookie, csrf)[2])
                assert len(page["rows"]) == 1 and page["rows"][0]["count"] == 1
                assert page["rows"][0]["grouped"]
                status, headers, csv = h.request(port, "POST", "/console/api/events/export",
                                                {"format": "csv"}, cookie, csrf)
                assert status == 200 and "text/csv" in headers["Content-Type"]
                assert b'"id","node"' in csv and b"hidden-value" not in csv
                assert csv.count(b"\r\n") > 2
                for _ in range(5):
                    status, headers, body = h.request(
                        port, "POST", "/console/api/events/export", grouped, cookie, csrf)
                    assert status == 200 and len(body) <= 4096
                    assert "attachment" in headers["Content-Disposition"]
                    assert b"hidden-value" not in body
                assert h.request(port, "POST", "/console/api/events/export",
                                 grouped, cookie, csrf)[0] == 429
            finally:
                h.stop(proc)
    print("console-e2e: real incident queries, filtering, pagination and privacy boundaries passed")
