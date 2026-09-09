"""Policy workflows through the live daemon: ordering changes a decision, replay counts
retained events, reputation prefixes deny and undo, a country block applies from the active
generation, and a chunked import replaces the managed set atomically."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import console_bootstrap_test as bootstrap
from console_users_test import login


def post(h, port, session, path, body, expected=200):
    code, _, reply = h.request(port, "POST", path, body, *session)
    assert code == expected, (path, code, reply)
    return json.loads(reply) if reply else None


def committed(h, port, admin):
    return post(h, port, admin, "/console/api/policies/query", {})["committed"]


def save(h, port, admin, document):
    return post(h, port, admin, "/console/api/policies/edit",
                {"expected_revision": committed(h, port, admin), "document": json.dumps(document)})


def wait_applied(h, port, admin, revision):
    for _ in range(100):
        page = post(h, port, admin, "/console/api/policies/query", {})
        if int(page["applied"]) >= int(revision):
            return
        time.sleep(0.1)
    raise AssertionError("revision not applied")


def fetch(h, data_port, path, ip, ua="Mozilla/5.0"):
    return h.request(data_port, "GET", path, extra_headers={"X-Forwarded-For": ip,
                                                              "User-Agent": ua})[0]


def check_order(h, port, data_port, admin):
    save(h, port, admin, {"id": "ord-allow", "name": "Ordered allow", "action": "allow",
                          "priority": 10, "path": "/ordered"})
    saved = save(h, port, admin, {"id": "ord-deny", "name": "Ordered deny", "action": "deny",
                                  "priority": 20, "path": "/ordered"})
    wait_applied(h, port, admin, saved["committed"])
    assert fetch(h, data_port, "/ordered", "8.8.9.20") != 403
    post(h, port, admin, "/console/api/policies/order",
         {"id": "ord-deny", "expected_revision": "1", "direction": "up"}, 409)
    moved = post(h, port, admin, "/console/api/policies/order",
                 {"id": "ord-deny", "expected_revision": saved["committed"], "direction": "up"})
    wait_applied(h, port, admin, moved["committed"])
    assert fetch(h, data_port, "/ordered", "8.8.9.21") == 403
    post(h, port, admin, "/console/api/policies/order",
         {"id": "ord-deny", "expected_revision": moved["committed"], "direction": "up"}, 400)


def check_replay(h, port, data_port, admin):
    # Only inspection findings are retained as incidents; traversal probes carry no query
    # or body, so their replay is conclusive, while the XSS probe's query makes it not.
    for i in range(3):
        assert fetch(h, data_port, "/replay/../../etc/passwd", f"8.8.9.{30 + i}") == 403
    assert fetch(h, data_port, "/replay?q=%3Cscript%3Ealert(1)%3C/script%3E", "8.8.9.40") == 403
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        summary = post(h, port, admin, "/console/api/policies/replay",
                       {"rule": "waf:path-traversal", "hours": 1})
        if summary["total"] >= 4:
            break
        time.sleep(0.2)
    assert summary["total"] >= 4 and summary["matched"] >= 3, summary
    assert summary["inconclusive"] >= 1 and not summary["preview"], summary
    assert any(row["conclusive"] and row["matched"] for row in summary["rows"]), summary
    everything = post(h, port, admin, "/console/api/policies/replay", {"hours": 1})
    assert everything["matched"] >= 4, everything
    draft = {"id": "replay-deny", "name": "Replay deny", "action": "deny", "path": "/nowhere"}
    preview = post(h, port, admin, "/console/api/policies/replay",
                   {"rule": "Replay deny", "hours": 1, "draft": json.dumps(draft),
                    "committed": committed(h, port, admin)})
    assert preview["preview"] and preview["matched"] == 0, preview
    saved = save(h, port, admin, {"id": "replay-deny", "name": "Replay deny", "action": "deny",
                                  "path": "/replay-path"})
    wait_applied(h, port, admin, saved["committed"])
    post(h, port, admin, "/console/api/policies/replay",
         {"rule": "x", "hours": 1, "draft": json.dumps(draft), "committed": "999999"}, 409)


def check_reputation(h, port, data_port, admin):
    post(h, port, admin, "/console/api/reputation/edit",
         {"prefix": "not a prefix", "expected_revision": committed(h, port, admin)}, 400)
    denied = post(h, port, admin, "/console/api/reputation/edit",
                  {"prefix": "203.0.113.0/24", "expected_revision": committed(h, port, admin),
                   "action": "deny", "note": "scanner range"})
    wait_applied(h, port, admin, denied["committed"])
    assert fetch(h, data_port, "/anything", "203.0.113.9") == 403
    page = post(h, port, admin, "/console/api/reputation/query", {})
    rows = {row["prefix"]: row for row in page["rows"]}
    assert rows["203.0.113.0/24"]["source"] == "console", page
    assert rows["203.0.113.0/24"]["note"] == "scanner range" and int(page["nodes"]) > 1
    post(h, port, admin, "/console/api/reputation/remove",
         {"prefix": "203.0.113.0/24", "expected_revision": "1"}, 409)
    removed = post(h, port, admin, "/console/api/reputation/remove",
                   {"prefix": "203.0.113.0/24", "expected_revision": page["committed"]})
    wait_applied(h, port, admin, removed["committed"])
    assert fetch(h, data_port, "/anything", "203.0.113.9") != 403


def check_country(h, port, data_port, admin):
    h.geo_import(port, admin[0], admin[1])
    post(h, port, admin, "/console/api/geoip/country/preview",
         {"country": "XX", "expected_revision": committed(h, port, admin)}, 400)
    preview = post(h, port, admin, "/console/api/geoip/country/preview",
                   {"country": "US", "expected_revision": committed(h, port, admin)})
    assert preview["prefixes"] == 200 and preview["overlaps"] == 0, preview
    assert preview["nodes_after"] > preview["nodes_before"] and len(preview["generation"]) == 64
    assert "8.8.0.0/24" in preview["sample"], preview
    post(h, port, admin, "/console/api/geoip/country/preview",
         {"country": "US", "expected_revision": committed(h, port, admin),
          "until": str(2 ** 63)}, 400)
    applied = post(h, port, admin, "/console/api/geoip/country/apply",
                   {"country": "US", "expected_revision": committed(h, port, admin),
                    "action": "deny", "review": preview["review"]})
    wait_applied(h, port, admin, applied["committed"])
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and fetch(h, data_port, "/anything", "8.8.5.1") != 403:
        time.sleep(0.2)
    assert fetch(h, data_port, "/anything", "8.8.5.1") == 403
    page = post(h, port, admin, "/console/api/reputation/query", {"after": "8.8.4"})
    assert any(row["source"] == "console:country:US" for row in page["rows"]), page
    check_country_refresh(h, port, data_port, admin)


def check_country_refresh(h, port, data_port, admin):
    base = {"country": "US", "expected_revision": committed(h, port, admin)}
    previous = post(h, port, admin, "/console/api/geoip/country/preview", base)
    source = {"provider": "dbip", "source_version": "2026-10", "expected_revision": 1,
              "csv": "".join(f"8.8.{i}.0,8.8.{i}.255,US\n" for i in range(100, 250))}
    post(h, port, admin, "/console/api/geoip", source)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        status = json.loads(h.request(port, "GET", "/console/api/geoip", cookie=admin[0])[2])
        if status["revision"] == 2 and status["status"] == "applied":
            break
        assert status["status"] != "failed", status
        time.sleep(0.05)
    else:
        raise AssertionError("Country refresh generation failed to activate")
    # Import alone never changes policy. The old ranges still deny until a reviewed commit.
    assert fetch(h, data_port, "/anything", "8.8.5.1") == 403
    post(h, port, admin, "/console/api/geoip/country/apply",
         dict(base, review=previous["review"]), 409)
    reviewed = post(h, port, admin, "/console/api/geoip/country/preview", base)
    assert (reviewed["added"], reviewed["removed"], reviewed["retained"]) == (50, 100, 100)
    assert reviewed["previous_generation"] == previous["generation"]
    assert reviewed["generation"] != previous["generation"]
    first = {row["prefix"] for row in reviewed["changes"]}
    following = post(h, port, admin, "/console/api/geoip/country/preview",
                     dict(base, review=reviewed["review"], offset=reviewed["next_offset"]))
    assert following["review"] == reviewed["review"]
    assert not first.intersection(row["prefix"] for row in following["changes"])
    post(h, port, admin, "/console/api/geoip/country/apply",
         dict(base, action="allow", review=reviewed["review"]), 409)
    result = post(h, port, admin, "/console/api/geoip/country/apply",
                  dict(base, review=reviewed["review"]))
    wait_applied(h, port, admin, result["committed"])
    assert fetch(h, data_port, "/anything", "8.8.5.1") != 403
    assert fetch(h, data_port, "/anything", "8.8.220.1") == 403


def check_import(h, port, admin):
    catalog = post(h, port, admin, "/console/api/policies/read", {"kind": "catalog"})
    documents = []
    for row in catalog["rows"]:
        read = post(h, port, admin, "/console/api/policies/read",
                    {"kind": "document", "id": row["id"]})
        documents.append(read["document"])
    assert len(documents) >= 3
    kept = [d for d in documents if json.loads(d)["id"] != "ord-allow"]
    digest = hashlib.sha256("\n".join(kept).encode()).hexdigest()
    for ordinal, document in enumerate(kept):
        post(h, port, admin, "/console/api/policies/import/chunk",
             {"digest": digest, "ordinal": ordinal, "document": document})
    post(h, port, admin, "/console/api/policies/import/chunk",
         {"digest": digest, "ordinal": 99, "document": "{\"id\":\"broken\"}"}, 400)
    post(h, port, admin, "/console/api/policies/import/commit",
         {"digest": digest, "count": len(kept) + 1,
          "expected_revision": committed(h, port, admin)}, 400)
    result = post(h, port, admin, "/console/api/policies/import/commit",
                  {"digest": digest, "count": len(kept),
                   "expected_revision": committed(h, port, admin)})
    wait_applied(h, port, admin, result["committed"])
    catalog = post(h, port, admin, "/console/api/policies/read", {"kind": "catalog"})
    ids = {row["id"] for row in catalog["rows"]}
    assert "ord-allow" not in ids and "ord-deny" in ids and "replay-deny" in ids, ids
    for action in ("policy.order", "reputation.edit", "reputation.remove",
                   "reputation.country", "policy.import"):
        code, _, body = h.request(port, "POST", "/console/api/audit/query", {"action": action},
                                  *admin)
        assert code == 200 and len(json.loads(body)["rows"]) >= 1, action


def check_cli(binary, h, port, admin, credentials, root):
    password = root / "cli-password"
    password.write_text(credentials["password"] + "\n")
    password.chmod(0o600)
    base = [binary, "console", "policies"]
    auth = ["--origin", f"http://127.0.0.1:{port}", "--username", credentials["username"],
            "--password-file", str(password)]
    exported = subprocess.run(base + ["export"] + auth, capture_output=True, text=True,
                              timeout=60)
    assert exported.returncode == 0, exported.stderr
    documents = json.loads(exported.stdout)
    ids = {document["id"] for document in documents}
    assert "ord-deny" in ids and "replay-deny" in ids, ids
    kept = [document for document in documents if document["id"] != "ord-deny"]
    set_file = root / "policy-set.json"
    set_file.write_text(json.dumps(kept))
    imported = subprocess.run(base + ["import", "--file", str(set_file)] + auth,
                              capture_output=True, text=True, timeout=60)
    assert imported.returncode == 0, imported.stderr
    result = json.loads(imported.stdout)
    wait_applied(h, port, admin, result["committed"])
    catalog = post(h, port, admin, "/console/api/policies/read", {"kind": "catalog"})
    assert {row["id"] for row in catalog["rows"]} == {d["id"] for d in kept}
    set_file.write_text("[{\"id\":\"broken\"}]")
    broken = subprocess.run(base + ["import", "--file", str(set_file)] + auth,
                            capture_output=True, text=True, timeout=60)
    assert broken.returncode == 1 and not broken.stdout, broken.stderr


def check(binary, h):
    with tempfile.TemporaryDirectory(prefix="sibuna-console-workflows-") as directory:
        root = Path(directory)
        temporary = bootstrap.initialize(binary, str(root / "data"), "admin")
        with (root / "daemon.log").open("w+") as log:
            port = h.port()
            proc = h.start(binary, str(root / "data"), port, log, extra=("--trust-forwarded",))
            try:
                credentials = bootstrap.change(h, port, temporary,
                                               "workflow admin private passphrase")
                cookie, csrf, _ = login(h, port, credentials)
                admin = (cookie, csrf)
                data_port = int(proc.args[proc.args.index("--port") + 1])
                check_order(h, port, data_port, admin)
                check_replay(h, port, data_port, admin)
                check_reputation(h, port, data_port, admin)
                check_country(h, port, data_port, admin)
                check_import(h, port, admin)
                check_cli(binary, h, port, admin, credentials, root)
            finally:
                h.stop(proc)
    print("console-e2e: rule ordering, replay, reputation prefixes, country block and set import passed")


if __name__ == "__main__":
    import sys
    import console_e2e
    check(sys.argv[1], console_e2e)
