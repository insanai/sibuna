"""Real HTTP matches, private tester exclusion, durable intervals and the shipped Wasm UI."""
import json
import time
import console_e2e as h
from console_workflows_test import post, save, wait_applied
from console_ui_forms import FormValues


def check(ui, data_port):
    csrf = next(request["csrf"] for request in ui.requests if request.get("csrf"))
    session = (ui.cookie, csrf)
    path = "/sid7-rule-hit-observation"
    save(h, ui.port, session, {"id": "ui-hit-weight", "name": "Observed weight",
                              "action": "weigh", "weight": 2, "priority": 1, "path": path})
    saved = save(h, ui.port, session, {"id": "ui-hit-deny", "name": "Observed denial",
                                      "action": "deny", "priority": 2, "path": path})
    wait_applied(h, ui.port, session, saved["committed"])
    for _ in range(5):
        result = post(h, ui.port, session, "/console/api/policies/test",
                      {"path": path, "ip": "198.51.100.88", "user_agent": "Mozilla"})
        assert result["action"] == "deny", result
    # Counters are sampled, not timestamped per request. Keep this cohort away from
    # the minute boundary so its next sample belongs to the same retained minute.
    ui.event(1, {"action": "dashboard", "fields": {}})
    ui.event(1, {"action": "traffic-period", "fields": {"hours": "0"}})
    deadline = time.monotonic() + 65
    while not 2 <= int(time.time()) % 60 <= 45:
        assert time.monotonic() < deadline, "rule-hit cohort start deadline"
        ui.receive()
    first = int(time.time()) // 60
    for index in range(20):
        status, _, _ = h.request(data_port, "GET", path, extra_headers={
            "X-Forwarded-For": f"198.51.100.{index + 1}", "User-Agent": "Mozilla"})
        assert status == 403, status
    last = int(time.time()) // 60
    assert first == last and int(time.time()) % 60 < 55, "cohort crossed sampling boundary"
    # The production collector seals ending-minute cohorts. No synthetic clock or SQL
    # injection substitutes for this request -> pinned counter -> storage -> browser path.
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline and time.time() < (last + 1) * 60 + 2:
        # Drain live snapshots and answer heartbeats while waiting for durable intervals.
        ui.receive()
    assert time.time() >= (last + 1) * 60 + 2, "rule-history seal deadline"
    query = {"key": "m:ui-hit-deny", "node": 1, "from_minute": first,
             "until_minute": last, "revision": saved["committed"]}
    for key in ("m:ui-hit-weight", "m:ui-hit-deny"):
        query["key"] = key
        deadline = time.monotonic() + 20
        while True:
            result = post(h, ui.port, session, "/console/api/policies/hits", query)
            if int(result["window"]["hits"]) != 0 or time.monotonic() >= deadline:
                break
            ui.receive()
        assert int(result["window"]["hits"]) == 20, result
        assert result["window"]["finished"] and result["window"]["next"] is None, result
    assert h.request(ui.port, "POST", "/console/api/policies/hits", query)[0] == 401
    invalid = dict(query, node=0)
    assert h.request(ui.port, "POST", "/console/api/policies/hits", invalid, *session)[0] == 400
    ui.event(1, {"action": "policies", "fields": {}})
    ui.topic("policy")
    assert "Recorded hits today (UTC)" in ui.html and "Hourly values" in ui.html
    assert "console-navigation" in ui.html
    ui.event(1, {"action": "rule-hits-open", "fields": {"key": "m:ui-hit-deny"}})
    assert "Rule hit history" in ui.html and "console-navigation" in ui.html
    ui.event(1, {"action": "rule-hits-start", "fields": {
        "minutes": "5", "offset": "0", "node": "1", "mode": "previous",
        "before_revision": "", "after_revision": str(saved["committed"])}})
    assert "20 recorded matches" in ui.html, ui.html
    assert "Incomplete coverage" in ui.html and "Deviation needs complete coverage" in ui.html
    assert "RULEHITS003" not in ui.html
    form = FormValues("rule-hits-start")
    form.feed(ui.html)
    assert form.values == {"minutes": "5", "offset": "0", "node": "1", "mode": "previous",
                           "before_revision": "", "after_revision": str(saved["committed"])}
    ui.event(1, {"action": "rule-hits-close", "fields": {}})
    assert "Rule hit history" not in ui.html and "console-navigation" in ui.html
    ui.event(1, {"action": "managed-refresh", "fields": {}})
    ui.event(1, {"action": "managed-history:ui-hit-deny", "fields": {}})
    selected = FormValues("rule-hits-open", attribute="data-submit")
    selected.feed(ui.html)
    assert selected.values["key"] == "m:ui-hit-deny"
    assert int(selected.values["edit_at"]) > 0
    assert selected.values["revision"] == str(saved["committed"])
    ui.event(1, {"action": "rule-hits-open", "fields": selected.values})
    around = FormValues("rule-hits-start")
    around.feed(ui.html)
    assert around.values["mode"] == "edit"
    assert around.values["after_revision"] == str(saved["committed"])
    assert "Selected edit:" in ui.html and "console-navigation" in ui.html
    ui.event(1, {"action": "rule-hits-close", "fields": {}})
    assert "Compare hits around this edit" in ui.html
    print("console-ui-e2e: live WEIGH/terminal hits, private test exclusion and rule history passed")
