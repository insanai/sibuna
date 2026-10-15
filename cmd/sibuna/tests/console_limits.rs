//! Rule quotas edited on the console reach the real daemon (the Zig e2e script
//! `console_limits_test.py`): an invalid document is refused, previews do not spend the
//! quota, the stored document keeps its limits, the quota limits live traffic per client,
//! an unrelated edit keeps the limiter's state, and a disabled rule stops limiting.
#![cfg(feature = "console")]
#![allow(clippy::unwrap_used)]

mod support;

use support::console::{
    Node, console_config, data_plane, field, init_admin, json_string, scratch,
};
use support::get;

#[test]
fn quota_edits_reach_the_daemon_without_previews_spending_them() {
    let dir = scratch("limits");
    let config = data_plane(&dir);
    let temporary = init_admin(&config);
    let mut node = Node::start(config, console_config(), None);
    let console = node.console();
    let session = console.change_password(&temporary);
    let port = node.port();

    let limits = "{\"rate\":1,\"window_seconds\":60,\"ban_seconds\":0}";
    let document = format!(
        "{{\"id\":\"live-quota\",\"name\":\"Live quota\",\"action\":\"challenge\",\
         \"path\":\"/console-quota-review\",\"limits\":{limits}}}"
    );
    let invalid = document.replace("\"challenge\"", "\"weigh\"");
    let body = format!(
        "{{\"expected_revision\":\"{}\",\"document\":{}}}",
        console.committed(&session),
        json_string(&invalid)
    );
    assert_eq!(console.post("/console/api/policies/edit", &body, &session).status(), 400);
    let saved = console.edit_rule(&session, &document);

    // Previews show the limits and do not spend the quota.
    let request =
        "{\"path\":\"/console-quota-review\",\"ip\":\"8.8.11.1\",\"user_agent\":\"curl\"}";
    for _ in 0..3 {
        let result = console.ok("/console/api/policies/test", request, &session);
        assert_eq!(field(&result, "limits"), limits);
        assert_eq!(field(&result, "action"), "challenge");
    }
    let read =
        format!("{{\"kind\":\"document\",\"id\":\"live-quota\",\"committed\":\"{saved}\"}}");
    let stored = console.ok("/console/api/policies/read", &read, &session);
    assert_eq!(
        support::console::field_of(field(&stored, "document").as_bytes(), "limits"),
        limits
    );

    let traffic = |ip: &str| get(port, "/console-quota-review", ip, "curl", "");
    assert_eq!(traffic("8.8.11.1").status(), 401);
    let limited = traffic("8.8.11.1");
    assert_eq!(limited.status(), 429);
    let retry: u64 = limited.header("retry-after").unwrap().parse().unwrap();
    assert!(retry > 0);
    assert_eq!(traffic("8.8.11.2").status(), 401);

    // An unrelated edit keeps the limiter's state; disabling the rule ends the quota.
    let neighbor = "{\"id\":\"quota-neighbor\",\"name\":\"Neighbor\",\"action\":\"deny\",\
                    \"path\":\"/quota-neighbor\",\"enabled\":false}";
    console.edit_rule(&session, neighbor);
    assert_eq!(traffic("8.8.11.1").status(), 429);
    let disabled = document.replace("\"limits\"", "\"enabled\":false,\"limits\"");
    console.edit_rule(&session, &disabled);
    assert_eq!(traffic("8.8.11.1").status(), 401);
    node.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}
