use super::*;
use crate::app::App;
use crate::golden::{self, configure};
use crate::testing::{ADMIN_SESSION, Harness};

fn model(app: &mut App) -> &mut Settings {
    app.pages_mut().find_mut::<Settings>().unwrap()
}

const DESTINATION: &str = r#"{"id":"3","revision":"5","kind":"syslog","transport":"tcp",
"label":"siem","target":"logs.example:6514","target_host":"logs.example","secret_set":true,
"events":15,"cooldown_seconds":60,"enabled":false,"last_attempt_at":null,
"last_outcome":"failed","last_detail":"refused"}"#;

const ABOUT: &str = r#"{"version":"0.2.0","node":1,"schema":13,"origin":"https://console",
"advertise":"","behind_proxy":true,"trusted_proxies":2,"cookie_secure":true,"key_file":false,
"probes":"3"}"#;

/// Opens Settings and answers its four reads: destinations, settings, About, the page.
fn opened() -> Harness {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness.action("settings", "null");
    let commands = harness.commands();
    assert!(commands.contains("\"id\":\"settings-1\""));
    assert!(commands.contains("\"body\":{\"after\":0}"));
    assert!(commands.contains("\"id\":\"pages-1\""));
    assert!(commands.contains("\"body\":{\"kind\":\"denied\"}"));
    harness.respond("settings-1", 200, &format!("{{\"rows\":[{DESTINATION}],\"next\":null}}"));
    assert!(
        harness.commands().contains("/console/api/settings/query\",\"csrf\":\"test\",\"body\":{}")
    );
    harness.respond(
        "settings-2",
        200,
        r#"[{"key":"retention.audit","value":"30","revision":"4","updated_at":1,"updated_by":1}]"#,
    );
    assert!(harness.commands().contains("\"method\":\"GET\",\"path\":\"/console/api/about\""));
    harness.respond("settings-3", 200, ABOUT);
    harness.respond(
        "pages-1",
        200,
        r#"{"kind":"denied","revision":"2","customized":true,"sha256":"","html":"<p>No</p>"}"#,
    );
    harness
}

#[test]
fn settings_render_destinations_settings_pages_and_about() {
    let harness = opened();
    let html = harness.html();
    assert!(html.contains("<td>siem (disabled)</td><td>syslog / TCP</td>"));
    assert!(html.contains("<td>all</td>"));
    assert!(html.contains("<td>failed refused</td>"));
    assert!(html.contains("Audit (days) (revision 4)"));
    assert!(html.contains("value=\"30\""));
    assert!(html.contains("<p>denied \u{b7} revision 2 \u{b7} customized</p>"));
    assert!(html.contains("&lt;p&gt;No&lt;/p&gt;</textarea>"));
    assert!(html.contains("<dt>Advertised console</dt><dd>same as origin</dd>"));
    assert!(html.contains("<dd>yes (2 trusted ranges)</dd>"));
    // Zig read only integer members; a numeric string reads as zero.
    assert!(html.contains("<dt>Configured peer probes</dt><dd>0</dd>"));
}

#[test]
fn destinations_save_with_their_revision_and_report_the_saved_change() {
    let mut harness = opened();
    harness.action("settings-open-0", "null");
    assert!(harness.commands().contains("#destination-label"));
    assert!(harness.html().contains("<h3>Edit destination</h3>"));
    assert!(harness.html().contains("A secret is stored."));
    harness.action("settings-save", "{\"cooldown_seconds\":\"x\"}");
    assert!(harness.html().contains("Cooldown must be a whole number"));
    harness.action("settings-save", "{\"cooldown_seconds\":\"5\"}");
    assert!(harness.html().contains("Select at least one event"));
    harness.action(
        "settings-save",
        "{\"cooldown_seconds\":\"5\",\"kind\":\"webhook\",\"transport\":\"tcp\",\
         \"label\":\"hook\",\"target\":\"https://x\",\"ban\":\"on\",\"enabled\":\"on\"}",
    );
    assert!(harness.commands().contains(
        "\"body\":{\"id\":3,\"expected_revision\":\"5\",\"kind\":\"webhook\",\
         \"transport\":\"udp\",\"label\":\"hook\",\"target\":\"https://x\",\"secret\":\"\",\
         \"clear_secret\":false,\"events\":2,\"cooldown_seconds\":5,\"enabled\":true}"
    ));
    harness.respond("settings-4", 200, "{\"saved\":true}");
    assert!(harness.commands().contains("\"id\":\"settings-5\""));
    assert!(model(&mut harness.app).selected.is_none());
    // Deliberate fix: Zig cleared "Saved." again with the refresh it sent.
    assert!(harness.html().contains(">Saved.</p>"));
    harness.respond("settings-5", 409, "null");
    assert!(harness.html().contains("Someone changed this entry first."));
    assert!(harness.commands().contains("#console-message"));
}

#[test]
fn retention_changes_need_the_deletion_acknowledgement_and_tests_report_inline() {
    let mut harness = opened();
    harness.action("settings-thresholds", "{\"key\":\"retention.audit\",\"value\":\"20\"}");
    assert!(!harness.commands().contains("settings/change"));
    harness.action(
        "settings-thresholds",
        "{\"key\":\"retention.audit\",\"value\":\"400\",\"confirmed\":\"on\"}",
    );
    assert!(!harness.commands().contains("settings/change"));
    harness.action(
        "settings-thresholds",
        "{\"key\":\"retention.audit\",\"value\":\"20\",\"confirmed\":\"on\"}",
    );
    assert!(harness.commands().contains(
        "\"body\":{\"key\":\"retention.audit\",\"confirmed\":true,\"value\":\"20\",\
         \"expected_revision\":\"4\"}"
    ));
    harness.respond("settings-4", 200, "{}");
    harness.respond("settings-5", 200, &format!("{{\"rows\":[{DESTINATION}],\"next\":null}}"));
    harness.respond("settings-6", 200, "[]");
    harness.action("settings-open-0", "null");
    harness.action("settings-test", "null");
    assert!(
        harness.commands().contains("/notifications/test\",\"csrf\":\"test\",\"body\":{\"id\":3}")
    );
    harness.respond("settings-7", 200, "{\"delivered\":true,\"audit_recorded\":false}");
    assert!(harness.html().contains("class=\"sb-error\">Test delivery: Delivered; the audit"));
    harness.respond("settings-8", 200, &format!("{{\"rows\":[{DESTINATION}],\"next\":null}}"));
    harness.respond("settings-9", 200, "[]");
    harness.action("settings-test", "null");
    harness.respond(
        "settings-10",
        200,
        "{\"delivered\":true,\"audit_recorded\":true,\"detail\":\"ok\"}",
    );
    assert!(harness.html().contains("class=\"sb-success\">Test delivery: ok</p>"));
}

#[test]
fn response_pages_save_preview_and_keep_the_draft() {
    let mut harness = opened();
    harness.action("pages-save", "{\"html\":\"\"}");
    assert!(harness.html().contains("Enter the page markup or reset to the default."));
    harness.action("pages-preview", "{\"html\":\"<p>Draft</p>\"}");
    assert!(
        harness.commands().contains("\"body\":{\"kind\":\"denied\",\"html\":\"<p>Draft</p>\"}")
    );
    let refused = format!("{{\"accepted\":false,\"diagnostic\":\"{}\"}}", "x".repeat(100));
    harness.respond("pages-2", 200, &refused);
    assert!(harness.html().contains("class=\"sb-error\">Draft refused.</p>"));
    assert!(harness.html().contains("&lt;p&gt;Draft&lt;/p&gt;</textarea>"));
    harness.action("pages-preview", "{\"html\":\"<p>Draft</p>\"}");
    harness.respond("pages-3", 200, "{\"accepted\":true,\"path\":\"/console/preview/1\"}");
    assert!(harness.html().contains("href=\"/console/preview/1\""));
    harness.action("pages-save", "{\"html\":\"<p>Draft</p>\"}");
    assert!(harness.commands().contains(
        "\"body\":{\"kind\":\"denied\",\"expected_revision\":\"2\",\"reset\":false,\
         \"html\":\"<p>Draft</p>\"}"
    ));
    harness.respond("pages-4", 409, "null");
    assert!(harness.html().contains("Another administrator changed this page"));
    harness.action("pages-reset", "null");
    harness.respond("pages-5", 200, "{}");
    assert!(harness.html().contains("Saved. The data plane serves it after the next rebuild."));
    assert!(harness.commands().contains("\"id\":\"pages-6\""));
    harness.respond(
        "pages-6",
        200,
        r#"{"kind":"denied","revision":3,"customized":false,"sha256":"","html":"<p>Default</p>"}"#,
    );
    assert!(harness.html().contains("<p>denied \u{b7} revision 3 \u{b7} default</p>"));
    assert!(harness.html().contains("data-action=\"pages-reset\" disabled>Reset"));
    harness.action("pages-open-banned", "null");
    assert!(harness.commands().contains("\"body\":{\"kind\":\"banned\"}"));
    harness.respond("pages-7", 200, "{\"kind\":\"banned\",\"revision\":-4}");
    assert!(harness.html().contains("The page could not be decoded."));
    harness.respond("pages-7", 401, "null");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.html().contains("Your session ended. Sign in to continue."));
}

#[test]
fn viewers_cannot_open_settings_and_expired_sessions_sign_out() {
    let mut harness = Harness::new();
    harness.respond(
        "session",
        200,
        "{\"user\":2,\"csrf\":\"test\",\"node\":1,\"role\":\"operator\",\"must_change\":false}",
    );
    harness.action("settings", "null");
    assert!(!harness.commands().contains("notifications/query"));
    let mut harness = opened();
    harness.action("settings-refresh", "null");
    harness.respond("settings-4", 401, "null");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.html().contains("Your session ended. Sign in to continue."));
    assert!(model(&mut harness.app).about.is_none());
}

#[test]
fn golden_settings_page() {
    let mut app = App::new();
    configure(&mut app, Phase::Settings);
    golden::check("settings", app.render_now());
}
