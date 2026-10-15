use super::*;
use crate::app::App;
use crate::golden::{self, configure};
use crate::testing::{ADMIN_SESSION, Harness};

fn model(app: &mut App) -> &mut Geoip {
    app.pages_mut().find_mut::<Geoip>().unwrap()
}

fn opened() -> Harness {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness.action("geoip", "null");
    assert!(harness.commands().contains(
        "{\"op\":\"request\",\"id\":\"geoip\",\"method\":\"GET\",\"path\":\"/console/api/geoip\"}"
    ));
    harness
}

const STATUS: &str = r#"{"revision":4,"digest":"abc","provider":"dbip",
"source_version":"2026-09","source_digests":"","ranges":12345,"loaded_at":172700,
"status":"storing","processed_ranges":100}"#;

#[test]
fn imports_poll_while_active_and_show_the_dataset() {
    let mut harness = opened();
    harness.respond("geoip", 200, STATUS);
    assert!(harness.commands().contains("{\"op\":\"timer\",\"id\":\"geoip\",\"delay_ms\":1000}"));
    let html = harness.html();
    assert!(html.contains("<h2>DB-IP IP to Country Lite</h2>"));
    assert!(html.contains("Active revision: 4 \u{b7} Known ranges loaded: 12345"));
    assert!(html.contains("Loaded: 1970-01-02 23:58:20 UTC"));
    assert!(html.contains("Status: storing \u{b7} 100 ranges processed"));
    assert!(html.contains("<option value=\"dbip\" selected>"));
    assert!(html.contains(" disabled aria-busy=\"true\">Import country data"));
    harness.action("geo-import", "{\"provider\":\"dbip\"}");
    assert!(!harness.commands().contains("\"id\":\"geo-import\""));
    harness.send(3, "{\"id\":\"geoip\",\"browser_time\":172801}");
    assert!(harness.commands().contains("\"path\":\"/console/api/geoip\""));
    harness.send(3, "{\"id\":\"age\",\"browser_time\":172801}");
    assert!(!harness.commands().contains("\"path\":\"/console/api/geoip\""));
    let finished = STATUS.replace("storing", "failed");
    harness.respond("geoip", 200, &finished);
    assert!(!model(&mut harness.app).importing);
    assert!(harness.html().contains("Import failed. The previous generation remains active."));
    harness.action(
        "geo-import",
        "{\"provider\":\"user-country\",\"source_version\":\"2026-10-01\",\"checksum\":\"\",\
         \"csv\":\"\"}",
    );
    assert!(harness.commands().contains(
        "\"body\":{\"provider\":\"user-country\",\"source_version\":\"2026-10-01\",\
         \"expected_revision\":4,\"checksum\":\"\",\"csv\":\"\"}"
    ));
    harness.respond("geo-import", 200, "{}");
    assert!(harness.commands().contains("\"id\":\"geoip\",\"method\":\"GET\""));
}

#[test]
fn lost_connections_retry_and_refusals_end_the_session() {
    let mut harness = opened();
    harness.action("geo-import", "{}");
    harness.respond("geo-import", 0, "null");
    assert!(harness.commands().contains("{\"op\":\"timer\",\"id\":\"geoip\",\"delay_ms\":5000}"));
    assert!(harness.html().contains("Connection lost. Import status is unknown; reconnecting."));
    assert!(model(&mut harness.app).importing);
    harness.respond("geo-import", 409, "{}");
    assert!(harness.html().contains("Import could not start."));
    harness.send(5, "{\"hidden\":false,\"browser_time\":172800}");
    assert!(harness.commands().contains("\"path\":\"/console/api/geoip\""));
    harness.respond("geoip", 200, "{\"ranges\":4294967296}");
    assert!(harness.html().contains("Could not complete the action"));
    harness.respond("geoip", 403, "{}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.app.state().csrf.is_empty());
}

#[test]
fn only_administrators_see_the_import_form() {
    let mut app = App::new();
    configure(&mut app, Phase::Geoip);
    app.state_mut().role.set("operator").unwrap();
    let html = app.render_now();
    assert!(html.contains("An administrator can import a country database."));
    assert!(!html.contains("<form id=\"geo-import\""));
}

#[test]
fn golden_geoip_page() {
    let mut app = App::new();
    configure(&mut app, Phase::Geoip);
    golden::check("geoip", app.render_now());
}
