//! The golden harness: reviewed full-page HTML from the native renderer, compared byte for
//! byte with `tests/golden/<name>.html` (the fixtures of the Zig module). The browser
//! patches these same trees; fixtures freeze time and contain no live credentials.
//!
//! A fixture is produced either by driving the application with recorded events (see
//! [`crate::testing::Harness`]) or by setting up the state directly with [`configure`],
//! as the Zig `golden.zig` did. Set `SIBUNA_UPDATE_CONSOLE_GOLDENS=1` to rewrite the
//! fixtures after a reviewed change.
//!
//! Every fixture file is listed exactly once: in [`CHECKED`] when a test compares it, or
//! in [`PENDING`] with the module it awaits. A page port moves its fixtures from one list
//! to the other.

use std::path::PathBuf;

use crate::app::App;
use crate::state::Phase;

/// The browser clock of every fixture, in Unix seconds.
pub const FIXTURE_TIME: u64 = 172_800;

/// Fixtures compared by a test.
pub const CHECKED: &[&str] = &[
    "policies",
    "rule-hit-history",
    "rule-hit-history-partial",
    "users",
    "tokens",
    "audit",
    "audit-detail",
    "settings",
    "nodes",
    "geoip",
    "events",
    "similarity",
    "challenges",
    "dashboard",
    "traffic-live",
    "traffic-stale",
    "traffic-comparison",
    "traffic-period",
    "traffic-period-partial",
    "ranking-history",
    "loading",
    "login",
    "password",
    "setup",
    "required-password",
    "security",
    "required-totp",
    "security_overview",
    "security-recorded",
    "kiosk-traffic",
    "kiosk-security",
    "kiosk-security-recorded",
];

/// Fixtures waiting for a page module, with the module (group) that produces them.
pub const PENDING: &[(&str, &str)] = &[];

/// Resets `app` to `phase` at the fixture time, signed in as an administrator of console
/// node 1 for every phase but the four authentication phases (Zig's `configure`).
pub fn configure(app: &mut App, phase: Phase) {
    app.pages_mut().reset_all();
    let state = app.state_mut();
    state.reset();
    state.phase = phase;
    state.browser_time = FIXTURE_TIME;
    state.received_at = FIXTURE_TIME - 1;
    if !matches!(phase, Phase::Loading | Phase::Setup | Phase::Login | Phase::Password) {
        state.csrf.set("fixture-only-csrf").unwrap();
        state.console_node = Some(1);
        state.role.set("admin").unwrap();
    }
}

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(format!("{name}.html"))
}

/// Compares `html` with the fixture `name` (or rewrites it in update mode) after the
/// mechanical principle checks.
///
/// # Panics
///
/// On a mismatch, a principle violation or an unreadable fixture: this is a test helper.
pub fn check(name: &str, html: &str) {
    assert!(CHECKED.contains(&name), "add {name} to golden::CHECKED");
    principles(name, html);
    let path = path(name);
    if std::env::var_os("SIBUNA_UPDATE_CONSOLE_GOLDENS").is_some_and(|value| !value.is_empty()) {
        std::fs::write(&path, html).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap();
    assert!(
        expected == html,
        "console golden changed: {}\n--- expected\n{expected}\n--- actual\n{html}",
        path.display()
    );
}

/// The mechanical half of the principle audit (rules a renderer can violate silently);
/// the judgement rules (R1, R5, R7) remain a human review of the same HTML.
fn principles(name: &str, html: &str) {
    // R2 trunk test: product, node, heading, active section and the way back.
    if html.contains("<nav ") {
        assert!(html.contains("SIBUNA"), "{name}");
        assert!(html.contains("Console node ") || html.contains("Node not reported"), "{name}");
        assert!(html.contains("id=\"page-heading\""), "{name}");
        assert!(html.contains("aria-current=\"page\""), "{name}");
        assert!(html.contains("href=\"/console/\""), "{name}");
    }
    // R8: decision colours reach markup only through the semantic classes.
    assert_eq!(html.matches("fill=\"#").count(), 0, "{name}");
    for (index, _) in html.match_indices("sb-decision-") {
        let rest = &html[index + "sb-decision-".len()..];
        let known = ["admitted", "challenged", "denied", "banned", "info"];
        assert!(known.iter().any(|tone| rest.starts_with(tone)), "{name}");
    }
    // R9 and R11: every traffic tile has a sparkline and a deviation marker.
    if ["dashboard", "traffic-period", "traffic-comparison"].contains(&name) {
        let tiles = html.matches("<article class=\"sb-tile ").count();
        assert_eq!(tiles, 11, "{name}");
        assert_eq!(html.matches("class=\"sb-sparkline\"").count(), tiles, "{name}");
        assert_eq!(html.matches("<p class=\"sb-note\">Yesterday: ").count(), tiles, "{name}");
    }
    if name == "traffic-live" {
        assert_eq!(html.matches("class=\"sb-sparkline\"").count(), 11);
        // R12: counts render with thousands separators.
        assert!(html.contains("12,345"));
    }
    // R18: permanent deletion needs an acknowledgement per retention window.
    if name == "settings" {
        assert_eq!(html.matches("name=\"confirmed\" required").count(), 4);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Harness;

    #[test]
    fn every_fixture_is_checked_or_pending_exactly_once() {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
        let mut files: Vec<String> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter_map(|name| name.strip_suffix(".html").map(str::to_owned))
            .collect();
        files.sort();
        let mut listed: Vec<String> = CHECKED
            .iter()
            .copied()
            .chain(PENDING.iter().map(|(name, _)| *name))
            .map(str::to_owned)
            .collect();
        listed.sort();
        assert_eq!(files, listed);
    }

    #[test]
    fn loading_is_the_first_page() {
        let harness = Harness::new();
        assert_eq!(
            harness.commands(),
            "[{\"op\":\"request\",\"id\":\"session\",\"method\":\"GET\",\
             \"path\":\"/console/api/session\"}]"
        );
        check("loading", harness.html());
    }

    #[test]
    fn a_missing_session_leads_through_the_setup_check_to_sign_in() {
        let mut harness = Harness::new();
        harness.respond("session", 401, "{}");
        assert!(harness.commands().contains("\"path\":\"/console/api/setup\""));
        harness.respond("setup", 200, "{\"setup_required\":false}");
        check("login", harness.html());
        let mut harness = Harness::new();
        harness.respond("session", 401, "{}");
        harness.respond("setup", 200, "{\"setup_required\":true}");
        check("setup", harness.html());
    }

    #[test]
    fn a_signed_out_password_phase_shows_the_password_form() {
        let mut app = App::new();
        configure(&mut app, Phase::Password);
        check("password", app.render_now());
    }

    #[test]
    fn a_required_password_change_hides_the_shell() {
        let mut harness = Harness::new();
        harness.respond(
            "session",
            200,
            "{\"user\":1,\"csrf\":\"fixture-only-csrf\",\"node\":1,\"role\":\"admin\",\
             \"must_change\":true}",
        );
        assert_eq!(harness.app.state().phase, Phase::Password);
        check("required-password", harness.html());
    }
}
