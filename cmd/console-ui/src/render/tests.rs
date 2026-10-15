use super::*;
use crate::page::Pages;
use crate::testing::{Probe, with_probes};
use sibuna_console_protocol::Text;

fn rendered(state: &State, pages: &Pages) -> String {
    let mut text = String::new();
    render(&View { state, pages }, &mut Html::new(&mut text, RENDER_LIMIT)).unwrap();
    text
}

#[test]
fn authentication_renders_no_geographic_or_telemetry_element_and_escapes_input() {
    let mut state = State { phase: Phase::Login, ..State::new() };
    state.username = Text::new("<script>\"").unwrap();
    let output = rendered(&state, &Pages::default());
    assert!(!output.contains("<svg"));
    assert!(!output.contains("world-110m"));
    assert!(output.contains("&lt;script&gt;&quot;"));
}

#[test]
fn the_renderer_gates_retained_page_state_when_authentication_is_not_complete() {
    let pages = with_probes(vec![Probe {
        phase: Some(Phase::SecurityOverview),
        body: "<main>private finding<svg></svg></main>",
        ..Probe::default()
    }]);
    let state = State { phase: Phase::SecurityOverview, ..State::new() };
    let output = rendered(&state, &pages);
    assert!(!output.contains("private finding"));
    assert!(!output.contains("<svg"));
    assert!(output.contains("Welcome back"));
}

#[test]
fn authenticated_pages_share_one_navigation_landmark_with_the_correct_active_section() {
    let cases = [
        (Phase::Dashboard, "dashboard"),
        (Phase::Events, "events"),
        (Phase::Similarity, "events"),
        (Phase::Challenges, "challenges"),
        (Phase::Geoip, "geoip"),
        (Phase::Password, "account"),
        (Phase::Security, "account"),
        (Phase::Users, "users"),
        (Phase::Tokens, "tokens"),
        (Phase::Audit, "audit"),
        (Phase::Nodes, "nodes"),
        (Phase::Policies, "policies"),
        (Phase::SecurityOverview, "dashboard"),
    ];
    let pages = crate::pages::load_pages();
    for (phase, active) in cases {
        let mut state = State { phase, ..State::new() };
        state.csrf.set("test").unwrap();
        state.role.set("admin").unwrap();
        let output = rendered(&state, &pages);
        assert_eq!(output.matches("<nav ").count(), 1, "{phase:?}");
        assert_eq!(output.matches("<main ").count(), 1, "{phase:?}");
        let expected = format!("data-action=\"{active}\"\n            aria-current=\"page\"");
        assert!(output.contains(&expected), "{phase:?}");
        state.must_change = true;
        assert!(!rendered(&state, &pages).contains("<nav "), "{phase:?}");
    }
}

#[test]
fn roles_hide_the_sections_they_cannot_open() {
    let mut state = State { phase: Phase::Dashboard, ..State::new() };
    state.csrf.set("test").unwrap();
    state.role.set("viewer").unwrap();
    let output = rendered(&state, &Pages::default());
    assert!(!output.contains("data-action=\"tokens\""));
    assert!(!output.contains("data-action=\"settings\""));
    assert!(output.contains("data-action=\"users\""));
    assert!(output.contains("This page is not available in this build."));
}

#[test]
fn messages_and_busy_forms_render_their_states() {
    let mut state = State { phase: Phase::Login, busy: true, ..State::new() };
    state.set_message("Sign-in failed. Check your credentials.");
    let output = rendered(&state, &Pages::default());
    assert!(
        output.contains(
            "<p id=\"console-message\" class=\"sb-error\" role=\"status\">Sign-in failed."
        )
    );
    assert!(output.contains(" disabled aria-busy=\"true\"> Please wait\u{2026}</button>"));
    assert!(output.contains("type=\"submit\" disabled>Open wall display"));
}

#[test]
fn the_sink_refuses_writes_beyond_its_bound() {
    let mut text = String::new();
    let mut out = Html::new(&mut text, 4);
    assert!(out.write_str("abcd").is_ok());
    assert!(out.write_str("e").is_err());
    assert_eq!(out.as_str(), "abcd");
    let mut text = String::new();
    statistics_tabs(true, &mut Html::new(&mut text, 4096)).unwrap();
    assert!(text.contains(
        "aria-pressed=\"true\" class=\"tab tab-active\"\n        data-action=\"security-overview\""
    ));
}
