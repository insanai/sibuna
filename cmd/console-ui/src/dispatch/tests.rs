use super::*;
use crate::testing::{ADMIN_SESSION, Harness};

#[test]
fn sign_in_posts_the_form_and_records_the_name() {
    let mut harness = Harness::new();
    harness.respond("session", 401, "{}");
    harness.respond("setup", 200, "{\"setup_required\":false}");
    harness.action("login", "{\"username\":\"admin\",\"password\":\"p\\\"w\",\"code\":\"\"}");
    assert_eq!(
        harness.commands(),
        "[{\"op\":\"request\",\"method\":\"POST\",\"id\":\"login\",\
         \"path\":\"/console/api/login\",\"csrf\":\"\",\
         \"body\":{\"username\":\"admin\",\"password\":\"p\\\"w\",\"code\":\"\"}}]"
    );
    assert_eq!(harness.app.state().username.as_str(), "admin");
    assert!(harness.app.state().busy);
    harness.action("login", "{\"username\":\"again\"}");
    assert_eq!(harness.commands(), "[]");
    harness.respond("login", 429, "{}");
    assert!(harness.html().contains("Too many attempts. Please wait a minute."));
    assert!(!harness.app.state().busy);
}

#[test]
fn a_session_starts_with_role_node_and_live_statistics() {
    let mut harness = Harness::new();
    harness.respond(
        "session",
        200,
        "{\"user\":\"9007199254740993\",\"csrf\":\"token\",\"node\":7,\"role\":\"operator\"}",
    );
    let state = harness.app.state();
    assert_eq!(state.phase, Phase::Dashboard);
    assert_eq!(state.user_id, 9_007_199_254_740_993);
    assert_eq!(state.console_node, Some(7));
    assert_eq!(state.role.as_str(), "operator");
    let commands = harness.commands();
    assert!(commands.contains("{\"op\":\"history\",\"value\":\"dashboard\",\"replace\":true}"));
    assert!(commands.contains("{\"op\":\"connect\",\"path\":\"/console/ws\"}"));
    assert!(commands.contains("{\"op\":\"timer\",\"id\":\"age\",\"delay_ms\":1000}"));
    assert!(commands.contains("{\"op\":\"focus\",\"selector\":\"main h1\",\"top\":true}"));
    assert!(harness.html().contains("Console node 7"));
}

#[test]
fn malformed_sessions_are_refused() {
    let mut harness = Harness::new();
    harness.respond("session", 200, "{\"csrf\":\"token\"}");
    assert!(harness.html().contains("Could not complete the action. Please try again."));
    assert!(!harness.app.state().is_full_access());
    let mut harness = Harness::new();
    let long = "x".repeat(65);
    harness.respond("session", 200, &format!("{{\"user\":1,\"csrf\":\"{long}\"}}"));
    assert!(!harness.app.state().is_full_access());
    let mut harness = Harness::new();
    harness.respond("session", 0, "{}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.app.state().stale);
}

#[test]
fn navigation_drawer_preferences_and_pause_are_core_actions() {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness.action("navigation-toggle", "{}");
    assert!(harness.app.state().navigation_open);
    assert!(harness.html().contains("data-navigation-open=\"true\""));
    harness.action("events", "{}");
    assert!(!harness.app.state().navigation_open);
    assert!(harness.commands().contains("\"selector\":\"main h1\""));
    harness.action("theme", "{}");
    assert!(
        harness
            .commands()
            .contains("\"preference\":\"light\",\"density\":\"comfortable\",\"persist\":true")
    );
    assert!(harness.html().contains("Theme: light"));
    harness.action("pause", "{}");
    assert!(harness.app.state().paused);
    harness.action("account", "{}");
    assert_eq!(harness.app.state().phase, Phase::Password);
    assert!(harness.html().contains("Back to dashboard"));
    harness.send(9, "{\"theme\":\"bogus\",\"density\":\"compact\",\"system_dark\":true}");
    assert!(harness.commands().contains("\"theme\":\"dark\",\"preference\":\"system\""));
}

#[test]
fn unknown_events_and_replies_change_nothing() {
    let mut harness = Harness::new();
    harness.send(6, "{\"anything\":1}");
    harness.respond("unknown", 200, "{}");
    harness.send(2, "{\"id\":\"session\",\"status\":\"200\",\"body\":{}}");
    assert_eq!(harness.app.state().phase, Phase::Loading);
    harness.send(7, "{\"reduced_motion\":true}");
    assert!(harness.app.state().reduced_motion);
}

/// Mutated events never panic, never leave the input unerased, and always leave a JSON
/// command list and a page or an empty page.
#[test]
fn fuzz_events_never_panic() {
    let seeds = [
        ADMIN_SESSION,
        "{\"action\":\"login\",\"fields\":{\"username\":\"a\",\"password\":\"b\"}}",
        "{\"id\":\"session\",\"status\":200,\
         \"body\":{\"user\":1,\"csrf\":\"t\",\"role\":\"admin\"}}",
        "{\"id\":\"totp\",\"status\":200,\"body\":{\"available\":true,\"enabled\":false}}",
        "{\"state\":\"message\",\"body\":{\"op\":\"snapshot_begin\",\"topic\":\"stats\"}}",
        "{\"route\":\"nodes\",\"hidden\":false,\"reduced_motion\":true}",
    ];
    let mut random = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = move || {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        random
    };
    let mut harness = Harness::new();
    for round in 0..100_000u32 {
        let mut bytes = seeds[(next() % seeds.len() as u64) as usize].as_bytes().to_vec();
        for _ in 0..next() % 4 {
            let at = (next() % (bytes.len() as u64 + 1)) as usize;
            match next() % 4 {
                0 if at < bytes.len() => bytes[at] ^= 1 << (next() % 7),
                1 => bytes.truncate(at),
                2 => bytes.insert(at.min(bytes.len()), b"{}[],:\"0"[(next() % 8) as usize]),
                _ => {
                    let other = seeds[(next() % seeds.len() as u64) as usize].as_bytes();
                    bytes.extend_from_slice(&other[..other.len() / 2]);
                }
            }
        }
        let kind = (next() % 11) as u32;
        let length = bytes.len();
        harness.app.input()[..length].copy_from_slice(&bytes);
        harness.app.event(kind, length);
        assert!(harness.app.input()[..length].iter().all(|byte| *byte == 0));
        assert!(harness.commands().starts_with('[') && harness.commands().ends_with(']'));
        sibuna_json::parse(harness.commands().as_bytes()).unwrap();
        if round % 5000 == 0 {
            harness = Harness::new();
        }
    }
}
