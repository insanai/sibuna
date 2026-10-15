use sibuna_console_protocol::challenges::{Algorithm, Defaults};
use sibuna_console_protocol::codec::to_json;

use super::*;
use crate::app::App;
use crate::golden::{self, configure};
use crate::page::Pages;
use crate::pages::events::tests::{connected, live_view};
use crate::testing::{ADMIN_SESSION, Harness};

fn challenges(app: &mut App) -> &mut Challenges {
    app.pages_mut().find_mut::<Challenges>().unwrap()
}

fn opened() -> Harness {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness.action("challenges", "null");
    harness
}

fn render_page(page: &Challenges, state: &State) -> String {
    let pages = Pages::default();
    let view = View { state, pages: &pages };
    let mut text = String::new();
    page.render(&view, &mut Html::new(&mut text, 1 << 20)).unwrap();
    text
}

fn record_row(id: u64) -> String {
    format!(
        "{{\"id\":{id},\"node\":1,\"second\":100,\"ip\":\"8.8.12.1\",\"outcome\":\"rejected\",\
         \"cause\":3,\"algorithm\":1,\"parameter\":13,\"openings\":16,\"duration_ms\":null}}"
    )
}

#[test]
fn golden_challenges_page() {
    let mut app = App::new();
    configure(&mut app, Phase::Challenges);
    golden::check("challenges", app.render_now());
}

/// Ported from `challenges_page.zig`.
#[test]
fn the_page_distinguishes_posw_depth_and_untrusted_timing_without_conversion_claims() {
    let state = State { phase: Phase::Challenges, ..State::new() };
    let page = Challenges {
        snapshot: Some(Snapshot {
            configured: Defaults {
                algorithm: Algorithm::Posw,
                difficulty: 16,
                parameter: 13,
                openings: 16,
            },
            selected: 133,
            ..Snapshot::default()
        }),
        ..Challenges::default()
    };
    let output = render_page(&page, &state);
    assert!(output.contains("PoSW, depth 13"));
    assert!(output.contains("Untrusted client"));
    assert!(output.contains(
        "<option value=\"133\" selected>PoSW depth 8\u{2013}15, openings 16\u{2013}31 \u{b7} 0 \
         accepted</option>"
    ));
    assert!(output.contains("<th scope=\"row\">4 \u{2264} ms &lt; 8</th>"));
    assert!(output.contains("data-action=\"challenges-records-cause-12\""));
}

/// Ported from `challenge_records.zig`.
#[test]
fn records_decode_owned_addresses_and_render_absent_durations_as_not_recorded() {
    let mut state = State { phase: Phase::Challenges, ..State::new() };
    state.csrf.set("csrf").unwrap();
    state.role.set("admin").unwrap();
    let source = format!(
        "{{\"version\":1,\"retention_days\":7,\"observed_at\":1,\"from\":0,\"until\":1,\
         \"dropped_since_boot\":3,\"unconfirmed_since_boot\":2,\"rows\":[{}],\"next\":null}}",
        record_row(5)
    );
    let mut page = Challenges { snapshot: Some(Snapshot::default()), ..Challenges::default() };
    page.records.accept_records(&sibuna_json::parse(source.as_bytes()).unwrap()).unwrap();
    assert_eq!(page.records.rows.len(), 1);
    let output = render_page(&page, &state);
    assert!(output.contains("8.8.12.1"));
    assert!(output.contains("Malformed solution"));
    assert!(output.contains("Not recorded"));
    assert!(output.contains("events-deny-8.8.12.1"));
    assert!(output.contains("3 records dropped"));
    assert!(output.contains("2 batches unconfirmed"));
}

#[test]
fn records_and_transitions_take_the_protocol_bounds() {
    let rows: Vec<String> = (1..=12).map(record_row).collect();
    let page = |rows: &[String]| {
        format!(
            "{{\"version\":1,\"retention_days\":7,\"dropped_since_boot\":0,\
             \"unconfirmed_since_boot\":0,\"rows\":[{}],\"next\":{{\"second\":9,\"id\":4}}}}",
            rows.join(",")
        )
    };
    let mut model = Records::default();
    model.accept_records(&sibuna_json::parse(page(&rows).as_bytes()).unwrap()).unwrap();
    assert_eq!(model.rows.len(), 12);
    assert_eq!(model.next, Some(Cursor { second: 9, id: 4 }));
    let thirteen: Vec<String> = (1..=13).map(record_row).collect();
    let before = model.clone();
    assert!(
        model.accept_records(&sibuna_json::parse(page(&thirteen).as_bytes()).unwrap()).is_err()
    );
    assert_eq!(model, before);
    let transition = "{\"node\":1,\"second\":60,\"previous_bits\":0,\"bits\":2,\"rate_256\":2560}";
    let transitions = |count: usize| {
        format!(
            "{{\"version\":1,\"current_bits\":null,\"missed_since_boot\":4,\"rows\":[{}],\
             \"truncated\":true}}",
            vec![transition; count].join(",")
        )
    };
    model.accept_transitions(&sibuna_json::parse(transitions(32).as_bytes()).unwrap()).unwrap();
    assert_eq!(model.difficulty.as_ref().unwrap().rows.len(), 32);
    assert!(
        model
            .accept_transitions(&sibuna_json::parse(transitions(33).as_bytes()).unwrap())
            .is_err()
    );
    let page = Challenges {
        snapshot: Some(Snapshot::default()),
        records: model,
        ..Challenges::default()
    };
    let output = render_page(&page, &State::new());
    assert!(output.contains(
        "<p>Current adaptive bump: 0</p><p class=\"sb-note\">Not recorded on this node.</p>"
    ));
    assert!(
        output.contains(
            "<td>1970-01-01 00:01:00 UTC</td><td>1</td><td>0 \u{2192} 2</td><td>10</td>"
        )
    );
    assert!(output.contains("Only the newest 32 transitions are shown."));
    assert!(output.contains("4 changes observed on this node since boot were not recorded"));
}

#[test]
fn opening_the_page_loads_the_window_transitions_and_funnel_in_order() {
    let harness = opened();
    assert_eq!(harness.app.state().phase, Phase::Challenges);
    let commands = harness.commands();
    let summary = commands.find("\"id\":\"challenges-summary\"").unwrap();
    let difficulty = commands.find("\"id\":\"challenges-difficulty\"").unwrap();
    let funnel = commands.find("\"id\":\"challenges\"").unwrap();
    assert!(summary < difficulty && difficulty < funnel);
    assert!(commands.contains("\"body\":{\"hours\":24,\"bin\":null,\"before\":null}"));
    assert!(commands.contains("\"body\":{\"hours\":24}"));
    assert!(commands.contains(
        "\"path\":\"/console/api/challenges\",\"csrf\":\"test\",\"body\":{\"bin\":null}"
    ));
    assert!(harness.html().contains("Refreshing challenge observations\u{2026}"));
    assert!(harness.html().contains("Summing retained minutes\u{2026}"));
}

/// Ported from `main.zig`.
#[test]
fn a_complete_funnel_reply_releases_the_refresh() {
    let mut harness = opened();
    let snapshot = Snapshot { submitted: 123, bin_accepted: [1; 256], ..Snapshot::default() };
    harness.respond("challenges", 200, &to_json(&snapshot));
    let model = challenges(&mut harness.app);
    assert!(!model.busy);
    assert_eq!(model.snapshot.unwrap().submitted, 123);
    assert_eq!(model.received_at, 172_800);
    assert_eq!(model.selected, Some(0));
    assert!(harness.html().contains("<tr><th scope=\"row\">Submitted</th><td>123</td></tr>"));
    harness.action("challenges-bin", "{\"bin\":\"200\"}");
    assert!(harness.commands().contains("\"body\":{\"bin\":200}"));
    harness.respond("challenges", 500, "{\"error\":\"x\"}");
    assert!(challenges(&mut harness.app).stale);
    assert!(harness.app.state().message.as_str().starts_with("Could not refresh challenges."));
    harness.action("challenges-refresh", "null");
    harness.respond("challenges", 200, "{\"issued\":\"x\"}");
    assert_eq!(
        harness.app.state().message.as_str(),
        "Could not read challenge observations. Try refreshing."
    );
    harness.action("challenges-refresh", "null");
    harness.respond("challenges", 403, "{}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert_eq!(
        harness.app.state().message.as_str(),
        "Your access changed. Sign in again to view challenges."
    );
}

#[test]
fn a_long_window_continues_from_its_cursor_a_bounded_number_of_times() {
    let mut harness = opened();
    harness.respond("challenges", 200, &to_json(&Snapshot::default()));
    let mut part = Summary::default();
    part.coverage.from = 100;
    part.coverage.until = 1539;
    part.coverage.next = Some(MinuteCursor { minute: 1500, node: 2, boot: [0xab; 16], epoch: 3 });
    part.totals.issued = 5;
    for _ in 0..MAX_CONTINUATIONS {
        harness.respond("challenges-summary", 200, &to_json(&part));
        assert!(harness.commands().contains(
            "\"before\":{\"minute\":1500,\"node\":2,\"boot\":\"abababababababababababababababab\",\
             \"epoch\":3}"
        ));
    }
    harness.respond("challenges-summary", 200, &to_json(&part));
    assert!(!harness.commands().contains("challenges-summary"));
    let window = &challenges(&mut harness.app).window;
    assert!(!window.busy && !window.failed);
    assert_eq!(window.continuations, MAX_CONTINUATIONS);
    assert_eq!(window.summary.unwrap().totals.issued, 5 * (u64::from(MAX_CONTINUATIONS) + 1));
    let html = harness.html();
    assert!(html.contains("0 recorded minutes (0 complete) of 1440 in the window"));
    assert!(html.contains("The window exceeds the bounded scan"));
    harness.action("challenges-period", "{\"hours\":\"1\"}");
    assert!(harness.commands().contains("\"body\":{\"hours\":1,\"bin\":null,\"before\":null}"));
    harness.respond("challenges-summary", 500, "{}");
    assert!(harness.html().contains("Retained challenge minutes are unavailable. Retry."));
    harness.action("challenges-period", "{\"hours\":\"2\"}");
    assert_eq!(
        harness.app.state().message.as_str(),
        "Could not complete the action. Please try again."
    );
}

#[test]
fn record_filters_come_from_the_action_name() {
    let mut harness = opened();
    harness.respond("challenges", 200, &to_json(&Snapshot::default()));
    harness.action("challenges-records-cause-3", "null");
    assert!(
        harness.commands().contains(
            "\"body\":{\"hours\":24,\"outcome\":\"rejected\",\"cause\":3,\"before\":null}"
        )
    );
    let page = format!(
        "{{\"version\":1,\"retention_days\":7,\"dropped_since_boot\":0,\
         \"unconfirmed_since_boot\":0,\"rows\":[{}],\"next\":{{\"second\":100,\"id\":5}}}}",
        record_row(5)
    );
    harness.respond("challenges-records", 200, &page);
    assert!(harness.commands().contains("{\"op\":\"focus\",\"selector\":\"#challenge-records\"}"));
    assert!(harness.html().contains("<p class=\"sb-note\">Malformed solution \u{b7} 0 records"));
    harness.action("challenges-records-more", "null");
    assert!(harness.commands().contains("\"before\":{\"second\":100,\"id\":5}"));
    harness.respond("challenges-records", 0, "{}");
    assert!(harness.html().contains("Records unavailable. Retry."));
    harness.action("challenges-records-accepted", "null");
    assert!(harness.commands().contains("\"outcome\":\"accepted\",\"cause\":null"));
    harness.respond("challenges-difficulty", 200, "{\"version\":2}");
    assert!(harness.html().contains("Transitions unavailable. Retry."));
}

#[test]
fn live_funnels_keep_the_shown_partition_and_go_stale_with_the_connection() {
    let mut harness = connected();
    harness.action("challenges", "null");
    assert!(harness.commands().contains("\"op\":\"sub\",\"topic\":\"challenges\",\"args\":{}"));
    let shown = Snapshot { selected: 7, buckets: [2; 16], issued: 1, ..Snapshot::default() };
    harness.respond("challenges", 200, &to_json(&shown));
    let other = Snapshot { selected: 0, buckets: [9; 16], issued: 4, ..Snapshot::default() };
    live_view(&mut harness, "challenges", &to_json(&other));
    let model = challenges(&mut harness.app);
    let snapshot = model.snapshot.unwrap();
    assert_eq!(snapshot.issued, 4);
    assert_eq!(snapshot.selected, 7);
    assert_eq!(snapshot.buckets, [2; 16]);
    assert!(!model.stale);
    harness.stream("{\"state\":\"closed\",\"entropy\":1}");
    assert!(challenges(&mut harness.app).stale);
    assert!(harness.html().contains("Disconnected / stale \u{b7} Received 0 seconds ago."));
}
