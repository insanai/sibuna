use sibuna_console_protocol::Text;
use sibuna_console_protocol::events::{Capture, Cursor, Row};
use sibuna_console_protocol::security::Module;

use super::*;
use crate::app::App;
use crate::golden::{self, configure};
use crate::page::Pages;
use crate::pages::similarity::Similarity;
use crate::testing::{ADMIN_SESSION, Harness};

fn events(app: &mut App) -> &mut Events {
    app.pages_mut().find_mut::<Events>().unwrap()
}

fn signed_in() -> Harness {
    let mut harness = Harness::new();
    harness.respond("session", 200, ADMIN_SESSION);
    harness
}

fn render_page(page: &Events, state: &State) -> String {
    let pages = Pages::default();
    let view = View { state, pages: &pages };
    let mut text = String::new();
    page.render(&view, &mut Html::new(&mut text, 1 << 20)).unwrap();
    text
}

#[test]
fn golden_events_page() {
    let mut app = App::new();
    configure(&mut app, Phase::Events);
    golden::check("events", app.render_now());
}

/// Ported from `events_page.zig`.
#[test]
fn historical_incident_rendering_escapes_stored_markup_and_names_absent_fields() {
    let mut state = State { phase: Phase::Events, ..State::new() };
    let mut page = Events::default();
    page.model.loaded = true;
    page.model.rows.push(Row {
        id: 9_007_199_254_740_993,
        time: 0,
        user_agent: Text::new("<script>alert(1)</script>").unwrap(),
        path: Text::new("/\"quoted\"").unwrap(),
        ..Row::default()
    });
    let output = render_page(&page, &state);
    assert!(!output.contains("<script>"));
    assert!(output.contains("&lt;script&gt;"));
    assert!(output.contains("9007199254740993"));
    assert!(output.contains("Not recorded"));
    assert!(output.contains("1970-01-01 00:00:00 UTC"));
    assert!(output.contains("JA4 fingerprint"));
    assert!(!output.contains("events-deny-"));
    state.csrf.set("test").unwrap();
    state.role.set("operator").unwrap();
    let row = &mut page.model.rows[0];
    row.ip = Text::new("203.0.113.9").unwrap();
    row.category = Text::new("honeypot").unwrap();
    row.capture = Some(Capture { selected_status: 403, ..Capture::default() });
    let managed = render_page(&page, &state);
    assert!(managed.contains("events-deny-203.0.113.9"));
    assert!(managed.contains("events-allow-203.0.113.9"));
    assert!(managed.contains("sb-chip sb-decision-banned"));
    assert!(managed.contains("Local denial: status 403"));
    state.kiosk = true;
    assert!(!render_page(&page, &state).contains("events-deny-"));
}

#[test]
fn evidence_names_every_truncation_and_groups_name_their_source() {
    let state = State { phase: Phase::Events, ..State::new() };
    let mut page = Events::default();
    page.model.rows.push(Row {
        capture: Some(Capture { truncated: 0b1000_0101, ..Capture::default() }),
        ..Row::default()
    });
    page.model.rows.push(Row {
        grouped: true,
        count: 2,
        node: 7,
        ip: Text::new("2001:db8::1").unwrap(),
        ..Row::default()
    });
    let output = render_page(&page, &state);
    assert!(output.contains(
        "Capture limits: client address, method, byte length saturated (shown as a lower \
         bound).</p>"
    ));
    assert!(output.contains("<p>2 recorded incidents \u{b7} Node 7</p>"));
    assert!(output.contains("data-action=\"events-source-7/2001:db8::1\""));
}

/// Ported from `events_actions.zig`.
#[test]
fn country_investigation_keeps_the_selected_node_and_cannot_escape_kiosk_scope() {
    let mut harness = signed_in();
    harness.app.state_mut().dashboard_node = Some(7);
    harness.action("events-country-US", "null");
    let state = harness.app.state();
    assert_eq!(state.phase, Phase::Events);
    let model = &events(&mut harness.app).model;
    assert_eq!(model.country.as_str(), "US");
    assert_eq!(model.node, 7);
    assert_eq!(model.until, 172_800);
    assert_eq!(model.hours, 1);
    assert!(model.busy);
    assert!(harness.commands().contains("\"id\":\"events\""));
    let mut harness = signed_in();
    harness.app.state_mut().kiosk = true;
    harness.action("events-country-DE", "null");
    assert_eq!(harness.app.state().phase, Phase::Dashboard);
}

/// Ported from `events_actions.zig`.
#[test]
fn incident_navigation_requires_full_authentication_and_preserves_paging_time_bounds() {
    let mut harness = Harness::new();
    harness.action("events", "null");
    assert_eq!(harness.app.state().phase, Phase::Loading);
    harness.respond("session", 200, &ADMIN_SESSION.replace("false", "true"));
    harness.action("events", "null");
    assert_eq!(harness.app.state().phase, Phase::Password);
    let mut harness = signed_in();
    harness.send(1, "{\"action\":\"events\",\"browser_time\":200}");
    assert_eq!(harness.app.state().phase, Phase::Events);
    let model = &mut events(&mut harness.app).model;
    model.busy = false;
    model.next = Some(Cursor { time: 150, id: 9_007_199_254_740_993 });
    harness.send(1, "{\"action\":\"events-next\",\"browser_time\":200}");
    assert!(harness.commands().contains("\"before\":{\"time\":150,\"id\":\"9007199254740993\"}"));
    events(&mut harness.app).model.busy = false;
    harness.send(1, "{\"action\":\"events-prev\",\"browser_time\":300}");
    assert_eq!(events(&mut harness.app).model.until, 200);
    assert!(harness.commands().contains("\"before\":null"));
}

/// Ported from `events_actions.zig`.
#[test]
fn source_drill_down_retains_node_address_and_the_selected_time_boundary() {
    let mut harness = signed_in();
    harness.send(1, "{\"action\":\"events\",\"browser_time\":200}");
    events(&mut harness.app).model.busy = false;
    harness.action("events-source", "null");
    assert!(events(&mut harness.app).model.grouped);
    events(&mut harness.app).model.busy = false;
    harness.send(1, "{\"action\":\"events-source-7/2001:4860::1\",\"browser_time\":300}");
    let model = &events(&mut harness.app).model;
    assert!(!model.grouped);
    assert_eq!(model.node, 7);
    assert_eq!(model.ip.as_str(), "2001:4860::1");
    assert_eq!(model.until, 200);
}

/// Ported from `events_actions.zig`.
#[test]
fn campaign_navigation_preserves_exact_identifiers_and_time_boundaries_across_nodes() {
    let mut harness = signed_in();
    harness.action("events", "null");
    let model = &mut events(&mut harness.app).model;
    model.busy = false;
    model.until = 200;
    model.node = 7;
    model.ip = Text::new("8.8.8.8").unwrap();
    harness.action("events-campaign-9007199254740993", "null");
    let model = &events(&mut harness.app).model;
    assert_eq!(model.campaign, 9_007_199_254_740_993);
    assert_eq!(model.until, 200);
    assert_eq!(model.node, 0);
    assert!(model.ip.is_empty());
    assert!(harness.commands().contains("\"campaign\":\"9007199254740993\""));
    events(&mut harness.app).model.busy = false;
    harness.action("events-clear-campaign", "null");
    assert_eq!(events(&mut harness.app).model.campaign, 0);
}

/// Ported from `security_investigation.zig`: the drill-down keeps the node and turns the
/// half-open period into inclusive endpoints.
#[test]
fn security_drill_down_preserves_the_node_and_half_open_period() {
    let mut harness = signed_in();
    let app = &mut harness.app;
    app.state_mut().phase = Phase::SecurityOverview;
    let investigation = Investigation {
        module: Some(Module::Inspection),
        node: 2,
        from: 100,
        until: 220,
        hours: 0,
        ..Default::default()
    };
    let mut page = Events::default();
    {
        let mut live = crate::live::Connection::default();
        let mut commands = crate::commands::Commands::default();
        commands.begin();
        let mut pages = Pages::default();
        let mut cx = Context {
            state: app.state_mut(),
            commands: &mut commands,
            pages: &mut pages,
            live: &mut live,
        };
        page.investigate(&mut cx, investigation).unwrap();
        commands.end();
        assert!(commands.as_str().contains("\"module\":\"inspection\""));
        assert!(commands.as_str().contains("\"until\":219,\"from\":100"));
    }
    assert_eq!(page.model.module, Some(Module::Inspection));
    assert_eq!(page.model.from, Some(100));
    assert_eq!(page.model.until, 219);
    assert_eq!(page.model.node, 2);
    assert_eq!(app.state().phase, Phase::Events);
    let output = render_page(&page, app.state());
    assert!(output.contains(
        "Security drill-down uses the fixed period 1970-01-01 00:01:40 UTC through \
         1970-01-01 00:03:39 UTC."
    ));
    assert!(output.contains("<option value=\"inspection\" selected>inspection</option>"));
}

#[test]
fn queries_carry_the_filters_in_the_zig_member_order() {
    let mut harness = signed_in();
    harness.action("events", "null");
    assert!(harness.commands().contains(
        "{\"op\":\"request\",\"id\":\"events\",\"method\":\"POST\",\
         \"filename\":\"sibuna-events.json\",\"path\":\"/console/api/events/query\",\
         \"csrf\":\"test\",\"body\":{\"format\":\"json\",\"view\":\"raw\",\"node\":0,\
         \"campaign\":\"\",\"incident\":\"\",\"before\":null,\"category\":\"\",\
         \"module\":null,\"country\":\"\",\"ip\":\"\",\"path_prefix\":\"\",\
         \"until\":172800,\"from\":0}}"
    ));
    events(&mut harness.app).model.busy = false;
    harness.action(
        "events-filter",
        "{\"module\":\"honeypot\",\"category\":\"waf:sqli\",\"country\":\"US\",\
         \"ip\":\"192.0.2.1\",\"path_prefix\":\"/a\",\"hours\":\"24\",\"node\":\"3\"}",
    );
    assert!(harness.commands().contains(
        "\"body\":{\"format\":\"json\",\"view\":\"raw\",\"node\":3,\"campaign\":\"\",\
         \"incident\":\"\",\"before\":null,\"category\":\"waf:sqli\",\"module\":\"honeypot\",\
         \"country\":\"US\",\"ip\":\"192.0.2.1\",\"path_prefix\":\"/a\",\"until\":172800,\
         \"from\":86400}"
    ));
}

#[test]
fn a_refused_filter_form_changes_nothing() {
    let mut harness = signed_in();
    harness.action("events", "null");
    events(&mut harness.app).model.busy = false;
    let before = events(&mut harness.app).model.clone();
    for fields in [
        "{\"module\":\"nope\",\"hours\":\"0\"}",
        "{\"category\":\"c\",\"country\":\"us\",\"hours\":\"0\"}",
        "{\"hours\":\"2\"}",
        "{\"hours\":\"\"}",
        "{\"hours\":\"0\",\"node\":\"x\"}",
    ] {
        harness.action("events-filter", fields);
        assert_eq!(events(&mut harness.app).model, before, "{fields}");
        assert_eq!(
            harness.app.state().message.as_str(),
            "Could not complete the action. Please try again."
        );
    }
}

#[test]
fn replies_fill_the_page_and_focus_results_after_a_filter() {
    let mut harness = signed_in();
    harness.action("events", "null");
    let row = "{\"id\":\"9007199254740993\",\"campaign\":\"9007199254740993\",\
               \"capture\":{\"selected_status\":403,\"query_bytes\":20,\"body_bytes\":30,\
               \"declared_body_bytes\":40,\"truncated\":64}}";
    // Ported from `main.zig`: a full page keeps exact candidate identifiers.
    let body = format!("{{\"rows\":[{}],\"next\":null}}", [row; 10].join(","));
    harness.respond("events", 200, &body);
    let model = &events(&mut harness.app).model;
    assert!(!model.busy);
    assert_eq!(model.rows.len(), 10);
    assert_eq!(model.rows[0].campaign, Some(9_007_199_254_740_993));
    assert!(!harness.commands().contains("Incident results"));
    assert!(harness.html().contains("Capture limits: body incomplete."));
    harness.action("events-refresh", "null");
    harness.respond("events", 200, "{\"rows\":[]}");
    assert!(
        harness
            .commands()
            .contains("{\"op\":\"focus\",\"selector\":\"[aria-label=\\\"Incident results\\\"]\"}")
    );
    assert!(harness.html().contains("No recorded incidents match these filters."));
}

#[test]
fn reply_failures_name_their_cause() {
    let mut harness = signed_in();
    harness.action("events", "null");
    harness.respond("events", 200, "{\"rows\":[{\"node\":1}]}");
    assert_eq!(
        harness.app.state().message.as_str(),
        "Could not read incidents. Narrow the filters and try again."
    );
    harness.action("events-refresh", "null");
    harness.respond("events", 200, "{\"rows\":[{\"id\":\"x\"}]}");
    assert_eq!(
        harness.app.state().message.as_str(),
        "Could not read incident fields. Please try again."
    );
    harness.action("events-refresh", "null");
    harness.respond("events", 429, "{}");
    assert!(harness.app.state().message.as_str().starts_with("The query allowance is used."));
    harness.action("events-refresh", "null");
    harness.respond("events", 403, "{}");
    assert_eq!(harness.app.state().phase, Phase::Login);
    assert!(harness.app.state().csrf.is_empty());
    assert_eq!(
        harness.app.state().message.as_str(),
        "Your access changed. Sign in again to view incidents."
    );
}

#[test]
fn exports_download_the_page_and_report_their_outcome() {
    let mut harness = signed_in();
    harness.action("events", "null");
    harness.action("events-export", "null");
    assert!(!harness.commands().contains("download"));
    harness.respond("events", 200, "{\"rows\":[{\"id\":\"1\"}]}");
    harness.action("events-export-csv", "null");
    assert!(harness.commands().starts_with(
        "[{\"op\":\"download\",\"id\":\"events-export\",\"method\":\"POST\",\
         \"filename\":\"sibuna-events.csv\",\"path\":\"/console/api/events/export\",\
         \"csrf\":\"test\",\"body\":{\"format\":\"csv\","
    ));
    assert!(events(&mut harness.app).model.exporting);
    assert!(harness.html().contains("data-action=\"events-export\" disabled"));
    harness.respond("events-export", 200, "{}");
    assert!(harness.html().contains(
        "<p class=\"sb-note\" role=\"status\">Your page export is ready. It contains records \
         matching this view.</p>"
    ));
    harness.action("events-export", "null");
    harness.respond("events-export", 429, "{}");
    assert!(harness.html().contains("<p class=\"sb-error\" role=\"status\">The export allowance"));
}

#[test]
fn heads_load_on_request_and_copy_the_plain_command() {
    let mut harness = signed_in();
    harness.action("events", "null");
    harness.respond("events", 200, "{\"rows\":[{\"id\":\"5\"}]}");
    assert!(harness.html().contains("data-action=\"events-heads-5\""));
    harness.action("events-heads-5", "null");
    assert!(harness.commands().contains(
        "\"id\":\"events-heads\",\"path\":\"/console/api/events/heads\",\"csrf\":\"test\",\
         \"body\":{\"id\":\"5\"}"
    ));
    assert!(harness.html().contains("Loading heads\u{2026}"));
    let request: String = b"GET /a HTTP/1.1\r\nHost: h\r\nX-Q: <it's>\r\n"
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    harness.respond(
        "events-heads",
        200,
        &format!(
            "{{\"version\":1,\"id\":5,\"recorded\":true,\"request\":\"{request}\",\
             \"response\":\"\",\"request_truncated\":false,\"response_truncated\":false,\
             \"response_state\":\"local\"}}"
        ),
    );
    let html = harness.html();
    assert!(html.contains(
        "<pre class=\"whitespace-pre-wrap break-all\">GET /a HTTP/1.1\nHost: h\n\
         X-Q: &lt;it&#39;s&gt;\n</pre>"
    ));
    assert!(html.contains("Local response: Sibuna answered the client"));
    assert!(html.contains("-H &#39;X-Q: &lt;it&#39;\\&#39;&#39;s&gt;&#39;"));
    harness.action("events-heads-copy", "null");
    assert!(harness.commands().contains(
        "{\"op\":\"copy\",\"id\":\"events-heads-copy\",\"text\":\"curl --globoff -X 'GET' \
         'http://h/a' \\\\\\n  -H 'X-Q: <it'\\\\''s>'\\n# incomplete: 0 values redacted or \
         omitted; body not captured; scheme assumed\\n\"}"
    ));
    harness.respond("events-heads-copy", 200, "{}");
    assert!(harness.html().contains("Copied to the clipboard."));
    harness.action("events-heads-latin1", "null");
    assert!(harness.html().contains("Rendered as Latin-1."));
}

#[test]
fn a_heads_reply_after_leaving_the_page_frees_the_request() {
    let mut harness = signed_in();
    harness.action("events", "null");
    harness.respond("events", 200, "{\"rows\":[{\"id\":\"5\"}]}");
    harness.action("events-heads-5", "null");
    harness.action("dashboard", "null");
    harness.respond("events-heads", 0, "{}");
    assert_eq!(events(&mut harness.app).heads, IncidentHeads::default());
    harness.action("events", "null");
    harness.respond("events", 200, "{\"rows\":[{\"id\":\"5\"}]}");
    harness.action("events-heads-5", "null");
    assert!(harness.commands().contains("\"id\":\"events-heads\""));
    harness.respond("events-heads", 500, "{}");
    assert!(harness.html().contains("Heads unavailable."));
}

/// Opens the live connection of a signed-in harness.
pub(crate) fn connected() -> Harness {
    let mut harness = signed_in();
    assert!(harness.commands().contains("/console/ws"));
    harness.stream("{\"state\":\"open\"}");
    harness
}

/// Delivers the snapshot `data` of `topic` in subscription epoch 1, in parts of 256 bytes.
pub(crate) fn live_view(harness: &mut Harness, topic: &str, data: &str) {
    let digits = "a".repeat(32);
    let pieces: Vec<&str> =
        data.as_bytes().chunks(256).map(|piece| std::str::from_utf8(piece).unwrap()).collect();
    let parts = pieces.len();
    let mut send = |op: &str, sequence: usize, part: usize, data: &str| {
        harness.stream(&format!(
            "{{\"state\":\"message\",\"browser_time\":172800,\"body\":{{\"op\":\"{op}\",\
             \"topic\":\"{topic}\",\"epoch\":\"{digits}:1\",\"seq\":{sequence},\
             \"snapshot\":true,\"watermark\":0,\"parts\":{parts},\"part\":{part},\
             \"data\":{data}}}}}"
        ));
    };
    send("snapshot_begin", 0, 0, "null");
    for (index, piece) in pieces.iter().enumerate() {
        let mut text = String::new();
        sibuna_json::write_string(&mut text, piece).unwrap();
        send("snapshot_chunk", index + 1, index, &text);
    }
    send("snapshot_end", parts + 1, parts, "null");
}

#[test]
fn live_rows_count_what_is_newer_than_the_page() {
    let mut harness = connected();
    harness.action("events", "null");
    assert!(harness.commands().contains("\"op\":\"sub\",\"topic\":\"events\",\"args\":{}"));
    live_view(
        &mut harness,
        "events",
        "{\"rows\":[{\"id\":1,\"time\":172801},{\"id\":2,\"time\":100}],\
         \"coverage\":{\"available\":true,\"observed_at\":172790,\"missing_ids\":3}}",
    );
    assert_eq!(harness.app.state().live.topic(Topic::Events).newer, 1);
    assert!(harness.html().contains(
        "<p>Live \u{b7} Last update 0 seconds ago.</p><p>1 recent summaries newer than this page."
    ));
    assert!(harness.html().contains("3 unavailable source IDs"));
    // An incident or campaign page has no live feed.
    harness.action("events-incident-4", "null");
    assert!(harness.commands().contains("\"op\":\"unsub\",\"topic\":\"events\""));
}

#[test]
fn incident_links_pause_similarity_and_lead_back() {
    let mut harness = signed_in();
    harness.action("events", "null");
    harness.respond("events", 200, "{\"rows\":[{\"id\":\"1\"}]}");
    harness.action("events-similar-1", "null");
    assert_eq!(harness.app.state().phase, Phase::Similarity);
    harness.action("events-incident-2", "null");
    assert_eq!(harness.app.state().phase, Phase::Events);
    assert_eq!(events(&mut harness.app).model.incident, 2);
    let similarity = harness.app.pages().find::<Similarity>().unwrap();
    assert!(!similarity.model.running);
    assert!(harness.html().contains("data-action=\"similarity-return\""));
    assert!(harness.html().contains("Incident #2"));
    harness.action("events-incident-0", "null");
    assert_eq!(
        harness.app.state().message.as_str(),
        "Could not complete the action. Please try again."
    );
}

/// Valid replies of every reader, the seeds of the mutation test.
const SEEDS: [&str; 4] = [
    "{\"rows\":[{\"id\":\"9007199254740993\",\"campaign\":\"7\",\"geography\":{\
     \"code\":\"US\",\"generation\":null,\"recorded\":true},\"capture\":{\
     \"selected_status\":403,\"query_bytes\":1,\"body_bytes\":2,\"declared_body_bytes\":3,\
     \"truncated\":64}}],\"next\":{\"time\":5,\"id\":\"4\"}}",
    "{\"version\":1,\"id\":5,\"recorded\":true,\"request\":\"474554202f20\",\
     \"response\":\"\",\"request_truncated\":false,\"response_truncated\":true,\
     \"response_state\":\"local\"}",
    "{\"generation\":1,\"source_available\":true,\"scanned\":64,\"invalid\":1,\
     \"rows\":[{\"id\":\"9\",\"node\":3,\"time\":7300,\"distance\":0.5}],\
     \"next\":{\"time\":7,\"id\":\"9\"}}",
    "{\"version\":1,\"retention_days\":7,\"dropped_since_boot\":0,\
     \"unconfirmed_since_boot\":0,\"rows\":[{\"id\":5,\"node\":1,\"second\":100,\
     \"ip\":\"8.8.12.1\",\"outcome\":\"rejected\",\"cause\":3,\"algorithm\":1,\
     \"parameter\":13,\"openings\":16,\"duration_ms\":null}],\"next\":null}",
];

/// Returns a mutant of a seed: a bit flip, a truncation, a duplicated tail, a splice of
/// two seeds, or a letter or digit replaced with another (which mostly keeps the JSON
/// valid, so the readers see wrong values rather than syntax errors).
fn mutant(next: &mut impl FnMut() -> u64) -> Vec<u8> {
    let pick = |value: u64| SEEDS[(value % SEEDS.len() as u64) as usize].as_bytes();
    let mut bytes = pick(next()).to_vec();
    let position = (next() % bytes.len() as u64) as usize;
    match next() % 8 {
        0 => bytes[position] ^= 1 << (next() % 8),
        1 => bytes.truncate(position),
        2 => {
            let piece = bytes[position..].to_vec();
            bytes.extend_from_slice(&piece);
        }
        3 => {
            let other = pick(next());
            bytes.truncate(position);
            bytes.extend_from_slice(&other[(next() % other.len() as u64) as usize..]);
        }
        _ if bytes[position].is_ascii_alphanumeric() => {
            let alphabet = b"0123456789aefnrtuxz";
            bytes[position] = alphabet[(next() % alphabet.len() as u64) as usize];
        }
        _ => {}
    }
    bytes
}

/// Feeds one document to every reader; a refused document changes nothing.
fn read_everything(value: &Value<'_>) {
    let mut model = Model::default();
    if let Ok(page) = WirePage::read(value) {
        let accepted = model.accept(&page).is_ok();
        assert_eq!(accepted, model.loaded);
        assert!(model.rows.len() <= PAGE_ROWS);
    }
    let mut heads = IncidentHeads { id: 5, ..IncidentHeads::default() };
    if heads.set(value).is_err() {
        assert_eq!(heads, IncidentHeads { id: 5, ..IncidentHeads::default() });
    }
    let _ = heads::curl(&heads.request, heads.request_truncated);
    let mut search = crate::pages::similarity::Model { until: 9999, ..Default::default() };
    if let Ok(part) = crate::pages::similarity::Part::read(value) {
        let before = search.clone();
        if search.accept(&part).is_err() {
            assert_eq!(search, before);
        }
    }
    let mut records = crate::pages::challenges::Records::default();
    if records.accept_records(value).is_err() {
        assert_eq!(records, crate::pages::challenges::Records::default());
    }
    let _ = records.accept_transitions(value);
}

/// Mutated replies never panic any reader of the investigation pages, and a refused reply
/// changes nothing.
#[test]
fn random_replies_never_panic() {
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut parsed = 0;
    for _ in 0..100_000 {
        let bytes = mutant(&mut next);
        let _ = crate::pages::request_headers::parse(&String::from_utf8_lossy(&bytes));
        if let Ok(value) = sibuna_json::parse(&bytes) {
            parsed += 1;
            read_everything(&value);
        }
    }
    // The mutations must reach the readers, not only the JSON parser.
    assert!(parsed > 20_000, "{parsed}");
}
