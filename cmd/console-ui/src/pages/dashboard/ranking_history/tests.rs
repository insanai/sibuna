//! Tests of retained path rankings.

use sibuna_console_protocol::ranking_storage::Minute;
use sibuna_console_protocol::rankings_archive::{Archive, Identity};

use super::*;
use crate::commands::Commands;
use crate::live::Connection;
use crate::page::Pages;
use crate::pages::dashboard::hex_lower;

/// One archive of node 7 at minute 2 holding 256 distinct paths, with its cursor.
fn archive() -> (String, Cursor) {
    let mut minute =
        Minute { minute: Some(2), first_second: 120, last_second: 120, ..Minute::default() };
    for index in 0..256 {
        minute.paths.add(format!("/{index}").as_bytes()).unwrap();
    }
    let source =
        Archive { identity: Identity { node: 7, boot: [1; 16], ..Identity::default() }, minute };
    let bytes = rankings_archive::encode(&source).unwrap();
    let digest = hex_lower(&sibuna_crypto::sha256::Sha256::digest(&bytes));
    (hex_lower(&bytes), Cursor { minute: 2, digest: Text::new(&digest).unwrap() })
}

fn reply(hex: &str, cursor: &Cursor) -> Reply {
    Reply {
        version: 1,
        archive: hex.to_owned(),
        metadata: Metadata {
            from_minute: 1,
            until_minute: 2,
            retention_days: 7,
            observed_at: 240,
            cursor: Some(cursor.clone()),
            next: Some(cursor.clone()),
        },
    }
}

#[test]
fn archive_pagination_merges_every_counter_and_refuses_a_replay_without_partial_publication() {
    let query = Request { from_minute: 1, until_minute: 2, node: Some(7), before: None };
    let mut window = Window { query, ..Window::default() };
    let (hex, cursor) = archive();
    window.accept(&reply(&hex, &cursor)).unwrap();
    assert_eq!(window.summary.len(), 256);
    assert_eq!(window.archives, 1);
    let saved = window.clone();
    assert_eq!(window.accept(&reply(&hex, &cursor)), Err(UiError::InvalidResponse));
    assert_eq!(window, saved);
}

#[test]
fn archives_must_match_their_digest_node_and_hex_encoding() {
    let (hex, cursor) = archive();
    let query = Request { from_minute: 1, until_minute: 2, node: Some(8), before: None };
    let mut other_node = Window { query: query.clone(), ..Window::default() };
    assert!(other_node.accept(&reply(&hex, &cursor)).is_err());
    let mut window = Window { query: Request { node: None, ..query }, ..Window::default() };
    let mut tampered = hex.clone();
    tampered.replace_range(..2, if hex.starts_with("00") { "01" } else { "00" });
    assert!(window.accept(&reply(&tampered, &cursor)).is_err());
    assert!(window.accept(&reply(&hex[1..], &cursor)).is_err());
    assert_eq!(window, Window { query: window.query.clone(), ..Window::default() });
    assert!(window.accept(&reply(&hex.to_uppercase(), &cursor)).is_ok());
    assert_eq!(hex_decode("0g"), None);
}

#[test]
fn an_empty_window_finishes_without_an_archive() {
    let query = Request { from_minute: 1, until_minute: 2, node: None, before: None };
    let mut window = Window { query, ..Window::default() };
    let mut empty = reply("", &Cursor::default());
    empty.metadata.cursor = None;
    empty.metadata.next = None;
    empty.metadata.from_minute = 2;
    window.accept(&empty).unwrap();
    assert!(window.finished && window.retention_clipped && window.archives == 0);
}

/// Runs `handler` with a context over `state`; returns its result and the command count.
fn run<T>(state: &mut State, handler: impl FnOnce(&mut Context<'_>) -> T) -> (T, usize) {
    let mut commands = Commands::default();
    commands.begin();
    let mut pages = Pages::default();
    let mut live = Connection::default();
    let mut cx = Context { state, commands: &mut commands, pages: &mut pages, live: &mut live };
    let result = handler(&mut cx);
    (result, commands.count())
}

#[test]
fn retained_ranking_actions_keep_their_scope_and_discard_responses_after_sign_out() {
    let mut state = State::new();
    let mut model = Model::default();
    let mut serial = 0;
    let null = Value::Null;
    let (claimed, _) =
        run(&mut state, |cx| action(&mut model, &mut serial, cx, "rank-history-toggle", &null));
    assert_eq!(claimed, Ok(false));
    state.phase = Phase::Dashboard;
    state.csrf.set("session").unwrap();
    let (claimed, _) =
        run(&mut state, |cx| action(&mut model, &mut serial, cx, "rank-history-toggle", &null));
    assert_eq!(claimed, Ok(true));
    model.started = true;
    model.windows[0].query =
        Request { node: Some(7), from_minute: 1, until_minute: 2, before: None };
    let (claimed, count) =
        run(&mut state, |cx| action(&mut model, &mut serial, cx, "rank-history-more", &null));
    assert_eq!((claimed, count), (Ok(true), 1));
    assert_eq!(model.remaining, 15);
    let saved = model.windows[0].query.clone();
    let id = format!("{PREFIX}{}", model.ticket);
    let limited = Envelope { id: &id, status: Some(429), body: Some(&null), envelope: &null };
    run(&mut state, |cx| response(&mut model, &mut serial, cx, &limited)).0.unwrap();
    assert!(!model.busy);
    assert_eq!(model.windows[0].query, saved);
    assert!(model.message.as_str().starts_with("RANKHISTORY429"));
    state.reset();
    model = Model::default();
    let expired = Envelope { id: &id, status: Some(401), body: Some(&null), envelope: &null };
    run(&mut state, |cx| response(&mut model, &mut serial, cx, &expired)).0.unwrap();
    assert_eq!(state.phase, Phase::Loading);
    assert!(!model.open);
}

#[test]
fn a_started_scan_posts_the_query_with_its_frozen_range() {
    let mut state = State::new();
    state.phase = Phase::Dashboard;
    state.csrf.set("session").unwrap();
    state.stats =
        Some(sibuna_console_protocol::StatsSnapshot { timestamp: 600_000, ..Default::default() });
    let mut model = Model { open: true, ..Model::default() };
    let mut serial = 0;
    let form = sibuna_json::parse(
        br#"{"mode":"yesterday","minutes":"60","offset":"0","node":"3","other_node":"0"}"#,
    )
    .unwrap();
    let (claimed, count) =
        run(&mut state, |cx| action(&mut model, &mut serial, cx, "rank-history-start", &form));
    assert_eq!((claimed, count), (Ok(true), 1));
    assert_eq!(model.windows[0].query.until_minute, 9999);
    assert_eq!(model.windows[1].query.until_minute, 9999 - 1440);
    assert_eq!(model.windows[1].query.node, Some(3));
    let bad = sibuna_json::parse(br#"{"mode":"sideways"}"#).unwrap();
    model.busy = false;
    run(&mut state, |cx| action(&mut model, &mut serial, cx, "rank-history-start", &bad))
        .0
        .unwrap();
    assert!(model.message.as_str().starts_with("RANKHISTORY001"));
}

/// The JSON text of a one-archive page of node 7 at minute 2, with three paths.
fn small_page() -> String {
    let mut minute =
        Minute { minute: Some(2), first_second: 120, last_second: 125, ..Minute::default() };
    for key in [&b"/a"[..], b"/b", b"/a"] {
        minute.paths.add(key).unwrap();
    }
    let identity = Identity { node: 7, boot: [1; 16], ..Identity::default() };
    let bytes = rankings_archive::encode(&Archive { identity, minute }).unwrap();
    let digest = hex_lower(&sibuna_crypto::sha256::Sha256::digest(&bytes));
    format!(
        "{{\"version\":1,\"metadata\":{{\"from_minute\":1,\"until_minute\":2,\
         \"retention_days\":7,\"observed_at\":240,\"cursor\":{{\"minute\":2,\
         \"digest\":\"{digest}\"}},\"next\":null}},\"archive\":\"{}\"}}",
        hex_lower(&bytes)
    )
}

/// Mutated archive pages never panic and never change a window they are refused by.
#[test]
fn fuzz_archive_pages_are_merged_whole_or_not_at_all() {
    let page = small_page();
    let empty = r#"{"version":1,"metadata":{"from_minute":1,"until_minute":2,
        "retention_days":7,"observed_at":240,"cursor":null,"next":null},"archive":""}"#;
    let seeds: [&[u8]; 2] = [page.as_bytes(), empty.as_bytes()];
    let mut random = crate::pages::dashboard::tests::XorShift(0x2545_f491_4f6c_dd1d);
    let query = Request { from_minute: 1, until_minute: 2, node: Some(7), before: None };
    let fresh = Window { query, ..Window::default() };
    let mut merged = 0;
    for _ in 0..100_000 {
        let input = random.mutate(&seeds);
        let Ok(value) = sibuna_json::parse(&input) else { continue };
        let Ok(reply) = Reply::decode(&value, Path::Root) else { continue };
        let mut window = fresh.clone();
        match window.accept(&reply) {
            Ok(()) => {
                merged += usize::from(window.archives == 1);
                assert!(window.archives <= 1 && window.summary.len() <= 256);
            }
            Err(_) => assert_eq!(window, fresh),
        }
    }
    assert!(merged > 100, "{merged}");
}

#[test]
fn keys_that_are_not_utf8_render_as_hex_paths_and_replaced_hosts() {
    let mut model = Model { open: true, started: true, ..Model::default() };
    let window = &mut model.windows[0];
    window.archives = 1;
    window.extended = 1;
    window.summary.add(b"\xff/x").unwrap();
    window.referrers.add(b"\xffhost").unwrap();
    window.families.status[15] = 2;
    let state = State::new();
    let mut text = String::new();
    render(&model, &state, &mut crate::render::Html::new(&mut text, 64 * 1024)).unwrap();
    assert!(text.contains("<code>hex:ff2f78</code>"));
    assert!(text.contains("<code>\u{fffd}host</code>"));
    assert!(text.contains("<tr><th scope=\"row\">429</th><td>2</td><td>Not available</td></tr>"));
    assert!(text.contains("<td>1\u{2013}1</td><td>Not available</td>"));
}
