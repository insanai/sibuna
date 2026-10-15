// Ports of peer_query_test.zig, and checks of the query session's answers.

use std::time::{Duration, Instant};

use sibuna_console_protocol::codec::{Decode, Path, to_json};
use sibuna_console_protocol::ranking_storage::Families;
use sibuna_console_protocol::rankings::{self, Encoding, Row};
use sibuna_console_protocol::timeline::{self, Bucket};
use sibuna_console_protocol::{StatsSnapshot, Text};

use super::query::{MAX_BODY, QueryError, Session, Wire, answer_text};
use super::serve::{INBOX_CAPACITY, Inbox, accept};
use super::*;

fn fixture() -> Peers {
    let targets = [PeerTarget { node: 2, origin: "https://peer.test".into() }];
    Peers::with_key(1, &targets, Some(ConsoleKey::new(auth::derive(&[7; 32]))))
}

/// Connects peer 2 with `boot` and makes it current at time 100.
fn connect(peers: &Peers, boot: [u8; 16], uptime: u64) -> Handle {
    let handle = peers.activate(0, boot).unwrap();
    let value = StatsSnapshot {
        node: 2,
        boot,
        outcomes_version: 1,
        uptime_ms: uptime,
        sample_probability: "1/64".into(),
        timestamp: 100,
        ..StatsSnapshot::default()
    };
    let update = Update { value: &value, watermark: uptime, sequence: uptime, received_at: 100 };
    assert_eq!(peers.publish(&handle, &update), Ok(true));
    handle
}

fn wire_id(text: &str) -> u64 {
    let value = sibuna_json::parse(text.as_bytes()).unwrap();
    Wire::decode(&value, Path::Root).unwrap().id
}

fn now() -> Instant {
    Instant::now()
}

// peer_query_test.zig: "peer queries own cursors and fence reconnects without recycling
// abandoned work".
#[test]
fn queries_own_cursors_and_fence_reconnects_without_recycling_abandoned_work() {
    let peers = fixture();
    let handle = connect(&peers, [1; 16], 1);
    let query = timeline::Query {
        before: Some(100),
        epoch: Some(1),
        boot: Some("a".repeat(32)),
        ..timeline::Query::default()
    };
    let cursor = Cursor::from_query(&query).unwrap();
    assert_eq!(cursor.limit, 8);
    let ticket = peers.submit(2, Kind::Timeline, cursor, 100).unwrap();
    let mut session = Session::new(&peers, handle, 2);
    let text = session.next().unwrap().unwrap();
    assert!(text.contains(&format!("\"boot\":\"{}\"", "a".repeat(32))), "{text}");
    assert_eq!(session.next(), Ok(None));
    session.overdue();
    assert_eq!(session.next(), Err(QueryError::Timeout));
    drop(ticket);
    drop(session);
    let old = peers.submit(2, Kind::Rankings, Cursor::default(), 100).unwrap();
    let reconnected = peers.activate(0, [2; 16]).unwrap();
    let mut session = Session::new(&peers, reconnected, 2);
    assert_eq!(session.next(), Ok(None));
    assert_eq!(old.wait(now(), || false), Some(Outcome::Failed(Status::Unavailable)));
    // Every abandoned or failed query returned its place: eight fit again.
    connect(&peers, [3; 16], 1);
    let tickets: Vec<Ticket> = (0..query::MAX_OUTSTANDING)
        .map(|_| peers.submit(2, Kind::Rankings, Cursor::default(), 100).unwrap())
        .collect();
    assert_eq!(
        peers.submit(2, Kind::Rankings, Cursor::default(), 100).err(),
        Some(StoreError::PeerUnavailable)
    );
    peers.stop();
    for ticket in &tickets {
        assert_eq!(ticket.wait(now(), || false), Some(Outcome::Failed(Status::Cancelled)));
    }
    let refused = peers.submit(2, Kind::Rankings, Cursor::default(), 100);
    assert_eq!(refused.err(), Some(StoreError::Stopping));
}

// peer_query_test.zig: "peer reader handoff is bounded and preserves FIFO ownership".
#[test]
fn reader_handoff_is_bounded_and_first_in_first_out() {
    let inbox = Inbox::default();
    let subscription = sibuna_json::parse(b"{\"op\":\"sub\",\"topic\":\"stats\"}").unwrap();
    assert_eq!(accept(&subscription), Ok(None));
    for id in 1..=INBOX_CAPACITY as u64 {
        let text = to_json(&Wire { id, kind: Kind::Rankings, cursor: Cursor::default() });
        let value = sibuna_json::parse(text.as_bytes()).unwrap();
        assert!(inbox.push(accept(&value).unwrap().unwrap()));
    }
    let full =
        sibuna_json::parse(b"{\"op\":\"peer_query\",\"id\":9,\"kind\":\"rankings\"}").unwrap();
    assert!(!inbox.push(accept(&full).unwrap().unwrap()));
    for id in 1..=INBOX_CAPACITY as u64 {
        assert_eq!(inbox.take().unwrap().id, id);
    }
    assert!(inbox.take().is_none());
    for invalid in [
        &b"{\"op\":\"peer_query\",\"id\":1,\"kind\":\"timeline\",\"cursor\":{\"limit\":9}}"[..],
        b"{\"op\":\"peer_query\",\"id\":0,\"kind\":\"timeline\"}",
        b"{\"op\":\"peer_query\",\"id\":1,\"kind\":\"audit\"}",
        b"{\"op\":\"peer_query\",\"id\":1,\"kind\":\"timeline\",\"extra\":1}",
    ] {
        let value = sibuna_json::parse(invalid).unwrap();
        assert_eq!(accept(&value), Err(QueryError::InvalidCursor));
    }
}

// peer_query_test.zig: "eight escaped ranking rows, eight referrers and full families fit
// the peer reply body".
#[test]
fn eight_escaped_rows_eight_referrers_and_full_families_fit_the_reply_body() {
    let label = "\u{1}".repeat(128);
    let row = Row {
        key: Text::new(&label).unwrap(),
        encoding: Encoding::Utf8,
        estimate: u64::MAX,
        error_bound: u64::MAX,
    };
    let referrer = Row { key: Text::new(&"\u{1}".repeat(24)).unwrap(), ..row.clone() };
    let families = Families { os: [u64::MAX; 8], browser: [u64::MAX; 8], ..Families::default() };
    let mut families = families;
    families.status.fill(u64::MAX);
    let page = rankings::Page {
        node: u32::MAX,
        boot: [255; 16],
        minute_start: u64::MAX,
        snapshot_at: u64::MAX,
        first_sample: Some(u64::MAX),
        last_sample: Some(u64::MAX),
        retained_samples: u64::MAX,
        truncated_records: u64::MAX,
        rejected_records: u64::MAX,
        queue_loss_since_boot: u64::MAX,
        missing_key_bound: u64::MAX,
        rows: vec![row; 8],
        referrer_missing_key_bound: u64::MAX,
        referrer_samples: u64::MAX,
        referrers: vec![referrer; 8],
        families,
        ..rankings::Page::default()
    };
    assert!(to_json(&page).len() < MAX_BODY);
}

// peer_query_test.zig: "peer reply identity cannot substitute another node or boot".
#[test]
fn an_answer_cannot_substitute_another_node_or_boot() {
    let peers = fixture();
    let handle = connect(&peers, [1; 16], 1);
    let ticket = peers.submit(2, Kind::Rankings, Cursor::default(), 100).unwrap();
    let mut session = Session::new(&peers, handle, 2);
    let id = wire_id(&session.next().unwrap().unwrap());
    for (node, boot) in [(3, [1; 16]), (2, [2; 16])] {
        let text = answer_text(id, node, &boot, Status::Unavailable, "");
        let value = sibuna_json::parse(text.as_bytes()).unwrap();
        assert_eq!(session.receive(&value), Err(QueryError::InvalidReply));
        assert_eq!(ticket.wait(now(), || false), None);
    }
    let other = answer_text(id + 1, 2, &[1; 16], Status::Unavailable, "");
    let value = sibuna_json::parse(other.as_bytes()).unwrap();
    assert_eq!(session.receive(&value), Err(QueryError::InvalidReply));
    let failed = answer_text(id, 2, &[1; 16], Status::Conflict, "");
    let value = sibuna_json::parse(failed.as_bytes()).unwrap();
    assert_eq!(session.receive(&value), Ok(true));
    assert_eq!(ticket.wait(now(), || false), Some(Outcome::Failed(Status::Conflict)));
    let value = sibuna_json::parse(failed.as_bytes()).unwrap();
    assert_eq!(session.receive(&value), Err(QueryError::UnexpectedReply));
    let other = sibuna_json::parse(b"{\"op\":\"delta\"}").unwrap();
    assert_eq!(session.receive(&other), Ok(false));
}

#[test]
fn a_valid_timeline_page_is_delivered_and_a_foreign_one_refused() {
    let peers = fixture();
    let boot = [1; 16];
    let handle = connect(&peers, boot, 1);
    let page = timeline::Page {
        version: 1,
        node: 2,
        boot: sibuna_encoding::hex::encode(&boot),
        rows: vec![Bucket { sequence: 4, ..Bucket::default() }; 2],
        ..timeline::Page::default()
    };
    for (page, expected) in [
        (timeline::Page { node: 3, ..page.clone() }, None),
        (timeline::Page { rows: vec![Bucket::default(); 9], ..page.clone() }, None),
        (page.clone(), Some(to_json(&page))),
    ] {
        let ticket = peers.submit(2, Kind::Timeline, Cursor::default(), 100).unwrap();
        let mut session = Session::new(&peers, handle, 2);
        let id = wire_id(&session.next().unwrap().unwrap());
        let text = answer_text(id, 2, &boot, Status::Ok, &to_json(&page));
        assert!(text.len() < 4096);
        let value = sibuna_json::parse(text.as_bytes()).unwrap();
        match expected {
            Some(json) => {
                assert_eq!(session.receive(&value), Ok(true));
                assert_eq!(ticket.wait(now(), || false), Some(Outcome::Page(json)));
            }
            None => {
                assert_eq!(session.receive(&value), Err(QueryError::InvalidReply));
                drop(session);
                let outcome = ticket.wait(now() + Duration::from_secs(1), || false);
                assert_eq!(outcome, Some(Outcome::Failed(Status::Unavailable)));
            }
        }
    }
}

#[test]
fn cursors_are_complete_or_empty_and_queries_need_a_current_peer() {
    let incomplete = timeline::Query { before: Some(1), ..timeline::Query::default() };
    assert_eq!(Cursor::from_query(&incomplete), Err(QueryError::InvalidCursor));
    let short_boot = timeline::Query {
        before: Some(1),
        epoch: Some(1),
        boot: Some("ab".into()),
        ..timeline::Query::default()
    };
    assert_eq!(Cursor::from_query(&short_boot), Err(QueryError::InvalidCursor));
    let none = timeline::Query { limit: 0, ..timeline::Query::default() };
    assert_eq!(Cursor::from_query(&none), Err(QueryError::InvalidCursor));
    let peers = fixture();
    let unobserved = peers.submit(2, Kind::Rankings, Cursor::default(), 100);
    assert_eq!(unobserved.err(), Some(StoreError::PeerUnavailable));
    connect(&peers, [1; 16], 1);
    let stale = peers.submit(2, Kind::Rankings, Cursor::default(), 110);
    assert_eq!(stale.err(), Some(StoreError::PeerUnavailable));
    let unknown = peers.submit(5, Kind::Rankings, Cursor::default(), 100);
    assert_eq!(unknown.err(), Some(StoreError::UnknownPeer));
    let wire = Wire { id: 3, kind: Kind::Timeline, cursor: Cursor::default() };
    let text = to_json(&wire);
    assert_eq!(
        text,
        "{\"op\":\"peer_query\",\"id\":3,\"kind\":\"timeline\",\
         \"cursor\":{\"before\":null,\"epoch\":null,\"boot\":null,\"limit\":8}}"
    );
}
