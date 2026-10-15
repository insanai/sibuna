//! Byte-for-byte agreement with the Zig console.
//!
//! `golden/zig-0.16.txt` was produced by Zig 0.16 from `libs/console-protocol` (the program
//! is described in the crate documentation): one vector per line, a name, a tab, and the
//! JSON Zig wrote. Each test builds the same value in Rust, checks that it encodes to the
//! same bytes, and that decoding Zig's bytes gives the value back.

// Test code: a failed expectation is a panic by design.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::OnceLock;

use sibuna_console_protocol::codec::{Decode, Encode, from_json, to_json};
use sibuna_console_protocol::events::country::{Mapping, Wire};
use sibuna_console_protocol::*;

const BIG: u64 = 9_007_199_254_740_993;
const MAX: u64 = u64::MAX;

fn golden() -> &'static HashMap<&'static str, Vec<&'static str>> {
    static GOLDEN: OnceLock<HashMap<&'static str, Vec<&'static str>>> = OnceLock::new();
    GOLDEN.get_or_init(|| {
        include_str!("golden/zig-0.16.txt")
            .lines()
            .filter_map(|line| {
                let mut parts = line.split('\t');
                Some((parts.next()?, parts.collect()))
            })
            .collect()
    })
}

fn zig(name: &str) -> &'static str {
    golden()
        .get(name)
        .and_then(|parts| parts.first())
        .unwrap_or_else(|| panic!("no vector {name}"))
}

/// Checks that `value` encodes to Zig's bytes and that Zig's bytes decode to `value`.
fn check<T: Encode + Decode + PartialEq + Debug>(name: &str, value: &T) {
    let expected = zig(name);
    assert_eq!(to_json(value), expected, "encoding of {name}");
    assert_eq!(&from_json::<T>(expected.as_bytes()).unwrap(), value, "decoding of {name}");
}

fn text<const N: usize>(value: &str) -> Text<N> {
    Text::new(value).unwrap()
}

fn token_row(id: u64, expires: Option<u64>) -> tokens::Row {
    tokens::Row {
        id,
        revision: BIG,
        label: text("ci \"x\" \u{1} caf\u{e9}"),
        role: Role::Operator,
        scopes: tokens::Scope::StatsRead.bit() | tokens::Scope::PolicyWrite.bit(),
        created_by: 1,
        created_at: 100,
        expires,
        disabled: false,
        active: true,
    }
}

#[test]
fn counters() {
    let mut out = String::new();
    codec::counter(&mut sibuna_json::Writer::new(&mut out), BIG).unwrap();
    assert_eq!(out, zig("counter_big"));
}

#[test]
fn accounts() {
    let page =
        tokens::Page { rows: vec![token_row(3, None), token_row(4, Some(MAX))], next: Some(9) };
    check("tokens_page", &page);
    let users = users::Page {
        rows: vec![users::Row {
            id: 1,
            username: text("admin"),
            role: Role::Admin,
            revision: 2,
            must_change: true,
            password_expires: BIG,
            last_login: Some(77),
            ..users::Row::default()
        }],
        next: None,
    };
    check("users_page", &users);
    let row = audit::Row {
        id: 5,
        actor: 1,
        subject: MAX,
        recorded_at: 1_700_000_000,
        action: text("policy.edit"),
        target: Some(text("rule-1")),
        actor_role: Some(Role::Operator),
        client_ip: Some(text("2001:db8::1")),
    };
    let login = audit::Row { id: 4, action: text("login"), ..audit::Row::default() };
    check("audit_page", &audit::Page { rows: vec![row.clone(), login], next: Some(BIG) });
    let detail = audit::Detail {
        row,
        before: Some(text("{\"a\":1}")),
        after: None,
        before_truncated: true,
        after_redacted: true,
        ..audit::Detail::default()
    };
    check("audit_detail", &detail);
}

fn mapping() -> Mapping {
    let generation = "ab".repeat(32);
    Mapping::from_wire(Wire { code: Some("US"), generation: Some(&generation), ..Wire::default() })
        .unwrap()
}

#[test]
fn incidents() {
    let row = events::Row {
        geography: mapping(),
        capture: Some(events::Capture {
            version: 1,
            selected_status: 403,
            query_bytes: 10,
            body_bytes: 20,
            declared_body_bytes: 30,
            truncated: 1,
        }),
        id: BIG,
        grouped: true,
        count: 3,
        first_seen: 50,
        node: 2,
        time: 100,
        ip: text("192.0.2.1"),
        method: text("GET"),
        path: text("/a?b=\"c\"\\d"),
        category: text("waf:sqli"),
        user_agent: text("Mozilla/5.0 \u{e9}\u{4e16}"),
        campaign: Some(7),
        display_truncated: false,
        query_redacted: false,
    };
    check("events_row", &row);
    check("events_row_plain", &events::Row { id: 1, ip: text("::1"), ..events::Row::default() });
    check("country_mapping", &mapping());
    check("country_mapping_empty", &Mapping::default());
    let event = subscription_feed::Event {
        geography: mapping(),
        id: BIG,
        node: 3,
        time: 99,
        ip: text("198.51.100.7"),
        method: text("POST"),
        path: text("/login"),
        category: text("honeypot"),
        display_truncated: true,
        query_redacted: false,
    };
    check("feed_event", &event);
    let heads = incident_heads::Heads {
        id: BIG,
        recorded: true,
        request: text("474554202f20485454502f312e310d0a"),
        response: text("48545450"),
        response_truncated: true,
        response_state: incident_heads::ResponseState::Unobserved,
        ..incident_heads::Heads::default()
    };
    check("incident_heads", &heads);
}

#[test]
fn security_pages() {
    let mut page = security::Page {
        request: security::Request {
            view: security::View::Categories,
            node: 1,
            from: 0,
            until: 60,
        },
        observed_at: 9,
        total: BIG,
        ..security::Page::default()
    };
    page.modules[1].total = 3;
    page.modules[1].trend[59] = MAX;
    page.modules[1].sources[0] =
        Some(security::Rank { label: text("honeypot"), count: 3, truncated: false });
    page.rows[0] =
        Some(security::Rank { label: text("/wp-login.php"), count: 2, truncated: true });
    check("security_page", &page);
    check(
        "security_request",
        &security::Request { from: 5, until: 10, ..security::Request::default() },
    );
}

#[test]
fn cluster() {
    check("nodes_summary", &nodes::Summary { healthy: 2, degraded: 1, down: 0, unknown: 3 });
    let page = nodes::Page {
        self_node: 1,
        committed: BIG,
        storage: nodes::Storage {
            role: nodes::Role::Leader,
            leader: Some(1),
            term: 3,
            decided: 9,
            applied: 8,
            durable: 7,
            quorum: true,
            observed_at: 100,
        },
        members: vec![
            nodes::Member {
                node: 1,
                address: text("10.0.0.1:7000"),
                console_url: text("https://console.example:9443"),
                version: text("0.2.0"),
                boot: text("00112233445566778899aabbccddeeff"),
                first_seen: 1,
                last_seen: 2,
                applied_revision: 3,
                control_revision: 4,
                draining: true,
            },
            nodes::Member { node: 2, ..nodes::Member::default() },
        ],
    };
    // SID 0013 (review of 2026-10-15) drops the Zaxonlite log frontiers `applied_slot` and
    // `decided_slot` from the member row; the rest of Zig's bytes are unchanged.
    let expected = zig("nodes_page")
        .replace(",\"applied_slot\":\"18446744073709551615\",\"decided_slot\":6", "")
        .replace(",\"applied_slot\":0,\"decided_slot\":0", "");
    assert_eq!(to_json(&page), expected, "encoding of nodes_page");
    assert_eq!(from_json::<nodes::Page>(expected.as_bytes()).unwrap(), page);
    assert!(from_json::<nodes::Page>(zig("nodes_page").as_bytes()).is_err());
    let probe = nodes::Probe {
        node: 2,
        health: nodes::Health::Degraded,
        latency_ms: 12,
        last_seen: 5,
        observed_at: 6,
        draining: false,
        requests: BIG,
    };
    check("nodes_probe", &probe);
    let peer = nodes::Peer {
        node: 3,
        status: nodes::PeerStatus::Current,
        boot: Some(text("ffeeddccbbaa99887766554433221100")),
        age_seconds: Some(1),
        clock_skew_seconds: None,
        sequence: 10,
        watermark: 11,
        resets: 1,
        requests: Some(BIG),
        sample_loss: Some(0),
        geoip_available: true,
        rss_kib: Some(20480),
        cpu_permille: Some(15),
    };
    check("nodes_peer", &peer);
    check("nodes_peer_empty", &nodes::Peer { node: 4, ..nodes::Peer::default() });
}

#[test]
fn node_commands() {
    let status = nodes::Status {
        operation_id: text("0123456789abcdef0123456789abcdef"),
        node: 1,
        boot: text("00112233445566778899aabbccddeeff"),
        control_revision: 2,
        connections: 10,
        active_ban_entries: 3,
        committed: 4,
        applied: 4,
        observed_at: 100,
        uptime_ms: BIG,
        completion_pending: true,
        ..nodes::Status::default()
    };
    check("nodes_status", &status);
    let receipt = nodes::Receipt {
        id: text("0123456789abcdef0123456789abcdef"),
        boot: text("00112233445566778899aabbccddeeff"),
        node: 1,
        kind: nodes::Kind::ClearLocalBans,
        state: nodes::State::Applied,
        expected_revision: 2,
        applied_revision: Some(3),
        cleared_entries: Some(17),
        requested_at: 100,
        completed_at: Some(101),
        completion_persisted: true,
    };
    check("nodes_receipt", &receipt);
}

#[test]
fn notifications() {
    let settings = notifications::SettingsPage {
        rows: vec![notifications::Setting {
            key: text("retention.audit"),
            value: text("30"),
            revision: 2,
            updated_at: 100,
            updated_by: BIG,
        }],
    };
    check("settings_page", &settings);
    let page = notifications::Page {
        rows: vec![notifications::Destination {
            id: 1,
            revision: 2,
            kind: notifications::Kind::Syslog,
            transport: notifications::Transport::Tcp,
            label: text("ops"),
            target: text("syslog.example:514"),
            target_host: text("syslog.example"),
            secret_set: false,
            events: 15,
            cooldown_seconds: 60,
            enabled: true,
            last_attempt_at: Some(1_700_000_000),
            last_outcome: Some(notifications::Outcome::Failed),
            last_detail: text("timeout"),
        }],
        next: Some(4),
    };
    check("notifications_page", &page);
}

fn record(minute: u64) -> minutes::Record {
    minutes::Record {
        node: 1,
        boot: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 255],
        epoch: 2,
        minute,
        utc_start: minute * 60 - 60,
        utc_end: minute * 60,
        start_ms: minute * 60_000 - 60_000,
        end_ms: minute * 60_000,
        observed_ms: 60_000,
        observations: 240,
        sealed: true,
        complete: true,
        gap: false,
        counts: timeline::Counts {
            admitted: BIG,
            denied: 3,
            origin_5xx: 1,
            ..timeline::Counts::default()
        },
        rss_last_kib: Some(100),
        rss_max_kib: Some(BIG),
        cpu_ms: None,
    }
}

#[test]
fn minute_history() {
    let rows = vec![record(11), record(10)];
    let reply = minutes::Reply {
        from_minute: 10,
        until_minute: 11,
        observed_at: 720,
        next: Some(rows[1].cursor()),
        rows: rows.clone(),
        ..minutes::Reply::default()
    };
    check("minutes_reply", &reply);
    let request = minutes::Request {
        from_minute: Some(10),
        node: Some(2),
        before: Some(rows[0].cursor()),
        ..minutes::Request::default()
    };
    check("minutes_request", &request);
    let status = minutes::Status {
        available: true,
        pending: 2,
        saved_snapshots: BIG,
        last_saved_end_ms: 5,
        ..minutes::Status::default()
    };
    check("minutes_status", &status);
    let mut window = minute_summary::Window {
        node: 1,
        from: 10,
        until: 11,
        retention_days: Some(90),
        ..minute_summary::Window::default()
    };
    window.add(&rows[0]).unwrap();
    window.next = window.last;
    let part = minute_summary::Part {
        version: 1,
        observed_at: 720,
        first: Some(rows[0].cursor()),
        window,
    };
    check("minute_summary_part", &part);
}

#[test]
fn live_timeline() {
    let rows = vec![
        timeline::Bucket {
            sequence: 5,
            utc_start: 1,
            utc_end: 2,
            start_ms: 3,
            end_ms: 4,
            observed_ms: 1,
            observations: 4,
            gap: true,
            partial: false,
            counts: timeline::Counts { challenged: MAX, ..timeline::Counts::default() },
        },
        timeline::Bucket { sequence: 4, partial: true, ..timeline::Bucket::default() },
    ];
    let page = timeline::Page {
        version: 1,
        node: 1,
        boot: "00112233445566778899aabbccddeeff".into(),
        epoch: 3,
        retention_seconds: timeline::CAPACITY,
        as_of_ms: BIG,
        discarded_intervals: 2,
        oldest_sequence: Some(1),
        next_before: None,
        rows,
    };
    check("timeline_page", &page);
    let query = timeline::Query {
        node: Some(1),
        before: Some(99),
        boot: Some("aa".into()),
        ..timeline::Query::default()
    };
    check("timeline_query", &query);
}

#[test]
fn challenge_pages() {
    let mut snapshot = challenges::Snapshot {
        timestamp: 100,
        last_issued: Some(challenges::Defaults {
            algorithm: challenges::Algorithm::Posw,
            difficulty: 20,
            parameter: 13,
            openings: 16,
        }),
        issued: BIG,
        submitted: 5,
        accepted: 4,
        rejected: 1,
        selected: 13,
        missing: 1,
        wasm: 3,
        javascript: 1,
        ..challenges::Snapshot::default()
    };
    snapshot.causes[2] = 1;
    snapshot.bin_accepted[13] = 4;
    snapshot.bin_accepted[255] = MAX;
    snapshot.buckets[0] = 3;
    check("challenges_snapshot", &snapshot);
    let cursor = record(5).cursor();
    let summary = challenge_minutes::Summary {
        version: 1,
        coverage: challenge_minutes::Coverage {
            node: Some(1),
            from: 1,
            until: 9,
            rows: 2,
            complete_rows: 1,
            observed_ms: BIG,
            bins_dropped: 1,
            first: Some(cursor),
            last: Some(cursor),
            next: None,
            finished: true,
            retention_days: 90,
            retention_changed: false,
        },
        totals: snapshot,
    };
    check("challenge_summary", &summary);
}

#[test]
fn challenge_record_pages() {
    let page = challenge_records::Page {
        observed_at: 9,
        from: 1,
        until: 9,
        dropped_since_boot: BIG,
        next: Some(challenge_records::Cursor { second: 5, id: MAX }),
        rows: vec![
            challenge_records::Row {
                id: 1,
                node: 2,
                second: 3,
                ip: text("::1"),
                outcome: challenge_records::Outcome::Rejected,
                cause: 2,
                algorithm: 1,
                parameter: 13,
                openings: 16,
                duration_ms: Some(40),
            },
            challenge_records::Row {
                id: 2,
                node: 2,
                second: 3,
                ip: text("10.0.0.2"),
                outcome: challenge_records::Outcome::Issued,
                cause: 255,
                algorithm: 0,
                parameter: 16,
                openings: 0,
                duration_ms: None,
            },
        ],
        ..challenge_records::Page::default()
    };
    check("challenge_records_page", &page);
    let difficulty = challenge_records::DifficultyPage {
        observed_at: 9,
        from: 1,
        until: 9,
        current_bits: Some(3),
        missed_since_boot: 1,
        truncated: true,
        rows: vec![challenge_records::TransitionRow {
            node: 1,
            second: 2,
            previous_bits: 0,
            bits: 3,
            rate_256: BIG,
        }],
        ..challenge_records::DifficultyPage::default()
    };
    check("challenge_difficulty_page", &difficulty);
}

fn span(minute: u64) -> rule_hits::Span {
    rule_hits::Span {
        node: 7,
        boot: [1; 16],
        generation: 1,
        revision: 1,
        sequence: minute,
        minute,
        utc_start: minute * 60 - 1,
        utc_end: minute * 60 + 59,
        start_ms: minute * 60_000 - 1000,
        end_ms: minute * 60_000 + 59_000,
        observed_ms: 60_000,
        observations: 60,
        complete: true,
        gap: false,
        unconfirmed: 2,
    }
}

#[test]
fn rule_history() {
    let request = rule_hit_history::Request {
        key: text("m:rule"),
        node: 7,
        from_minute: 2,
        until_minute: 3,
        revision: Some(1),
        before: Some(rule_hit_history::Cursor { minute: 4, boot: [2; 16], sequence: 9 }),
    };
    let mut window = rule_hit_history::Window::new(request);
    window.retention_days = Some(90);
    window.add(&rule_hit_history::Row { span: span(3), hits: Some(BIG) }).unwrap();
    window.add(&rule_hit_history::Row { span: span(2), hits: None }).unwrap();
    window.next = window.last;
    check("rule_hit_part", &rule_hit_history::Part { version: 1, observed_at: 300, window });
    let mut today = rule_hit_history::Today {
        hits: Some(MAX),
        rows: 2,
        complete: 1,
        observed_at: 3,
        from_minute: 4,
        partial: true,
        unconfirmed: 5,
        ..rule_hit_history::Today::default()
    };
    today.hours[0] = Some(MAX);
    today.hours[23] = Some(7);
    check("rule_hit_today", &today);
}

#[test]
fn ranking_pages() {
    let rows = vec![
        rankings::Row {
            key: text("/index.html"),
            encoding: rankings::Encoding::Utf8,
            estimate: 10,
            error_bound: 1,
        },
        rankings::Row {
            key: text("ff00"),
            encoding: rankings::Encoding::Hex,
            estimate: BIG,
            error_bound: 0,
        },
    ];
    let mut families = ranking_storage::Families::default();
    families.os[1] = 5;
    families.status[21] = MAX;
    let mut page = rankings::Page {
        node: 1,
        boot: *b"0123456789abcdef",
        archive: rankings::ArchiveStatus {
            stored: rankings::Inventory {
                available: true,
                archives: 2,
                first_minute: Some(1),
                last_minute: None,
                reserved_bytes: 9,
                observed_at: 4,
            },
            pending: 1,
            saved_since_boot: 2,
            last_saved_minute: Some(BIG),
            ..rankings::ArchiveStatus::default()
        },
        minute_start: 60,
        snapshot_at: 61,
        first_sample: Some(60),
        last_sample: None,
        retained_samples: 11,
        rejected_records: 1,
        queue_loss_since_boot: 2,
        referrer_samples: 3,
        referrers: rows[..1].to_vec(),
        rows,
        families,
        ..rankings::Page::default()
    };
    check("rankings_page", &page);
    page.boot = [0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
    page.rows = Vec::new();
    check("rankings_page_binary_boot", &page);
    let cursor = ranking_history::Cursor { minute: BIG, digest: text(&"ab".repeat(32)) };
    check("ranking_cursor", &cursor);
    let form = ranking_history::Form {
        from_minute: 1,
        until_minute: 2,
        node: None,
        before: Some(ranking_history::Cursor { minute: 2, digest: text(&"cd".repeat(32)) }),
    };
    check("ranking_form", &form);
}

fn stats_snapshot() -> StatsSnapshot {
    let mut value = StatsSnapshot {
        proxy_mode: Some(ProxyMode::ReverseProxy),
        server_location: Some(Location { lat: 1.3521, lon: 103.8198 }),
        incident_geo: Some(incident_geo::Snapshot {
            started_at: 1,
            other: 2,
            unknown: 3,
            dropped: BIG,
            ..incident_geo::Snapshot::default()
        }),
        minute_history: minutes::Status {
            available: true,
            saved_snapshots: 4,
            ..minutes::Status::default()
        },
        outcomes_version: 1,
        node: 2,
        boot: [0x41, 0x42, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
        uptime_ms: 5000,
        requests: BIG,
        admitted: 10,
        challenged: 2,
        denied: 1,
        banned: 1,
        origin_4xx: 3,
        incidents: 4,
        sample_loss: 1,
        retention_failures: Some(0),
        active_bans: Some(BIG),
        cluster_health: Some(nodes::Summary { healthy: 1, ..nodes::Summary::default() }),
        rss_kib: Some(20480),
        cpu_permille: Some(12),
        geoip_available: true,
        unknown_samples: 2,
        timestamp: 1_700_000_000,
        ..StatsSnapshot::default()
    };
    value.countries[0] = CountryCount { code: 0x5553, samples: 7 };
    value.countries[1] = CountryCount { code: 0x4445, samples: MAX };
    if let Some(geo) = value.incident_geo.as_mut() {
        geo.countries[0] = CountryCount { code: 0x4652, samples: 1 };
    }
    value
}

#[test]
fn dashboard_views() {
    let value = stats_snapshot();
    check("stats_snapshot", &value);
    assert_eq!(StatsSnapshot::from_json(zig("stats_snapshot").as_bytes()), Ok(value.clone()));
    check(
        "stats_snapshot_zero",
        &StatsSnapshot { sample_probability: String::new(), ..StatsSnapshot::default() },
    );
    let mut scope = dashboard::Scope {
        available: true,
        history_available: true,
        count: 2,
        contributing: 1,
        request_rate: Some(2.5),
        outcome_rates: Some(dashboard::Rates {
            requests: 0.1,
            admitted: 1234.5,
            challenged: 1e-7,
            denied: 2.0 / 3.0,
            banned: 1e21,
            rate_limited: 123_456_789.0,
            ..dashboard::Rates::default()
        }),
        traffic_uncertainty: BIG,
        ..dashboard::Scope::default()
    };
    scope.sources[0] = Some(dashboard::Source {
        status: nodes::PeerStatus::Current,
        age_seconds: Some(1),
        window_end: Some(1_700_000_000),
        resets: 2,
        contributing: true,
        geoip_available: true,
        proxy_mode: Some(ProxyMode::ForwardAuth),
        location: Some(Location { lat: -33.8688, lon: 151.2093 }),
        ..dashboard::Source::new(1)
    });
    scope.sources[1] = Some(dashboard::Source::new(2));
    scope.traffic_flows[0] = Some(dashboard::Flow { node: 1, country: 0x5553, samples: 9 });
    check("dashboard_view", &dashboard::View { scope, value: Some(value.clone()) });
    check("dashboard_view_empty", &dashboard::View::default());
    let mut next = value.clone();
    next.timestamp += 1;
    next.uptime_ms += 1000;
    next.requests += 7;
    next.admitted += 3;
    check("interval_rates", &dashboard::interval_rates(&value, &next).unwrap());
}

#[test]
fn subscription_commands() {
    let command = subscriptions::Command {
        op: subscriptions::Op::Filter,
        topic: Some(Topic::Events),
        args: subscriptions::Args {
            node: Some(2),
            module: Some(security::Module::Inspection),
            category: text("waf:sqli"),
            country: text("US"),
            ip: text("192.0.2.1"),
            path_prefix: text("/api"),
            ..subscriptions::Args::default()
        },
    };
    assert_eq!(to_json(&command), zig("command_filter"));
    assert_eq!(subscriptions::parse(zig("command_filter").as_bytes()), Ok(command));
    let ping = subscriptions::Command {
        op: subscriptions::Op::Ping,
        ..subscriptions::Command::default()
    };
    assert_eq!(to_json(&ping), zig("command_ping"));
    assert_eq!(subscriptions::parse(zig("command_ping").as_bytes()), Ok(ping));
}

#[test]
fn deltas_and_patched_views() {
    let pairs = [
        (
            "delta_counters",
            "{\"count\":\"9007199254740993\",\"rows\":[1],\"old\":true}",
            "{\"count\":\"9007199254740994\",\"rows\":[1],\"empty\":null}",
        ),
        ("delta_order", "{\"a\":1,\"b\":2,\"c\":3,\"d\":4}", "{\"b\":2,\"c\":30,\"d\":4,\"e\":5}"),
        (
            "delta_floats",
            "{\"x\":1.50,\"y\":1,\"z\":0.1,\"w\":-0}",
            "{\"x\":1.5,\"y\":1.0,\"z\":1e300,\"w\":-0.0,\"v\":5e-324,\
             \"u\":1.7976931348623157e308,\"t\":1e400,\"s\":123456789012345678901234567890}",
        ),
        (
            "delta_nested",
            "{\"a\":{\"x\":[1,{\"y\":null}],\"z\":\"\\u00e9\"},\"b\":[1,2]}",
            "{\"b\":[1,2,3],\"a\":{\"z\":\"\\u00e9\",\"x\":[1,{\"y\":null}]}}",
        ),
        (
            "delta_floats2",
            "{}",
            "{\"a\":0.30000000000000004,\"b\":1e21,\"c\":1e22,\"d\":1.5e-7,\"e\":2.5e-308,\
             \"f\":12345.678e3,\"g\":-1E-2}",
        ),
    ];
    for (name, previous, current) in pairs {
        let mut out = String::new();
        let changed =
            json_delta::write(previous.as_bytes(), current.as_bytes(), &mut out).unwrap();
        let expected = &golden()[name];
        assert_eq!(out, expected[0], "{name}");
        assert_eq!(changed.to_string(), expected[1], "{name}");
        let state = sibuna_json::parse(previous.as_bytes()).unwrap();
        let delta = sibuna_json::parse(out.as_bytes()).unwrap();
        let mut applied = String::new();
        json_delta::apply(&state, &delta, &mut applied).unwrap();
        assert_eq!(applied, zig(&format!("{name}_applied")), "{name} applied");
    }
}

#[test]
fn ranking_archives() {
    let mut archive = rankings_archive::Archive {
        identity: rankings_archive::Identity {
            node: 7,
            boot: [9; 16],
            queue_loss_start: 4,
            queue_loss_end: 6,
        },
        minute: ranking_storage::Minute {
            minute: Some(2),
            first_second: 120,
            last_second: 179,
            ..Default::default()
        },
    };
    archive.minute.paths.add(b"/a").unwrap();
    archive.minute.paths.add(b"/b").unwrap();
    archive.minute.paths.add(b"/a").unwrap();
    archive.minute.referrers.add(b"example.com").unwrap();
    archive.minute.families.os[1] = 3;
    archive.minute.families.status[0] = 3;
    let encoded = rankings_archive::encode(&archive).unwrap();
    let hex: String = encoded.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(hex, zig("archive_hex"));
    assert_eq!(rankings_archive::decode(&encoded), Ok(archive));
}
