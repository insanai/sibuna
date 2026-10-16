//! Incident reads of the Events page: filters, paging, the search language with the same
//! matches on both backends, the work bound, the sidecars of the detail, the similarity
//! scan, and audited exports (S39).

use std::collections::BTreeSet;

use sibuna_console_protocol::events::{Cursor, Query};
use sibuna_console_protocol::incident_heads::{self, ResponseState};
use sibuna_console_protocol::security::Module;
use sibuna_console_protocol::{Text, similarity};
use sibuna_console_storage::events::{self, EventPage, heads, similar};
use sibuna_console_storage::{ConsoleStorageError, Credential};
use sibuna_storage::search::{self, Field, Term};
use sibuna_storage::{Dialect, Param, Sql, Transaction, WorkBound};

use crate::common::{NOW, audit_actions, bootstrap_admin, for_each_backend, sign_in};

/// One stored incident, as tests describe it.
#[derive(Clone, Debug)]
pub(crate) struct Stored {
    pub sequence: u64,
    pub node: u32,
    pub ip: &'static str,
    pub path: Vec<u8>,
    pub category: &'static str,
    pub payload: Vec<u8>,
    pub user_agent: Vec<u8>,
    pub ja4: Option<&'static str>,
    pub time: u64,
    pub campaign: i64,
    pub embedding: [u8; 256],
}

impl Stored {
    pub fn new(sequence: u64, time: u64) -> Stored {
        Stored {
            sequence,
            node: 1,
            ip: "198.51.100.7",
            path: b"/login".to_vec(),
            category: "waf:sqli",
            payload: Vec::new(),
            user_agent: b"curl/8".to_vec(),
            ja4: None,
            time,
            campaign: 1,
            embedding: [0; 256],
        }
    }

    /// The incident id, `(node << 40) | sequence`.
    pub fn id(&self) -> u64 {
        (u64::from(self.node) << 40) | self.sequence
    }
}

const RECEIPT: Sql = Sql::both(
    "INSERT INTO incident_receipts (node_id, next_sequence) VALUES ($1, 1099511627776) \
     ON CONFLICT (node_id) DO NOTHING",
);
const INCIDENT: Sql = Sql {
    sqlite: "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, path, \
             violation_category, offending_payload, campaign_id, recorded_at, embedding, ja4) \
             VALUES ($1, $2, $3, $4, 'GET', $5, $6, $7, $8, $9, $10, $11)",
    postgres: "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, \
               path, violation_category, offending_payload, campaign_id, recorded_at, \
               embedding, ja4, search) \
               VALUES ($1, $2, $3, $4, 'GET', $5, $6, $7, $8, $9, $10, $11, \
               CAST($12 AS tsvector))",
};
const FTS: Sql =
    Sql::both("INSERT INTO incidents_fts (rowid, path, offending_payload) VALUES ($1, $2, $3)");

/// Stores `incident` with its search index exactly as the core's incident writer does.
pub(crate) async fn store(tx: &mut Transaction, incident: &Stored) {
    tx.execute(RECEIPT, &[i64::from(incident.node).into()]).await.expect("receipt");
    let path_tokens = search::index_tokens(&incident.path);
    let payload_tokens = search::index_tokens(&incident.payload);
    let vector = search::tsvector_literal(&path_tokens, &payload_tokens);
    let id = i64::try_from(incident.id()).expect("id");
    let params: [Param<'_>; 12] = [
        id.into(),
        i64::from(incident.node).into(),
        incident.ip.into(),
        incident.user_agent.as_slice().into(),
        incident.path.as_slice().into(),
        incident.category.into(),
        incident.payload.as_slice().into(),
        incident.campaign.into(),
        i64::try_from(incident.time).expect("time").into(),
        incident.embedding.as_slice().into(),
        incident.ja4.into(),
        vector.as_str().into(),
    ];
    let bound = if tx.dialect() == Dialect::Sqlite { &params[..11] } else { &params[..] };
    tx.execute(INCIDENT, bound).await.expect("incident");
    if tx.dialect() == Dialect::Sqlite {
        let path = search::fts_text(&path_tokens);
        let payload = search::fts_text(&payload_tokens);
        let fts: [Param<'_>; 3] = [id.into(), path.as_str().into(), payload.as_str().into()];
        tx.execute(FTS, &fts).await.expect("fts");
    }
}

/// Bootstraps the administrator and returns its cookie credential.
pub(crate) async fn admin(tx: &mut Transaction) -> Credential {
    let admin = bootstrap_admin(tx).await;
    sign_in(tx, admin, 1, 10).await
}

async fn page(tx: &mut Transaction, admin: &Credential, input: &Query, find: &str) -> EventPage {
    let input = searching(input, find);
    events::query_events(tx, admin, &input, WorkBound::default(), NOW).await.expect("page")
}

/// Returns `input` with the search text `find`.
fn searching(input: &Query, find: &str) -> Query {
    Query { search: Text::new(find).expect("search text"), ..input.clone() }
}

/// Reads every page of `input` and returns the ids in page order.
async fn all_ids(tx: &mut Transaction, admin: &Credential, input: &Query, find: &str) -> Vec<u64> {
    let mut input = input.clone();
    let mut ids = Vec::new();
    loop {
        let page = page(tx, admin, &input, find).await;
        ids.extend(page.rows.iter().map(|row| row.id));
        match page.next {
            Some(next) => input.before = Some(next),
            None => return ids,
        }
    }
}

// Port of console_store_test.zig "incident pages bound bytes, paginate tied timestamps and
// redact historical queries".
#[test]
fn incident_pages_bound_bytes_paginate_tied_timestamps_and_redact_queries() {
    for_each_backend("events_pages", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = admin(&mut tx).await;
        for sequence in 1..=30u64 {
            let incident = Stored {
                path: b"/attack?token=secret-marker".to_vec(),
                payload: b"secret-marker".to_vec(),
                user_agent: b"<script>".to_vec(),
                category: "attack",
                ..Stored::new(sequence, 200 + sequence % 2)
            };
            store(&mut tx, &incident).await;
        }
        let mut input = Query::default();
        let mut seen = BTreeSet::new();
        loop {
            let page = page(&mut tx, &admin, &input, "").await;
            let json = page.to_json();
            assert!(json.len() <= sibuna_console_protocol::MAX_MESSAGE);
            assert!(!json.contains("secret-marker"));
            assert!(!page.rows.is_empty() && page.rows.len() <= usize::from(input.limit));
            for row in &page.rows {
                assert!(seen.insert(row.id), "a row repeats");
                assert!(row.query_redacted && row.capture.is_none());
                assert!(!row.geography.recorded);
            }
            match page.next {
                Some(next) => input.before = Some(next),
                None => break,
            }
        }
        assert_eq!(seen.len(), 30);
        let input = Query { category: Text::new("attack' OR 1=1 --").expect("text"), ..input };
        let empty = page(&mut tx, &admin, &Query { before: None, ..input.clone() }, "").await;
        assert_eq!(empty.to_json(), "{\"rows\":[],\"next\":null}");
        tx.execute(Sql::both("DELETE FROM console_sessions"), &[]).await.expect("sign out");
        let refused =
            events::query_events(&mut tx, &admin, &input, WorkBound::default(), NOW).await;
        assert!(matches!(refused, Err(ConsoleStorageError::Unauthorized)));
    });
}

// Port of console_store_test.zig "source groups report exact filtered counts and audit
// bounded export preparation".
#[test]
fn source_groups_count_exactly_and_exports_are_audited_first() {
    for_each_backend("events_groups", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = admin(&mut tx).await;
        for sequence in 1..=30u64 {
            store(&mut tx, &Stored::new(sequence, 200 + sequence % 2)).await;
        }
        let input =
            Query { grouped: true, export_page: true, from: 201, until: 201, ..Query::default() };
        let page = page(&mut tx, &admin, &input, "").await;
        let [row] = page.rows.as_slice() else { panic!("one group: {page:?}") };
        assert!(row.grouped && row.capture.is_none() && row.campaign.is_none());
        assert_eq!((row.count, row.first_seen, row.time), (15, 201, 201));
        assert_eq!(row.id, (1 << 40) | 29);
        assert!(page.to_json().contains("\"grouped\":true,\"count\":15,"));
        assert_eq!(
            audit_actions(&mut tx).await.last().map(String::as_str),
            Some("events.export_prepared")
        );
        let audited = audit_actions(&mut tx).await.len();
        // A credential that no longer authorizes gets nothing and audits nothing.
        let stranger = Credential { digest: [99; 32], ..admin.clone() };
        let refused =
            events::query_events(&mut tx, &stranger, &input, WorkBound::default(), NOW).await;
        assert!(matches!(refused, Err(ConsoleStorageError::Unauthorized)));
        assert_eq!(audit_actions(&mut tx).await.len(), audited);
    });
}

/// Inserts the sidecars of incident `id`: evidence, a country (or none) and heads.
async fn sidecars(tx: &mut Transaction, id: u64, country: Option<&str>, generation: u8) {
    let id = i64::try_from(id).expect("id");
    let evidence = Sql::both(
        "INSERT INTO console_incident_evidence (incident_id, selected_status, query_bytes, \
         body_bytes, declared_body_bytes, truncated) VALUES ($1, 403, 25, 18, 20, 66)",
    );
    tx.execute(evidence, &[id.into()]).await.expect("evidence");
    let place = Sql::both(
        "INSERT INTO console_incident_country (incident_id, country, generation) \
         VALUES ($1, $2, $3)",
    );
    let digest = [generation; 32];
    let params: [Param<'_>; 3] = [id.into(), country.into(), digest.as_slice().into()];
    tx.execute(place, &params).await.expect("country");
}

const HEADS: Sql = Sql::both(
    "INSERT INTO console_incident_heads (incident_id, request_head, response_head, \
     request_truncated, response_truncated, response_state) VALUES ($1, $2, $3, $4, $5, $6)",
);

#[test]
fn the_detail_reads_its_sidecars_and_missing_ones_are_not_recorded() {
    for_each_backend("events_detail", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = admin(&mut tx).await;
        let with = Stored { path: b"/evidence".to_vec(), ..Stored::new(1, 105) };
        let without = Stored::new(2, 106);
        store(&mut tx, &with).await;
        store(&mut tx, &without).await;
        sidecars(&mut tx, with.id(), Some("US"), 7).await;
        let head: &[u8] = b"GET /trap HTTP/1.1\r\n";
        let params: [Param<'_>; 6] = [
            i64::try_from(with.id()).expect("id").into(),
            head.into(),
            (&b"HTTP/1.1 200 OK\r\n"[..]).into(),
            Param::Int(Some(0)),
            Param::Int(Some(1)),
            "captured".into(),
        ];
        let flags = match tx.dialect() {
            Dialect::Sqlite => HEADS,
            Dialect::Postgres => Sql::both(
                "INSERT INTO console_incident_heads (incident_id, request_head, response_head, \
                 request_truncated, response_truncated, response_state) \
                 VALUES ($1, $2, $3, $4 <> 0, $5 <> 0, $6)",
            ),
        };
        tx.execute(flags, &params).await.expect("heads");
        let row = events::read_event(&mut tx, &admin, with.id(), NOW).await.expect("read");
        let row = row.expect("the incident");
        let capture = row.capture.expect("evidence");
        assert_eq!((capture.selected_status, capture.truncated, capture.version), (403, 66, 1));
        assert!(row.query_redacted, "query bytes mark the query as redacted");
        assert_eq!(row.geography.wire().code, Some("US"));
        assert_eq!(row.geography.generation.as_str(), "07".repeat(32));
        let read = incident_heads::Read { id: with.id(), ..Default::default() };
        let found = heads::read_heads(&mut tx, &admin, &read, NOW).await.expect("heads");
        assert!(found.recorded && found.response_truncated && !found.request_truncated);
        assert_eq!(found.response_state, ResponseState::Captured);
        assert_eq!(found.request.as_str(), sibuna_encoding::hex::encode(head));
        let row = events::read_event(&mut tx, &admin, without.id(), NOW).await.expect("read");
        let row = row.expect("the incident");
        assert!(row.capture.is_none() && !row.geography.recorded && !row.query_redacted);
        let read = incident_heads::Read { id: without.id(), ..Default::default() };
        let missing = heads::read_heads(&mut tx, &admin, &read, NOW).await.expect("heads");
        assert!(!missing.recorded && missing.request.is_empty());
        assert!(events::read_event(&mut tx, &admin, 99, NOW).await.expect("read").is_none());
        let zero = incident_heads::Read { id: 0, ..Default::default() };
        let invalid = heads::read_heads(&mut tx, &admin, &zero, NOW).await;
        assert!(matches!(invalid, Err(ConsoleStorageError::InvalidInput(_))));
    });
}

#[test]
fn every_filter_selects_exactly_its_rows() {
    for_each_backend("events_filters", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = admin(&mut tx).await;
        let rows = [
            Stored { ip: "203.0.113.1", category: "waf:sqli", ..Stored::new(1, 100) },
            Stored { ip: "203.0.113.2", category: "honeypot", ..Stored::new(2, 110) },
            Stored { path: b"/admin/x".to_vec(), category: "rate", ..Stored::new(3, 120) },
            Stored { node: 2, campaign: 9_007_199_254_740_993, ..Stored::new(4, 130) },
            Stored {
                category: "audit:xss",
                campaign: 9_007_199_254_740_993,
                ..Stored::new(5, 140)
            },
        ];
        for row in &rows {
            store(&mut tx, row).await;
        }
        sidecars(&mut tx, rows[0].id(), Some("US"), 1).await;
        sidecars(&mut tx, rows[1].id(), None, 1).await;
        let id = |index: usize| rows[index].id();
        let cases: Vec<(Query, Vec<u64>)> = vec![
            (Query::default(), vec![id(4), id(3), id(2), id(1), id(0)]),
            (Query { node: 2, ..Query::default() }, vec![id(3)]),
            (
                Query { category: Text::new("honeypot").expect("text"), ..Query::default() },
                vec![id(1)],
            ),
            (
                Query { ip: Text::new("203.0.113.1").expect("text"), ..Query::default() },
                vec![id(0)],
            ),
            (
                Query { path_prefix: Text::new("/admin").expect("text"), ..Query::default() },
                vec![id(2)],
            ),
            (Query { country: Text::new("US").expect("text"), ..Query::default() }, vec![id(0)]),
            (
                Query { country: Text::new("unknown").expect("text"), ..Query::default() },
                vec![id(1)],
            ),
            (
                Query { country: Text::new("not_recorded").expect("text"), ..Query::default() },
                vec![id(4), id(3), id(2)],
            ),
            (
                Query { module: Some(Module::Inspection), ..Query::default() },
                vec![id(4), id(3), id(0)],
            ),
            (Query { module: Some(Module::Honeypot), ..Query::default() }, vec![id(1)]),
            (Query { module: Some(Module::Other), ..Query::default() }, vec![id(2)]),
            (Query { campaign: 9_007_199_254_740_993, ..Query::default() }, vec![id(4), id(3)]),
            (Query { incident: id(2), ..Query::default() }, vec![id(2)]),
            (Query { from: 110, until: 130, ..Query::default() }, vec![id(3), id(2), id(1)]),
            (
                Query { before: Some(Cursor { time: 120, id: id(2) }), ..Query::default() },
                vec![id(1), id(0)],
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(all_ids(&mut tx, &admin, &input, "").await, expected, "{input:?}");
        }
        let campaign =
            page(&mut tx, &admin, &Query { incident: id(4), ..Query::default() }, "").await;
        assert_eq!(campaign.rows[0].campaign, Some(9_007_199_254_740_993));
        let invalid = Query { limit: 11, ..Query::default() };
        let refused =
            events::query_events(&mut tx, &admin, &invalid, WorkBound::default(), NOW).await;
        assert!(matches!(refused, Err(ConsoleStorageError::InvalidInput(_))));
    });
}

// Port of event_country_test.zig: missing, unknown and known countries stay distinct, and a
// group whose members map to different countries is mixed.
#[test]
fn country_attribution_stays_distinct_and_groups_are_mixed() {
    for_each_backend("events_country", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = admin(&mut tx).await;
        let countries = [Some(Some("US")), Some(Some("DE")), Some(None), None];
        for (sequence, country) in (1u64..).zip(countries) {
            let incident = Stored { ip: "8.8.8.8", ..Stored::new(sequence, 100 + sequence) };
            store(&mut tx, &incident).await;
            if let Some(code) = country {
                sidecars(&mut tx, incident.id(), code, 3).await;
            }
        }
        for (filter, code, recorded) in [
            ("US", Some("US"), true),
            ("DE", Some("DE"), true),
            ("unknown", None, true),
            ("not_recorded", None, false),
        ] {
            let input = Query { country: Text::new(filter).expect("text"), ..Query::default() };
            let page = page(&mut tx, &admin, &input, "").await;
            let [row] = page.rows.as_slice() else { panic!("{filter}: {page:?}") };
            assert_eq!((row.geography.wire().code, row.geography.recorded), (code, recorded));
            assert_eq!(row.geography.wire().generation.is_some(), recorded);
        }
        let grouped =
            Query { grouped: true, ip: Text::new("8.8.8.8").expect("text"), ..Query::default() };
        let page = page(&mut tx, &admin, &grouped, "").await;
        let [row] = page.rows.as_slice() else { panic!("one group: {page:?}") };
        assert_eq!(row.count, 4);
        assert!(row.geography.mixed && !row.geography.recorded);
        assert!(row.geography.wire().code.is_none() && row.geography.wire().generation.is_none());
    });
}

/// Recorded attack paths and payloads for the search filter.
fn corpus() -> Vec<(&'static [u8], Vec<u8>)> {
    vec![
        (b"/etc/passwd", b"file=../../etc/passwd".to_vec()),
        (b"/search", b"q=1%27%20UNION%20SELECT%20username,password%20FROM%20users--".to_vec()),
        (
            b"/wp-admin/admin-ajax.php",
            b"action=revslider_show_image&img=../wp-config.php".to_vec(),
        ),
        (
            b"/caf%C3%A9/men%C3%BC",
            "Stra\u{df}e \u{c9}COLE \u{41c}\u{43e}\u{441}\u{43a}\u{432}\u{430}".into(),
        ),
        (b"/admin", b"login=admin&password=admin".to_vec()),
        (b"/repeat", "spam ".repeat(102).into_bytes()),
        (b"/index.php", b"<script>alert(document.cookie)</script>".to_vec()),
        (b"/admin/login", b"user=root".to_vec()),
        (b"/raw\xff\xfeunion", b"\x00select\xc3\x28from".to_vec()),
        (b"/UNION%20SELECT", b"union select".to_vec()),
    ]
}

/// Queries covering every construct of the grammar.
const QUERIES: [&str; 22] = [
    "passwd",
    "/etc/passwd",
    "path:/etc/passwd",
    "payload:passwd",
    "union select",
    "UNION%20SELECT",
    "\"union select\"",
    "path:union",
    "payload:\"union select username\"",
    "admin OR shadow",
    "admin password OR path:index",
    "CAF\u{c9}",
    "stra\u{df}e",
    "\u{c9}cole",
    "\"spam spam spam\"",
    "payload:spam path:repeat",
    "\"login user\"",
    "login user",
    "select from",
    "nothingmatches",
    "\"OR\"",
    "script OR raw OR wp",
];

fn contains(haystack: &[String], needle: &[String]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn term_matches(term: &Term, path: &[String], payload: &[String]) -> bool {
    match term.field {
        Some(Field::Path) => contains(path, &term.tokens),
        Some(Field::Payload) => contains(payload, &term.tokens),
        None => contains(path, &term.tokens) || contains(payload, &term.tokens),
    }
}

#[test]
fn the_search_filter_matches_the_reference_on_both_backends() {
    for_each_backend("events_search", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = admin(&mut tx).await;
        let mut indexed = Vec::new();
        for (sequence, (path, payload)) in (1u64..).zip(corpus()) {
            let incident =
                Stored { path: path.to_vec(), payload, ..Stored::new(sequence, 1000 + sequence) };
            store(&mut tx, &incident).await;
            let tokens = (search::index_tokens(path), search::index_tokens(&incident.payload));
            indexed.push((incident.id(), tokens));
        }
        for text in QUERIES {
            let query = search::Query::parse(text).expect("valid").expect("not empty");
            let expected: BTreeSet<u64> = indexed
                .iter()
                .filter(|(_, (path, payload))| {
                    query
                        .groups
                        .iter()
                        .any(|group| group.iter().all(|term| term_matches(term, path, payload)))
                })
                .map(|(id, _)| *id)
                .collect();
            let ids = all_ids(&mut tx, &admin, &Query::default(), text).await;
            assert!(ids.windows(2).all(|pair| pair[0] > pair[1]), "newest first: {text}");
            assert_eq!(ids.into_iter().collect::<BTreeSet<u64>>(), expected, "{text}");
        }
        // The same filter applies to the grouped view.
        let grouped = Query { grouped: true, ..Query::default() };
        let groups = page(&mut tx, &admin, &grouped, "admin").await;
        assert_eq!(groups.rows.iter().map(|row| row.count).sum::<u64>(), 3);
        let invalid = searching(&Query::default(), "a OR");
        let refused =
            events::query_events(&mut tx, &admin, &invalid, WorkBound::default(), NOW).await;
        assert!(matches!(refused, Err(ConsoleStorageError::InvalidInput("search query"))));
    });
}

/// Inserts 20,000 incidents whose path and payload hold `attack`, in one statement.
pub(crate) async fn many(tx: &mut Transaction) {
    tx.execute(RECEIPT, &[1i64.into()]).await.expect("receipt");
    let script = match tx.dialect() {
        Dialect::Sqlite => {
            "WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM seq WHERE x < 20000) \
             INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, path, \
             violation_category, offending_payload, campaign_id, recorded_at, embedding) \
             SELECT 1099511627776 + x, 1, '10.0.' || (x % 200) || '.' || (x % 250), X'', 'GET', \
             CAST('/attack' AS BLOB), 'waf:sqli', CAST('attack payload' AS BLOB), x, \
             1000 + x % 100, zeroblob(256) FROM seq; \
             INSERT INTO incidents_fts (rowid, path, offending_payload) \
             SELECT id, 'attack', 'attack payload' FROM security_incidents"
        }
        Dialect::Postgres => {
            "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, path, \
             violation_category, offending_payload, campaign_id, recorded_at, embedding, search) \
             SELECT 1099511627776 + x, 1, '10.0.' || (x % 200) || '.' || (x % 250), \
             '\\x'::bytea, 'GET', convert_to('/attack', 'UTF8'), 'waf:sqli', \
             convert_to('attack payload', 'UTF8'), x, 1000 + x % 100, \
             decode(repeat('00', 256), 'hex'), \
             CAST('''attack'':1A,2B ''payload'':3B' AS tsvector) \
             FROM generate_series(1, 20000) AS x"
        }
    };
    tx.execute_script(script).await.expect("many incidents");
}

/// A bound far below what grouping 20,000 matches takes.
pub(crate) const TINY: WorkBound = WorkBound { sqlite_steps: 1_000, postgres_timeout_ms: 1 };

#[test]
fn a_search_past_its_work_bound_is_unavailable() {
    for_each_backend("events_bound", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = admin(&mut tx).await;
        many(&mut tx).await;
        tx.commit().await.expect("commit");
        let grouped = searching(&Query { grouped: true, ..Query::default() }, "attack");
        let mut tx = db.begin().await.expect("begin");
        let refused = events::query_events(&mut tx, &admin, &grouped, TINY, NOW).await;
        assert!(matches!(refused, Err(ConsoleStorageError::Unavailable)), "{refused:?}");
        drop(tx);
        // A cancelled statement aborts a PostgreSQL transaction, so the next read begins
        // its own; the default bound suffices for the same read.
        let mut tx = db.begin().await.expect("begin");
        let bounded = events::query_events(&mut tx, &admin, &grouped, WorkBound::default(), NOW)
            .await
            .expect("within the default bound");
        // The page's byte bound may keep fewer than its ten rows; more always follow.
        assert!(!bounded.rows.is_empty() && bounded.next.is_some());
        if tx.dialect() == Dialect::Sqlite {
            // On SQLite an interrupted read leaves the transaction usable, without the bound.
            let refused = events::query_events(&mut tx, &admin, &grouped, TINY, NOW).await;
            assert!(matches!(refused, Err(ConsoleStorageError::Unavailable)));
            let rows = page(&mut tx, &admin, &Query { limit: 1, ..Query::default() }, "").await;
            assert_eq!(rows.rows.len(), 1);
        }
    });
}

fn embedding(payload: &[u8]) -> [u8; 256] {
    sibuna_policy::embedding::to_bytes(&sibuna_policy::embedding::embed(payload))
}

// Port of console_store_test.zig "incremental similarity scans yield at 64 rows and
// recheck authorization".
#[test]
fn similarity_scans_yield_at_64_rows_and_recheck_authorization() {
    for_each_backend("events_similar", |db| async move {
        let mut tx = db.begin().await.expect("begin");
        let admin = admin(&mut tx).await;
        for index in 0..130u64 {
            let payload: &[u8] =
                if index % 3 == 0 { b"id=1 union select password" } else { b"../../etc/passwd" };
            let incident =
                Stored { embedding: embedding(payload), ..Stored::new(index + 1, 200 + index) };
            store(&mut tx, &incident).await;
        }
        let mut input =
            similarity::Query { source: (1 << 40) | 1, until: 400, ..Default::default() };
        let mut best = similarity::Best::default();
        let (mut scanned, mut parts) = (0usize, 0usize);
        loop {
            let part = similar::similar(&mut tx, &admin, &input, NOW).await.expect("part");
            assert!(part.source_available && part.scanned <= 64 && part.invalid == 0);
            scanned += usize::from(part.scanned);
            parts += 1;
            for row in part.best.rows() {
                assert_ne!(row.id, input.source);
                best.add(*row);
            }
            input.before = part.next;
            if part.next.is_none() {
                break;
            }
            assert!(parts < 4);
        }
        assert_eq!((scanned, parts), (130, 3));
        assert_eq!(best.rows().len(), similarity::BEST_ROWS);
        assert!(best.rows().iter().all(|row| row.distance < 0.00001));
        let missing = similarity::Query { source: 9, until: 400, ..Default::default() };
        let part = similar::similar(&mut tx, &admin, &missing, NOW).await.expect("part");
        assert!(!part.source_available && part.scanned == 0);
        tx.execute(Sql::both("DELETE FROM console_sessions"), &[]).await.expect("sign out");
        let refused = similar::similar(&mut tx, &admin, &input, NOW).await;
        assert!(matches!(refused, Err(ConsoleStorageError::Unauthorized)));
    });
}
