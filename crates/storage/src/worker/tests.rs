//! The tests of `persistent.zig`, `persistent_policy.zig`, `policy_inspection.zig` and
//! `policy_limits.zig`, run on SQLite and, when `SIBUNA_TEST_DATABASE_URL` is set, on
//! PostgreSQL. Where Zig evaluated the rebuilt engine, these tests check the published
//! snapshot, because the daemon builds the engine from it.

use std::sync::atomic::{AtomicU64, Ordering};

use sibuna_core::Incident;

use crate::database::{Dialect, Target};
use crate::error::StorageError;
use crate::incidents::write_batch;
use crate::policy::{InspectionRow, ReputationRow};
use crate::testing::{Fixture, for_each_backend};

fn honeypot(now: u64) -> Incident<'static> {
    Incident {
        client_ip: "198.51.100.99",
        user_agent: b"test",
        method: "GET",
        path: b"/trap",
        category: "honeypot",
        payload: b"repeat",
        now,
        ..Incident::default()
    }
}

fn sqli(
    ip: &'static str,
    path: &'static [u8],
    payload: &'static [u8],
    now: u64,
) -> Incident<'static> {
    Incident {
        client_ip: ip,
        user_agent: b"sqlmap",
        method: "GET",
        path,
        category: "waf:sqli",
        payload,
        now,
        ..Incident::default()
    }
}

const DELETE_INCIDENTS_SQLITE: &str = "INSERT INTO incidents_fts (incidents_fts, rowid, path, \
    offending_payload) SELECT 'delete', id, path, offending_payload FROM security_incidents; \
    DELETE FROM security_incidents;";

#[test]
fn incident_identity_survives_removal_of_all_rows_and_rejects_exhausted_or_corrupt_receipts() {
    for_each_backend("identity", |target| Box::pin(identity(target)));
}

async fn identity(target: Target) {
    let event = honeypot(100);
    let mut owner = Fixture::open(&target).await;
    owner.record(&event);
    owner.worker_tick().await;
    assert_eq!(owner.worker.next_sequence, 2);
    // Simulate retention's removal without changing the durable receipt.
    match target.dialect() {
        Dialect::Sqlite => owner.exec(DELETE_INCIDENTS_SQLITE).await,
        Dialect::Postgres => owner.exec("DELETE FROM security_incidents").await,
    }
    owner.close().await;

    let mut owner = Fixture::open(&target).await;
    assert_eq!(owner.worker.next_sequence, 2);
    owner.record(&event);
    owner.worker_tick().await;
    let counts =
        owner.ints("SELECT COUNT(*), MIN(id & 1099511627775) FROM security_incidents").await;
    assert_eq!(counts, [1, 2]);
    owner.exec("DELETE FROM sibuna_meta WHERE key = 'incident_cursor_1'").await;
    owner.worker.load_next_sequence().await.unwrap();
    assert_eq!(owner.worker.next_sequence, 3);
    owner.exec("INSERT INTO sibuna_meta VALUES ('incident_cursor_1', '1099511627776')").await;
    owner.worker.load_next_sequence().await.unwrap();
    owner.record(&event);
    assert!(matches!(owner.worker.drain().await, Err(StorageError::IncidentIdExhausted)));
    // The exhausted fixture cannot flush; the production shutdown reports this failure.
    owner.worker.pending.clear();
    owner.exec("UPDATE sibuna_meta SET value = '0' WHERE key = 'incident_cursor_1'").await;
    let corrupt = owner.worker.load_next_sequence().await;
    assert!(matches!(corrupt, Err(StorageError::InvalidIncidentCursor)));
    owner.close().await;
}

impl Fixture {
    /// Ticks and fails the test on a policy error.
    async fn worker_tick(&mut self) {
        self.worker.tick().await.expect("tick");
    }
}

const INSERT_P1: &str = "INSERT INTO policies (id, name, priority, path_pattern, action, \
    difficulty, algorithm, header_matchers, cidr_matchers, weight, enabled, created_at, \
    updated_at) VALUES ('p1', 'protect-secret', 10, '/secret/*', 'CHALLENGE', 20, 'posw', \
    '{\"X-Api\":\"v2\"}', '[\"10.0.0.0/8\"]', 0, 1, 100, 100)";

#[test]
fn persistent_store_policy_reload_reputation_forensics_campaigns() {
    for_each_backend("store", |target| Box::pin(store(target)));
}

async fn store(target: Target) {
    let mut p = Fixture::open(&target).await;
    // Nothing is stored yet; the daemon's file policy is all that applies.
    let first = p.latest();
    assert!(first.rules.is_empty() && first.reputation.is_empty() && first.inspection.is_none());

    // A dynamic policy and a reputation ban appear after one tick.
    p.exec(INSERT_P1).await;
    p.worker.db.ban_address("198.51.100.7", 4_102_444_800, "test", 100).await.unwrap();
    p.worker_tick().await;
    let fresh = p.latest();
    assert!(fresh.revision > first.revision);
    let [rule] = fresh.rules.as_slice() else { panic!("one rule: {fresh:?}") };
    assert_eq!((rule.id.as_str(), rule.name.as_str()), ("p1", "protect-secret"));
    assert_eq!((rule.action.as_str(), rule.difficulty), ("CHALLENGE", Some(20)));
    assert_eq!(rule.algorithm.as_deref(), Some("posw"));
    assert_eq!(rule.path_pattern.as_deref(), Some("/secret/*"));
    assert_eq!(rule.header_matchers.as_deref(), Some("{\"X-Api\":\"v2\"}"));
    assert_eq!(rule.cidr_matchers.as_deref(), Some("[\"10.0.0.0/8\"]"));
    let ban = ReputationRow {
        ip_or_cidr: "198.51.100.7".into(),
        reputation_score: -100,
        banned_until: Some(4_102_444_800),
    };
    assert_eq!(fresh.reputation, [ban]);
    assert_eq!(fresh.next_expiry, Some(4_102_444_800));

    // Repeated updates with identical timestamps must reload every time.
    for round in 0..4 {
        let action = if round % 2 == 0 { "DENY" } else { "ALLOW" };
        let params = [action.into()];
        let update = crate::database::Sql::both("UPDATE policies SET action = $1 WHERE id = 'p1'");
        p.worker.db.execute(update, &params).await.unwrap();
        let before = p.published();
        p.worker_tick().await;
        assert_eq!(p.published(), before + 1);
        assert_eq!(p.latest().rules[0].action, action);
        assert_eq!(p.latest().rules[0].name, "protect-secret");
    }
    // Without a change, a tick publishes nothing.
    let before = p.published();
    p.worker_tick().await;
    assert_eq!(p.published(), before);

    incidents_and_campaigns(&mut p).await;
    replay_after_failure(&mut p, target.dialect()).await;
    p.close().await;
}

async fn incidents_and_campaigns(p: &mut Fixture) {
    p.record(&sqli(
        "203.0.113.5",
        b"/login",
        b"id=1' UNION SELECT username,password FROM users--",
        200,
    ));
    p.record(&sqli(
        "203.0.113.6",
        b"/account",
        b"id=77' union select name,pass from users--",
        201,
    ));
    p.record(&Incident {
        client_ip: "203.0.113.7",
        user_agent: b"Scrapy",
        method: "GET",
        path: b"/__sibuna/honeypot",
        category: "honeypot",
        payload: b"",
        now: 202,
        ..Incident::default()
    });
    p.worker_tick().await;
    let found = p.worker.db.search_incidents("users", 10).await.unwrap();
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].campaign_id, found[1].campaign_id);
    let all = p.ints("SELECT COUNT(*), COUNT(DISTINCT campaign_id) FROM security_incidents").await;
    assert_eq!(all, [3, 2]);
    let reputation = p
        .row(
            "SELECT reputation_score, trigger_rule FROM ip_reputation \
              WHERE ip_or_cidr = '203.0.113.7'",
        )
        .await;
    assert_eq!(reputation[0].as_i64(), Some(-100));
    assert_eq!(reputation[1].as_str(), Some("honeypot"));
}

const FAIL_SQLITE: &str = "CREATE TRIGGER fail_incident BEFORE INSERT ON security_incidents \
    BEGIN SELECT RAISE(ABORT, 'injected test failure'); END;";
const FAIL_POSTGRES: &str = "CREATE FUNCTION fail_incident() RETURNS trigger LANGUAGE plpgsql \
    AS $$ BEGIN RAISE EXCEPTION 'injected test failure'; END $$; \
    CREATE TRIGGER fail_incident BEFORE INSERT ON security_incidents \
    FOR EACH ROW EXECUTE FUNCTION fail_incident();";

/// Holds a full batch across a real SQL failure (policy reads still run), then commits it
/// behind the worker's back as if the acknowledgement were lost, and checks that the retry
/// writes nothing twice.
async fn replay_after_failure(p: &mut Fixture, dialect: Dialect) {
    match dialect {
        Dialect::Sqlite => p.exec(FAIL_SQLITE).await,
        Dialect::Postgres => p.exec(FAIL_POSTGRES).await,
    }
    let event = honeypot(203);
    for _ in 0..40 {
        p.record(&event);
    }
    p.worker_tick().await;
    assert_eq!(p.worker.pending.len(), 32);
    assert!(p.worker.prepared.is_some());
    assert_eq!(p.metrics.incident_write_failures.value(), 1);
    match dialect {
        Dialect::Sqlite => p.exec("DROP TRIGGER fail_incident").await,
        Dialect::Postgres => p.exec("DROP TRIGGER fail_incident ON security_incidents").await,
    }
    // Commit successfully but pretend the client lost its acknowledgement.
    let batch = p.worker.prepared.clone().unwrap();
    write_batch(&p.worker.db, 1, &batch).await.unwrap();
    p.worker_tick().await;
    p.worker_tick().await;
    let counts = p
        .ints(
            "SELECT (SELECT COUNT(*) FROM security_incidents), \
               (SELECT COUNT(embedding) FROM security_incidents), \
               (SELECT hits FROM ip_reputation WHERE ip_or_cidr = '198.51.100.99')",
        )
        .await;
    assert_eq!(counts, [43, 43, 40]);
    assert_eq!(p.worker.db.search_incidents("repeat", 100).await.unwrap().len(), 40);
    assert_eq!(p.metrics.incidents_persisted.value(), 43);
    assert_eq!(p.metrics.incident_batches.value(), 3);
    for _ in 0..513 {
        p.record(&event);
    }
    assert_eq!(p.metrics.incidents_dropped.value(), 1);
    for _ in 0..16 {
        p.worker_tick().await;
    }
    assert_eq!(p.metrics.incidents_persisted.value(), 555);
}

#[test]
fn rejected_snapshots_preserve_the_applied_revision_until_repaired() {
    for_each_backend("rejected", |target| Box::pin(rejected(target)));
}

/// `persistent_policy.zig`: invalid stored matchers keep the live engine and revision. The
/// daemon validates matchers; here its publish hook refuses anything but the good pair.
async fn rejected(target: Target) {
    let good = |snapshot: &crate::PolicySnapshot| {
        snapshot.rules.iter().all(|rule| {
            rule.header_matchers.as_deref() == Some("{\"X-Api\":\"v2\"}")
                && rule.cidr_matchers.as_deref() == Some("[\"10.0.0.0/8\"]")
        })
    };
    let mut owner = Fixture::open_with(&target, 1, good).await;
    owner
        .exec(
            "INSERT INTO policies (id, name, action, path_pattern, created_at, updated_at, \
               header_matchers, cidr_matchers) VALUES ('limited', 'Limited', 'allow', \
               '/private', 1, 1, '{\"X-Api\":\"v2\"}', '[\"10.0.0.0/8\"]')",
        )
        .await;
    owner.worker_tick().await;
    let applied = owner.worker.applied_revision;
    let cases = [
        "header_matchers = '[]'",
        "header_matchers = '{\"X-Api\":7}'",
        "cidr_matchers = '[\"invalid\"]'",
    ];
    for case in cases {
        owner.exec(&format!("UPDATE policies SET {case}")).await;
        assert!(matches!(owner.worker.tick().await, Err(StorageError::PublishRejected)));
        assert_eq!(owner.worker.applied_revision, applied);
        // The refusal is retried on every tick until the rows are repaired.
        assert!(matches!(owner.worker.tick().await, Err(StorageError::PublishRejected)));
        owner
            .exec(
                "UPDATE policies SET header_matchers = '{\"X-Api\":\"v2\"}', \
                   cidr_matchers = '[\"10.0.0.0/8\"]'",
            )
            .await;
    }
    owner.worker_tick().await;
    assert_ne!(owner.worker.applied_revision, applied);
    assert_eq!(owner.latest().rules[0].name, "Limited");
    owner.close().await;
}

#[test]
fn persistent_inspection_overrides_apply_and_their_removal_falls_back() {
    for_each_backend("inspection", |target| Box::pin(inspection(target)));
}

async fn inspection(target: Target) {
    let mut owner = Fixture::open(&target).await;
    owner
        .exec(
            "INSERT INTO policy_inspection VALUES (1, 'disabled', 'audit', 'enforce', 'enforce')",
        )
        .await;
    owner.worker_tick().await;
    let expected = InspectionRow {
        path_traversal: "disabled".into(),
        sqli: "audit".into(),
        xss: "enforce".into(),
        rce: "enforce".into(),
    };
    assert_eq!(owner.latest().inspection, Some(expected));
    // The CHECK constraints refuse unknown modes and a second row.
    let bad = owner
        .worker
        .db
        .execute_script(
            "INSERT INTO policy_inspection VALUES (2, 'audit', 'audit', 'audit', 'audit')",
        )
        .await;
    assert!(bad.is_err());
    let bad = owner.worker.db.execute_script("UPDATE policy_inspection SET sqli = 'loud'").await;
    assert!(bad.is_err());
    owner.exec("DELETE FROM policy_inspection WHERE id = 1").await;
    owner.worker_tick().await;
    // The daemon falls back to the file's inspection settings.
    assert_eq!(owner.latest().inspection, None);
    owner.close().await;
}

#[test]
fn rule_limits_load_and_newer_schemas_are_refused() {
    for_each_backend("limits", |target| Box::pin(limits(target)));
}

/// `policy_limits.zig`: a legacy row without limits loads with none; a stored limit
/// document loads verbatim; a database from a newer build is refused.
async fn limits(target: Target) {
    let mut owner = Fixture::open(&target).await;
    owner
        .exec(
            "INSERT INTO policies (id, name, action, path_pattern, created_at, updated_at) \
               VALUES ('legacy', 'Legacy', 'deny', '/legacy', 100, 100)",
        )
        .await;
    owner.worker_tick().await;
    assert_eq!(owner.latest().rules[0].limit_config, None);
    owner
        .exec(
            "UPDATE policies SET limit_config = '{\"rate\":1,\"window_seconds\":60}' \
               WHERE id = 'legacy'",
        )
        .await;
    owner.worker_tick().await;
    let limits = owner.latest().rules[0].limit_config.clone();
    assert_eq!(limits.as_deref(), Some("{\"rate\":1,\"window_seconds\":60}"));
    owner.close().await;

    // Reopening applies nothing twice.
    let owner = Fixture::open(&target).await;
    assert_eq!(
        owner.ints("SELECT COUNT(*) FROM sibuna_schema WHERE component = 'core'").await,
        [1]
    );
    owner.exec("INSERT INTO sibuna_schema VALUES ('core', 99, 0)").await;
    owner.close().await;
    let refused = Fixture::try_open(&target, 1, |_| true).await;
    let Err(StorageError::SchemaTooNew { component, found, known }) = refused else {
        panic!("a newer schema must be refused");
    };
    assert_eq!((component, found, known), ("core", 99, 1));
}

static TEST_NOW: AtomicU64 = AtomicU64::new(0);

fn test_clock() -> u64 {
    TEST_NOW.load(Ordering::Relaxed)
}

#[test]
fn an_expired_ban_triggers_a_rebuild_without_a_write() {
    for_each_backend("expiry", |target| Box::pin(expiry(target)));
}

async fn expiry(target: Target) {
    let mut owner = Fixture::open(&target).await;
    owner.worker.clock = test_clock;
    TEST_NOW.store(900, Ordering::Relaxed);
    owner.worker.db.ban_address("198.51.100.8", 1000, "test", 500).await.unwrap();
    owner
        .exec("INSERT INTO ip_reputation VALUES ('192.0.2.0/24', 60, NULL, 'allow', 1, 500)")
        .await;
    owner.exec("INSERT INTO ip_reputation VALUES ('192.0.2.77', -20, 2000, 'weak', 1, 500)").await;
    owner.worker_tick().await;
    let mut addresses: Vec<String> =
        owner.latest().reputation.into_iter().map(|row| row.ip_or_cidr).collect();
    addresses.sort();
    // The weak score is not decisive, so it is not loaded.
    assert_eq!(addresses, ["192.0.2.0/24", "198.51.100.8"]);
    assert_eq!(owner.latest().next_expiry, Some(1000));
    let published = owner.published();
    TEST_NOW.store(999, Ordering::Relaxed);
    owner.worker_tick().await;
    assert_eq!(owner.published(), published);
    TEST_NOW.store(1000, Ordering::Relaxed);
    owner.worker_tick().await;
    assert_eq!(owner.published(), published + 1);
    let reputation = owner.latest().reputation;
    assert_eq!(reputation.len(), 1);
    assert_eq!(reputation[0].banned_until, None);
    assert_eq!(owner.latest().next_expiry, None);
    owner.close().await;
}

#[test]
fn nodes_share_campaigns_through_the_incremental_window() {
    for_each_backend("window", |target| Box::pin(window(target)));
}

/// Two workers with different node ids share one database: node 2's window picks up node
/// 1's incident on its next tick, so a variant recorded on node 2 joins node 1's campaign.
async fn window(target: Target) {
    let mut one = Fixture::open_with(&target, 1, |_| true).await;
    let mut two = Fixture::open_with(&target, 2, |_| true).await;
    one.record(&sqli(
        "203.0.113.5",
        b"/a",
        b"id=1' UNION SELECT username,password FROM users--",
        1,
    ));
    one.worker_tick().await;
    two.worker_tick().await;
    assert_eq!(two.worker.campaigns.len(), 1);
    two.record(&sqli("203.0.113.6", b"/b", b"id=42' union select name,pass from users--", 2));
    two.record(&sqli("203.0.113.6", b"/c", b"<img src=x onerror=alert(document.cookie)>", 3));
    two.worker_tick().await;
    let hits = two.worker.db.search_incidents("users", 10).await.unwrap();
    assert_eq!(hits.len(), 2);
    let first_id = (1i64 << 40) | 1;
    assert!(hits.iter().all(|hit| hit.campaign_id == Some(first_id)));
    let ids =
        two.ints("SELECT COUNT(DISTINCT campaign_id), COUNT(*) FROM security_incidents").await;
    assert_eq!(ids, [2, 3]);
    // Node 1 picks up node 2's two incidents; its own row is not read back.
    one.worker_tick().await;
    assert_eq!(one.worker.campaigns.len(), 3);
    one.close().await;
    two.close().await;
    // A restarted node fills its window from the stored rows of every node.
    let three = Fixture::open_with(&target, 3, |_| true).await;
    assert_eq!(three.worker.campaigns.len(), 3);
    three.close().await;
}

#[test]
fn search_rejects_long_queries_and_caps_results() {
    for_each_backend("search", |target| Box::pin(search(target)));
}

async fn search(target: Target) {
    let mut owner = Fixture::open(&target).await;
    for now in 0..5 {
        owner.record(&sqli("203.0.113.1", b"/q", b"union select secret from vault", now));
    }
    owner.worker_tick().await;
    let long = "x".repeat(crate::MAX_SEARCH_QUERY + 1);
    let error = owner.worker.db.search_incidents(&long, 10).await;
    assert!(matches!(error, Err(StorageError::SearchQueryTooLong)));
    assert_eq!(owner.worker.db.search_incidents("vault", 3).await.unwrap().len(), 3);
    assert!(owner.worker.db.search_incidents("nothing", 3).await.unwrap().is_empty());
    owner.close().await;
}

/// Times the write of one 32-incident batch. Run with
/// `cargo test --release -p sibuna-storage --features postgres -- --ignored --nocapture
/// batch_write`.
#[test]
#[ignore]
fn batch_write_latency() {
    for_each_backend("latency", |target| Box::pin(latency(target)));
}

async fn latency(target: Target) {
    let mut owner = Fixture::open(&target).await;
    let mut samples = Vec::new();
    for round in 0..100u64 {
        for index in 0..32u64 {
            owner.record(&sqli(
                "203.0.113.50",
                b"/search",
                b"q=1' UNION SELECT card_number,cvv FROM payments WHERE '1'='1",
                round * 32 + index,
            ));
        }
        let start = std::time::Instant::now();
        assert_eq!(owner.worker.drain().await.unwrap(), 32);
        samples.push(start.elapsed());
    }
    samples.sort();
    println!(
        "{:?}: 32-incident batch write p50 {:?}, p90 {:?}, max {:?}",
        target.dialect(),
        samples[50],
        samples[90],
        samples[99]
    );
    owner.close().await;
}
