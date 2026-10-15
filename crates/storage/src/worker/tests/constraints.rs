//! The typed schema (SID 0011, "Schema and migrations") refuses, on both backends, every row
//! the row structs could not hold, and rules stored through [`Database::store_policy`] bind
//! their enums by name and come back unchanged.

use sqlx::error::ErrorKind;

use crate::database::{Database, Dialect, Param, Sql, Target};
use crate::error::StorageError;
use crate::policy::{ChallengeAlgorithm, PolicyAction, PolicyRow, RuleLimits};
use crate::testing::{Fixture, for_each_backend};

/// How the database must refuse a write.
#[derive(Clone, Copy, Debug)]
enum Refusal {
    /// A `CHECK` constraint.
    Check,
    /// A missing `NOT NULL` value.
    NotNull,
    /// The deferred foreign key from an incident to its node's receipt.
    ForeignKey,
    /// A value of the wrong type. SQLite reports a violated `CHECK` or `STRICT` datatype,
    /// PostgreSQL an input or type error, so any refusal counts.
    Type,
}

/// Asserts that `result` is the refusal `expected`; `label` names the case.
fn assert_refused<T>(result: Result<T, StorageError>, expected: Refusal, label: &str) {
    let error = match result {
        Ok(_) => panic!("{label}: the write was accepted"),
        Err(error) => error,
    };
    let kind = match &error {
        StorageError::Database(sqlx::Error::Database(database)) => database.kind(),
        other => panic!("{label}: not a database refusal: {other}"),
    };
    let wanted = match expected {
        Refusal::Check => ErrorKind::CheckViolation,
        Refusal::NotNull => ErrorKind::NotNullViolation,
        Refusal::ForeignKey => ErrorKind::ForeignKeyViolation,
        Refusal::Type => return,
    };
    assert_eq!(kind, wanted, "{label}: {error}");
}

/// Runs one parameterless statement.
async fn run(db: &Database, sql: &'static str) -> Result<u64, StorageError> {
    db.execute(Sql::both(sql), &[]).await
}

/// Rows of `policies` that differ from a valid row in one column or one pair of columns:
/// the columns and values added to [`policy_insert`]'s, and the expected refusal.
const POLICY_CASES: [(&str, &str, Refusal); 15] = [
    ("action", "'DENY'", Refusal::Check),
    ("action", "'maybe'", Refusal::Check),
    ("action, algorithm", "'challenge', 'sha256'", Refusal::Check),
    ("action, difficulty", "'challenge', -1", Refusal::Check),
    ("action, difficulty", "'challenge', 4294967296", Refusal::Check),
    ("action, weight", "'weigh', 2147483648", Refusal::Type),
    ("action, header_matchers", "'deny', '[]'", Refusal::Check),
    ("action, header_matchers", "'deny', 'not json'", Refusal::Type),
    ("action, cidr_matchers", "'deny', '{}'", Refusal::Check),
    ("action, limit_rate", "'deny', 1", Refusal::Check),
    ("action, limit_rate, limit_window_seconds", "'deny', 0, 60", Refusal::Check),
    ("action, limit_rate, limit_window_seconds", "'deny', 1, 86401", Refusal::Check),
    ("action, limit_ban_seconds", "'deny', 60", Refusal::Check),
    ("action, enabled", "'deny', 2", Refusal::Type),
    ("action, priority", "'deny', 'high'", Refusal::Type),
];

/// Returns an insert of the rule `bad` with `columns` set to `values`.
fn policy_insert(columns: &str, values: &str) -> String {
    format!(
        "INSERT INTO policies (id, name, created_at, updated_at, {columns}) \
         VALUES ('bad', 'bad', 1, 1, {values})"
    )
}

/// Rows of the other policy tables, and updates of the revision and of receipts.
const OTHER_CASES: [(&str, Refusal); 12] = [
    (
        "INSERT INTO policies (id, action, created_at, updated_at) VALUES ('bad', 'deny', 1, 1)",
        Refusal::NotNull,
    ),
    (
        "INSERT INTO policy_inspection VALUES (1, 'disabled', 'loud', 'audit', 'audit')",
        Refusal::Check,
    ),
    (
        "INSERT INTO policy_inspection VALUES (2, 'audit', 'audit', 'audit', 'audit')",
        Refusal::Check,
    ),
    ("INSERT INTO ip_reputation VALUES ('192.0.2.1', 101, NULL, 'x', 1, 1)", Refusal::Check),
    ("INSERT INTO ip_reputation VALUES ('192.0.2.1', -101, NULL, 'x', 1, 1)", Refusal::Check),
    ("INSERT INTO ip_reputation VALUES ('192.0.2.1', -100, -1, 'x', 1, 1)", Refusal::Check),
    ("INSERT INTO ip_reputation VALUES ('192.0.2.1', 'bad', NULL, 'x', 1, 1)", Refusal::Type),
    ("INSERT INTO policy_revision VALUES (2, 0)", Refusal::Check),
    ("UPDATE policy_revision SET revision = -1", Refusal::Check),
    ("INSERT INTO incident_receipts VALUES (0, 1)", Refusal::Check),
    ("INSERT INTO incident_receipts VALUES (2, 0)", Refusal::Check),
    ("INSERT INTO incident_receipts VALUES (2, 1099511627777)", Refusal::Check),
];

#[test]
fn the_schema_refuses_rows_the_rust_types_cannot_hold() {
    for_each_backend("constraints", |target| Box::pin(constraints(target)));
}

async fn constraints(target: Target) {
    let p = Fixture::open(&target).await;
    let db = &p.worker.db;
    let valid = "INSERT INTO policies (id, name, action, algorithm, difficulty, weight, \
                 header_matchers, cidr_matchers, limit_rate, limit_window_seconds, \
                 limit_ban_seconds, enabled, created_at, updated_at) VALUES ('good', 'good', \
                 'challenge', 'hashcash', 64, -2147483648, '{\"A\": \"b\"}', '[]', 1000000, \
                 86400, 86400, FALSE, 0, 0)";
    run(db, valid).await.expect("a row at every bound is accepted");
    for (columns, values, refusal) in POLICY_CASES {
        let sql = policy_insert(columns, values);
        assert_refused(db.execute_script(&sql).await, refusal, &sql);
    }
    for (sql, refusal) in OTHER_CASES {
        assert_refused(run(db, sql).await, refusal, sql);
    }
    run(db, "INSERT INTO ip_reputation VALUES ('192.0.2.1', -100, 0, 'x', 0, 0)").await.unwrap();
    run(db, "INSERT INTO incident_receipts VALUES (1, 1099511627776)").await.unwrap();
    incident_constraints(db).await;
    p.close().await;
}

/// Inserts one incident with bound values; PostgreSQL also needs the search text.
const INSERT_INCIDENT: Sql = Sql {
    sqlite: "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, path, \
             violation_category, offending_payload, campaign_id, recorded_at, embedding) \
             VALUES ($1, $2, '192.0.2.9', $3, 'GET', $4, 'waf:xss', $5, $1, $6, $7)",
    postgres: "INSERT INTO security_incidents (id, node_id, client_ip, user_agent, method, \
               path, violation_category, offending_payload, campaign_id, recorded_at, \
               embedding, search_text) \
               VALUES ($1, $2, '192.0.2.9', $3, 'GET', $4, 'waf:xss', $5, $1, $6, $7, '')",
};

/// One incident row; `sizes` are the lengths of the user agent, path, payload and embedding.
struct Incident {
    id: i64,
    node: i64,
    sizes: [usize; 4],
    recorded_at: i64,
}

impl Incident {
    const fn valid(id: i64) -> Incident {
        Incident { id, node: 1, sizes: [200, 512, 512, 256], recorded_at: 0 }
    }

    async fn insert(&self, db: &Database) -> Result<u64, StorageError> {
        let [user_agent, path, payload, embedding] = self.sizes.map(|size| vec![b'x'; size]);
        let params: [Param<'_>; 7] = [
            self.id.into(),
            self.node.into(),
            user_agent.as_slice().into(),
            path.as_slice().into(),
            payload.as_slice().into(),
            self.recorded_at.into(),
            embedding.as_slice().into(),
        ];
        db.execute(INSERT_INCIDENT, &params).await
    }
}

async fn incident_constraints(db: &Database) {
    let first = (1i64 << 40) | 1;
    Incident::valid(first).insert(db).await.expect("a row at every bound is accepted");
    let cases = [
        ("another node's id", Incident::valid((2 << 40) | 1)),
        ("sequence 0", Incident::valid(1 << 40)),
        (
            "long user agent",
            Incident { sizes: [201, 512, 512, 256], ..Incident::valid(first + 1) },
        ),
        ("long path", Incident { sizes: [200, 513, 512, 256], ..Incident::valid(first + 1) }),
        ("long payload", Incident { sizes: [200, 512, 513, 256], ..Incident::valid(first + 1) }),
        (
            "short embedding",
            Incident { sizes: [200, 512, 512, 255], ..Incident::valid(first + 1) },
        ),
        ("negative time", Incident { recorded_at: -1, ..Incident::valid(first + 1) }),
    ];
    for (label, incident) in cases {
        assert_refused(incident.insert(db).await, Refusal::Check, label);
    }
    // Node 3 has no receipt: its incident is refused when the statement commits.
    let orphan = Incident { node: 3, ..Incident::valid((3 << 40) | 1) };
    assert_refused(orphan.insert(db).await, Refusal::ForeignKey, "no receipt");
}

#[test]
fn stored_rules_bind_their_enums_and_come_back_unchanged() {
    for_each_backend("store_policy", |target| Box::pin(store_policy(target)));
}

async fn store_policy(target: Target) {
    let mut p = Fixture::open(&target).await;
    let rule = PolicyRow {
        id: "stored".into(),
        name: "Stored".into(),
        priority: 7,
        path_pattern: Some("/api/*".into()),
        ua_pattern: None,
        action: PolicyAction::Challenge,
        difficulty: Some(18),
        algorithm: Some(ChallengeAlgorithm::Hashcash),
        // As PostgreSQL's JSONB prints it, so both backends return the same text.
        header_matchers: Some("{\"X-Api\": \"v2\"}".into()),
        cidr_matchers: Some("[\"10.0.0.0/8\", \"192.0.2.0/24\"]".into()),
        weight: -12,
        limits: Some(RuleLimits { rate: 5, window_seconds: 60, ban_seconds: 300 }),
    };
    p.worker.db.store_policy(&rule, 100).await.unwrap();
    p.worker.tick().await.unwrap();
    let first = p.latest();
    assert_eq!(first.rules, std::slice::from_ref(&rule));
    let replaced = PolicyRow { action: PolicyAction::Deny, limits: None, ..rule.clone() };
    p.worker.db.store_policy(&replaced, 200).await.unwrap();
    p.worker.tick().await.unwrap();
    assert_eq!(p.latest().rules, [replaced]);
    assert!(p.latest().revision > first.revision);
    let times = p.ints("SELECT created_at, updated_at FROM policies").await;
    assert_eq!(times, [100, 200]);
    // A quota out of range is refused by the database, not by a node.
    let invalid =
        PolicyRow { limits: Some(RuleLimits { rate: 0, ..RuleLimits::default() }), ..rule };
    let refused = p.worker.db.store_policy(&invalid, 300).await;
    assert_refused(refused, Refusal::Check, "rate 0");
    if target.dialect() == Dialect::Postgres {
        // JSONB keeps one value of a repeated key, as SID 0011 records.
        let duplicate = PolicyRow {
            header_matchers: Some("{\"A\": \"1\", \"A\": \"2\"}".into()),
            ..PolicyRow { id: "dup".into(), ..PolicyRow::default() }
        };
        p.worker.db.store_policy(&duplicate, 300).await.unwrap();
        let stored = p.row("SELECT CAST(header_matchers AS TEXT) FROM policies WHERE id = 'dup'");
        assert_eq!(stored.await[0].as_str(), Some("{\"A\": \"2\"}"));
    }
    p.close().await;
}
