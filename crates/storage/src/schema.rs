//! Numbered migrations, written once per dialect and compiled into the binary.
//!
//! `sibuna_schema(component, version, applied_at)` records what is applied. The core schema
//! is the component `core`; a later crate (the console) passes its own [`MigrationSet`] to
//! [`migrate`], numbered independently, so a node without the console neither applies nor
//! rejects the console's tables. All pending migrations of every set run in one transaction;
//! under PostgreSQL a transaction-scoped advisory lock serialises nodes that start together.

use crate::database::{Database, Dialect, Param, Sql};
use crate::error::StorageError;

/// One schema change.
#[derive(Clone, Copy, Debug)]
pub struct Migration {
    /// The version this migration brings the component to: 1, 2, 3, ...
    pub version: u64,
    /// The SQLite script.
    pub sqlite: &'static str,
    /// The PostgreSQL script.
    pub postgres: &'static str,
}

/// The migrations of one component, in version order.
#[derive(Clone, Copy, Debug)]
pub struct MigrationSet {
    /// The component's name in `sibuna_schema`.
    pub component: &'static str,
    /// Its migrations, numbered 1, 2, 3, ... without gaps.
    pub migrations: &'static [Migration],
}

impl MigrationSet {
    /// Returns the newest version this set knows (0 when empty).
    pub fn latest(&self) -> u64 {
        self.migrations.last().map_or(0, |migration| migration.version)
    }

    fn is_numbered(&self) -> bool {
        self.migrations
            .iter()
            .zip(1u64..)
            .all(|(migration, expected)| migration.version == expected)
    }
}

/// The key of the PostgreSQL advisory lock that serialises migrations ("sibuna" in ASCII).
const MIGRATION_LOCK: i64 = 0x7369_6275_6e61;

const SCHEMA_TABLE: Sql = Sql::both(
    "CREATE TABLE IF NOT EXISTS sibuna_schema (component TEXT NOT NULL, \
     version BIGINT NOT NULL, applied_at BIGINT NOT NULL, PRIMARY KEY (component, version))",
);
const APPLIED_VERSION: Sql = Sql::both(
    "SELECT CAST(COALESCE(MAX(version), 0) AS BIGINT) FROM sibuna_schema WHERE component = $1",
);
const RECORD_VERSION: Sql =
    Sql::both("INSERT INTO sibuna_schema (component, version, applied_at) VALUES ($1, $2, $3)");
const LOCK: Sql = Sql { sqlite: "SELECT 1", postgres: "SELECT pg_advisory_xact_lock($1)" };

/// Applies every pending migration of `sets` in one transaction and returns.
///
/// Fails with [`StorageError::SchemaTooNew`] when the database records a newer version of a
/// set than the set knows, with [`StorageError::InvalidMigrations`] when a set is not
/// numbered 1, 2, 3, ..., and with the driver's error otherwise; on failure nothing is
/// applied.
pub async fn migrate(db: &Database, sets: &[MigrationSet], now: u64) -> Result<(), StorageError> {
    if let Some(set) = sets.iter().find(|set| !set.is_numbered()) {
        return Err(StorageError::InvalidMigrations(set.component));
    }
    let mut tx = db.begin().await?;
    let dialect = tx.dialect();
    let lock_params: &[Param<'_>] = match dialect {
        Dialect::Sqlite => &[],
        Dialect::Postgres => &[Param::Int(Some(MIGRATION_LOCK))],
    };
    tx.execute(LOCK, lock_params).await?;
    tx.execute(SCHEMA_TABLE, &[]).await?;
    let applied_at = i64::try_from(now).unwrap_or(i64::MAX);
    for set in sets {
        let rows = tx.fetch_all(APPLIED_VERSION, &[set.component.into()]).await?;
        let applied = rows.first().and_then(|row| row.first()).and_then(|cell| cell.as_i64());
        let applied = applied.and_then(|value| u64::try_from(value).ok()).unwrap_or(0);
        if applied > set.latest() {
            return Err(StorageError::SchemaTooNew {
                component: set.component,
                found: applied,
                known: set.latest(),
            });
        }
        for migration in set.migrations.iter().filter(|migration| migration.version > applied) {
            let script = match dialect {
                Dialect::Sqlite => migration.sqlite,
                Dialect::Postgres => migration.postgres,
            };
            tx.execute_script(script).await?;
            let version = i64::try_from(migration.version).unwrap_or(i64::MAX);
            let params = [set.component.into(), version.into(), applied_at.into()];
            tx.execute(RECORD_VERSION, &params).await?;
        }
    }
    tx.commit().await
}

/// The core schema of SID 0011: the tables of SID 0005 with the rule limit column, the
/// inspection override, the incident embedding and full-text search (version 1), and the
/// raw bytes of incident user agents, paths and payloads (version 2).
pub const CORE: MigrationSet = MigrationSet { component: "core", migrations: &CORE_MIGRATIONS };

const CORE_MIGRATIONS: [Migration; 2] = [
    Migration { version: 1, sqlite: SQLITE_V1, postgres: POSTGRES_V1 },
    Migration { version: 2, sqlite: SQLITE_V2, postgres: POSTGRES_V2 },
];

const SQLITE_V1: &str = "
CREATE TABLE sibuna_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO sibuna_meta (key, value) VALUES ('policy_version', '0')
    ON CONFLICT (key) DO NOTHING;
CREATE TABLE policies (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 100,
    path_pattern TEXT, ua_pattern TEXT, action TEXT NOT NULL, difficulty INTEGER,
    algorithm TEXT, header_matchers TEXT, cidr_matchers TEXT,
    weight INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, limit_config TEXT);
CREATE TABLE ip_reputation (
    ip_or_cidr TEXT PRIMARY KEY, reputation_score INTEGER NOT NULL, banned_until INTEGER,
    trigger_rule TEXT, hits INTEGER NOT NULL DEFAULT 1, last_seen INTEGER NOT NULL);
CREATE TABLE policy_inspection (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    path_traversal TEXT NOT NULL CHECK (path_traversal IN ('disabled', 'audit', 'enforce')),
    sqli TEXT NOT NULL CHECK (sqli IN ('disabled', 'audit', 'enforce')),
    xss TEXT NOT NULL CHECK (xss IN ('disabled', 'audit', 'enforce')),
    rce TEXT NOT NULL CHECK (rce IN ('disabled', 'audit', 'enforce')));
CREATE TABLE security_incidents (
    id INTEGER PRIMARY KEY, node_id INTEGER NOT NULL, client_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
    violation_category TEXT NOT NULL, offending_payload TEXT NOT NULL,
    campaign_id INTEGER, recorded_at INTEGER NOT NULL,
    embedding BLOB CHECK (embedding IS NULL OR length(embedding) = 256));
CREATE INDEX security_incidents_recorded ON security_incidents (recorded_at);
CREATE VIRTUAL TABLE incidents_fts USING fts5(
    path, offending_payload, content='security_incidents', content_rowid='id');
CREATE TRIGGER version_policies_insert AFTER INSERT ON policies BEGIN
    UPDATE sibuna_meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'policy_version'; END;
CREATE TRIGGER version_policies_update AFTER UPDATE ON policies BEGIN
    UPDATE sibuna_meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'policy_version'; END;
CREATE TRIGGER version_policies_delete AFTER DELETE ON policies BEGIN
    UPDATE sibuna_meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'policy_version'; END;
CREATE TRIGGER version_ip_reputation_insert AFTER INSERT ON ip_reputation BEGIN
    UPDATE sibuna_meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'policy_version'; END;
CREATE TRIGGER version_ip_reputation_update AFTER UPDATE ON ip_reputation BEGIN
    UPDATE sibuna_meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'policy_version'; END;
CREATE TRIGGER version_ip_reputation_delete AFTER DELETE ON ip_reputation BEGIN
    UPDATE sibuna_meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'policy_version'; END;
CREATE TRIGGER version_policy_inspection_insert AFTER INSERT ON policy_inspection BEGIN
    UPDATE sibuna_meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'policy_version'; END;
CREATE TRIGGER version_policy_inspection_update AFTER UPDATE ON policy_inspection BEGIN
    UPDATE sibuna_meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'policy_version'; END;
CREATE TRIGGER version_policy_inspection_delete AFTER DELETE ON policy_inspection BEGIN
    UPDATE sibuna_meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'policy_version'; END;
";

const POSTGRES_V1: &str = "
CREATE TABLE sibuna_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO sibuna_meta (key, value) VALUES ('policy_version', '0')
    ON CONFLICT (key) DO NOTHING;
CREATE TABLE policies (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, priority BIGINT NOT NULL DEFAULT 100,
    path_pattern TEXT, ua_pattern TEXT, action TEXT NOT NULL, difficulty BIGINT,
    algorithm TEXT, header_matchers TEXT, cidr_matchers TEXT,
    weight BIGINT NOT NULL DEFAULT 0, enabled BIGINT NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, limit_config TEXT);
CREATE TABLE ip_reputation (
    ip_or_cidr TEXT PRIMARY KEY, reputation_score BIGINT NOT NULL, banned_until BIGINT,
    trigger_rule TEXT, hits BIGINT NOT NULL DEFAULT 1, last_seen BIGINT NOT NULL);
CREATE TABLE policy_inspection (
    id BIGINT PRIMARY KEY CHECK (id = 1),
    path_traversal TEXT NOT NULL CHECK (path_traversal IN ('disabled', 'audit', 'enforce')),
    sqli TEXT NOT NULL CHECK (sqli IN ('disabled', 'audit', 'enforce')),
    xss TEXT NOT NULL CHECK (xss IN ('disabled', 'audit', 'enforce')),
    rce TEXT NOT NULL CHECK (rce IN ('disabled', 'audit', 'enforce')));
CREATE TABLE security_incidents (
    id BIGINT PRIMARY KEY, node_id BIGINT NOT NULL, client_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
    violation_category TEXT NOT NULL, offending_payload TEXT NOT NULL,
    campaign_id BIGINT, recorded_at BIGINT NOT NULL,
    embedding BYTEA CHECK (embedding IS NULL OR octet_length(embedding) = 256),
    search tsvector GENERATED ALWAYS AS
        (to_tsvector('simple', path || ' ' || offending_payload)) STORED);
CREATE INDEX security_incidents_recorded ON security_incidents (recorded_at);
CREATE INDEX security_incidents_search ON security_incidents USING GIN (search);
CREATE FUNCTION sibuna_policy_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE sibuna_meta SET value = CAST(CAST(value AS BIGINT) + 1 AS TEXT)
        WHERE key = 'policy_version';
    PERFORM pg_notify('sibuna_policy', '');
    RETURN NULL;
END
$$;
CREATE TRIGGER version_policies AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON policies
    FOR EACH STATEMENT EXECUTE FUNCTION sibuna_policy_revision();
CREATE TRIGGER version_ip_reputation
    AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON ip_reputation
    FOR EACH STATEMENT EXECUTE FUNCTION sibuna_policy_revision();
CREATE TRIGGER version_policy_inspection
    AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON policy_inspection
    FOR EACH STATEMENT EXECUTE FUNCTION sibuna_policy_revision();
";

/// Version 2 on SQLite: the user agent, path and payload become `BLOB` columns holding the
/// captured bytes, and `incidents_fts` holds its own text (a lossy UTF-8 rendering) instead of
/// reading the bytes as external content. SQLite cannot change a declared column type, so
/// the table is rebuilt; stored text becomes its UTF-8 bytes, and the index is refilled from
/// that text, which version 1 already wrote as valid UTF-8 without NUL. No table references
/// `security_incidents` at core version 1, so dropping it breaks no foreign key.
const SQLITE_V2: &str = "
DROP TABLE incidents_fts;
CREATE VIRTUAL TABLE incidents_fts USING fts5(path, offending_payload);
INSERT INTO incidents_fts (rowid, path, offending_payload)
    SELECT id, path, offending_payload FROM security_incidents;
CREATE TABLE security_incidents_v2 (
    id INTEGER PRIMARY KEY, node_id INTEGER NOT NULL, client_ip TEXT NOT NULL,
    user_agent BLOB NOT NULL, method TEXT NOT NULL, path BLOB NOT NULL,
    violation_category TEXT NOT NULL, offending_payload BLOB NOT NULL,
    campaign_id INTEGER, recorded_at INTEGER NOT NULL,
    embedding BLOB CHECK (embedding IS NULL OR length(embedding) = 256));
INSERT INTO security_incidents_v2 (id, node_id, client_ip, user_agent, method, path,
        violation_category, offending_payload, campaign_id, recorded_at, embedding)
    SELECT id, node_id, client_ip, CAST(user_agent AS BLOB), method, CAST(path AS BLOB),
        violation_category, CAST(offending_payload AS BLOB), campaign_id, recorded_at, embedding
    FROM security_incidents;
DROP TABLE security_incidents;
ALTER TABLE security_incidents_v2 RENAME TO security_incidents;
CREATE INDEX security_incidents_recorded ON security_incidents (recorded_at);
";

/// Version 2 on PostgreSQL: the user agent, path and payload become `BYTEA` holding the
/// captured bytes, and the generated `tsvector` reads the new text column `search_text` (a
/// lossy UTF-8 rendering of path and payload). The generated column depends on the columns
/// whose type changes, so it is dropped (with its index) and added again.
const POSTGRES_V2: &str = "
ALTER TABLE security_incidents DROP COLUMN search;
ALTER TABLE security_incidents ADD COLUMN search_text TEXT NOT NULL DEFAULT '';
UPDATE security_incidents SET search_text = path || ' ' || offending_payload;
ALTER TABLE security_incidents
    ALTER COLUMN search_text DROP DEFAULT,
    ALTER COLUMN user_agent TYPE BYTEA USING convert_to(user_agent, 'UTF8'),
    ALTER COLUMN path TYPE BYTEA USING convert_to(path, 'UTF8'),
    ALTER COLUMN offending_payload TYPE BYTEA USING convert_to(offending_payload, 'UTF8');
ALTER TABLE security_incidents ADD COLUMN search tsvector
    GENERATED ALWAYS AS (to_tsvector('simple', search_text)) STORED;
CREATE INDEX security_incidents_search ON security_incidents USING GIN (search);
";
