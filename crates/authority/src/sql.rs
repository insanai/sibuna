//! The store in SQLite or PostgreSQL, over the dialect-neutral database of SID 0011.
//!
//! ```text
//!   caller thread                       SqlStore
//!   -------------                       --------
//!   head / revision / commit ...  -->   connect if needed (read the URL file, open,
//!                                       migrate for the operator, probe for a node)
//!                                       run the statements on a current-thread runtime
//!                                       unreachable? drop the connections, say so
//!   wait(timeout)                 -->   the LISTEN task wakes it on PostgreSQL
//! ```
//!
//! One revision is one row, so a read returns it whole. The commit is one transaction:
//! it moves the head from the expected number to the next and inserts the row. Every
//! statement is written once. Only the schema differs between the dialects.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sibuna_storage::schema::{self, Migration, MigrationSet};
use sibuna_storage::{Columns, Database, Dialect, Param, Sql, StorageError};
use tokio::sync::Notify;

use crate::error::Error;
use crate::settings::Settings;
use crate::store::{
    Draft, Entry, Head, MAX_DETAIL, MAX_HISTORY, MAX_NODES, NodeReport, Origin, Revision, Store,
    Woken, clip,
};

/// The channel on which PostgreSQL announces a new head.
pub const CHANNEL: &str = "sibuna_edge";

/// How long closing the connections may take.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// The tables of SID 0028, as the component `authority` of `sibuna_schema`.
pub const SCHEMA: MigrationSet = MigrationSet { component: "authority", migrations: &MIGRATIONS };

const MIGRATIONS: [Migration; 1] =
    [Migration { version: 1, sqlite: SQLITE_V1, postgres: POSTGRES_V1 }];

const SQLITE_V1: &str = "
CREATE TABLE edge_head (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL CHECK (revision >= 0)) STRICT;
INSERT INTO edge_head (id, revision) VALUES (1, 0);

CREATE TABLE edge_revisions (
    revision INTEGER PRIMARY KEY CHECK (revision >= 1),
    origin TEXT NOT NULL CHECK (origin IN ('apply', 'rollback')),
    restored INTEGER CHECK ((origin = 'rollback') = (restored IS NOT NULL)
        AND (restored IS NULL OR restored BETWEEN 1 AND revision - 1)),
    document TEXT NOT NULL CHECK (length(document) BETWEEN 2 AND 262144),
    digest TEXT NOT NULL CHECK (length(digest) = 64),
    source BLOB NOT NULL CHECK (length(source) <= 262144),
    source_name TEXT NOT NULL CHECK (length(source_name) <= 128),
    source_digest TEXT NOT NULL CHECK (length(source_digest) = 64),
    author TEXT NOT NULL CHECK (length(author) <= 128),
    note TEXT NOT NULL CHECK (length(note) <= 200),
    committed_at INTEGER NOT NULL CHECK (committed_at >= 0)) STRICT;

CREATE TABLE edge_nodes (
    node TEXT NOT NULL PRIMARY KEY CHECK (length(node) BETWEEN 1 AND 64),
    applied INTEGER NOT NULL CHECK (applied >= 0),
    digest TEXT NOT NULL CHECK (length(digest) <= 64),
    refused INTEGER NOT NULL CHECK (refused >= 0),
    detail TEXT NOT NULL CHECK (length(detail) <= 300),
    seen_at INTEGER NOT NULL CHECK (seen_at >= 0)) STRICT;
";

const POSTGRES_V1: &str = "
CREATE TABLE edge_head (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision BIGINT NOT NULL CHECK (revision >= 0));
INSERT INTO edge_head (id, revision) VALUES (1, 0);

CREATE TABLE edge_revisions (
    revision BIGINT PRIMARY KEY CHECK (revision >= 1),
    origin TEXT NOT NULL CHECK (origin IN ('apply', 'rollback')),
    restored BIGINT CHECK ((origin = 'rollback') = (restored IS NOT NULL)
        AND (restored IS NULL OR restored BETWEEN 1 AND revision - 1)),
    document TEXT NOT NULL CHECK (octet_length(document) BETWEEN 2 AND 262144),
    digest TEXT NOT NULL CHECK (octet_length(digest) = 64),
    source BYTEA NOT NULL CHECK (octet_length(source) <= 262144),
    source_name TEXT NOT NULL CHECK (octet_length(source_name) <= 128),
    source_digest TEXT NOT NULL CHECK (octet_length(source_digest) = 64),
    author TEXT NOT NULL CHECK (octet_length(author) <= 128),
    note TEXT NOT NULL CHECK (octet_length(note) <= 200),
    committed_at BIGINT NOT NULL CHECK (committed_at >= 0));

CREATE TABLE edge_nodes (
    node TEXT NOT NULL PRIMARY KEY CHECK (octet_length(node) BETWEEN 1 AND 64),
    applied BIGINT NOT NULL CHECK (applied >= 0),
    digest TEXT NOT NULL CHECK (octet_length(digest) <= 64),
    refused BIGINT NOT NULL CHECK (refused >= 0),
    detail TEXT NOT NULL CHECK (octet_length(detail) <= 300),
    seen_at BIGINT NOT NULL CHECK (seen_at >= 0));

CREATE FUNCTION sibuna_edge_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('sibuna_edge', '');
    RETURN NULL;
END $$;
CREATE TRIGGER edge_head_revision AFTER UPDATE ON edge_head
    FOR EACH STATEMENT EXECUTE FUNCTION sibuna_edge_revision();
";

const HAS_TABLES: Sql = Sql {
    sqlite: "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'edge_head'",
    postgres: "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'edge_head' \
               AND table_schema = ANY (current_schemas(false))",
};
const SCHEMA_VERSION: Sql = Sql::both(
    "SELECT CAST(COALESCE(MAX(version), 0) AS BIGINT) FROM sibuna_schema \
     WHERE component = 'authority'",
);
const HEAD: Sql = Sql::both(
    "SELECT h.revision, COALESCE(r.digest, '') FROM edge_head h \
     LEFT JOIN edge_revisions r ON r.revision = h.revision WHERE h.id = 1",
);
const HEAD_NUMBER: Sql = Sql::both("SELECT revision FROM edge_head WHERE id = 1");
const MOVE_HEAD: Sql =
    Sql::both("UPDATE edge_head SET revision = $1 WHERE id = 1 AND revision = $2");
const INSERT_REVISION: Sql = Sql::both(
    "INSERT INTO edge_revisions (revision, origin, restored, document, digest, source, \
     source_name, source_digest, author, note, committed_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
);
const READ_REVISION: Sql = Sql::both(
    "SELECT revision, origin, restored, digest, source_name, source_digest, author, note, \
     committed_at, document, source FROM edge_revisions WHERE revision = $1",
);
const READ_HISTORY: Sql = Sql::both(
    "SELECT revision, origin, restored, digest, source_name, source_digest, author, note, \
     committed_at FROM edge_revisions ORDER BY revision DESC LIMIT $1",
);
const WRITE_REPORT: Sql = Sql::both(
    "INSERT INTO edge_nodes (node, applied, digest, refused, detail, seen_at) \
     VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (node) DO UPDATE SET \
     applied = excluded.applied, digest = excluded.digest, refused = excluded.refused, \
     detail = excluded.detail, seen_at = excluded.seen_at",
);
const READ_NODES: Sql = Sql::both(
    "SELECT node, applied, digest, refused, detail, seen_at FROM edge_nodes \
     ORDER BY node LIMIT $1",
);

/// What the holder of a store may do to the schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// A command of the operator: it creates and migrates the tables.
    Operator,
    /// A node: it reads the tables and writes its report. It never changes the schema.
    Node,
}

/// Wakes the thread that waits in [`Store::wait`] of the store it came from.
#[derive(Clone)]
pub struct Waker(Arc<Notify>);

impl Waker {
    /// Ends the current wait, or the next one when nobody waits now.
    pub fn wake(&self) {
        self.0.notify_one();
    }
}

/// A failure inside one operation: of the database, or of the authority itself.
enum Failure {
    Storage(StorageError),
    Authority(Error),
}

impl From<StorageError> for Failure {
    fn from(error: StorageError) -> Failure {
        Failure::Storage(error)
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Failure {
        Failure::Authority(error)
    }
}

/// The open database and the task that listens for commits.
struct Link {
    db: Database,
    listener: Option<tokio::task::JoinHandle<()>>,
}

/// The store in SQLite or PostgreSQL. It connects at its first use and again after the
/// database was unreachable. One thread owns it.
pub struct SqlStore {
    runtime: tokio::runtime::Runtime,
    settings: Settings,
    access: Access,
    wake: Arc<Notify>,
    link: Option<Link>,
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

fn int(value: u64) -> Result<i64, Failure> {
    i64::try_from(value)
        .map_err(|_| Failure::Authority(Error::Rejected(format!("{value} is out of range"))))
}

impl SqlStore {
    /// A store for the database that `settings` names. It does not connect yet. Fails
    /// with [`Error::Unavailable`] when the runtime of the store cannot be built.
    pub fn new(settings: &Settings, access: Access) -> Result<SqlStore, Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::Unavailable(format!("no runtime for the store: {error}")))?;
        let wake = Arc::new(Notify::new());
        Ok(SqlStore { runtime, settings: settings.clone(), access, wake, link: None })
    }

    /// A handle that ends a wait of this store from another thread.
    pub fn waker(&self) -> Waker {
        Waker(Arc::clone(&self.wake))
    }

    /// Opens the database when it is not open. The operator migrates the tables. A node
    /// only looks whether they are there and whether it knows their version.
    fn connect(&mut self) -> Result<(), Error> {
        if self.link.is_some() {
            return Ok(());
        }
        let target = self.settings.target()?;
        let (access, wake) = (self.access, Arc::clone(&self.wake));
        let opened: Result<Link, Failure> = self.runtime.block_on(async {
            let db = Database::open(&target).await?;
            let prepared = match access {
                Access::Operator => {
                    schema::migrate(&db, &[SCHEMA], unix_now()).await.map_err(Failure::from)
                }
                Access::Node => probe(&db).await,
            };
            if let Err(failure) = prepared {
                db.close().await;
                return Err(failure);
            }
            let listener = sibuna_storage::subscribe(&db, CHANNEL, move || wake.notify_one());
            Ok(Link { db, listener })
        });
        match opened {
            Ok(link) => {
                self.link = Some(link);
                Ok(())
            }
            Err(Failure::Authority(error)) => Err(error),
            Err(Failure::Storage(StorageError::SchemaTooNew { found, known, .. })) => {
                Err(too_new(found, known))
            }
            Err(Failure::Storage(error)) => Err(Error::Unavailable(error.to_string())),
        }
    }

    /// Closes the connections. The next operation opens them again.
    fn disconnect(&mut self) {
        let Some(link) = self.link.take() else { return };
        if let Some(listener) = &link.listener {
            listener.abort();
        }
        self.runtime.block_on(async {
            let _ = tokio::time::timeout(CLOSE_TIMEOUT, link.db.close()).await;
        });
    }

    /// Runs one operation on the open database. A failure that a later attempt may not
    /// have closes the connections, so that the next operation connects anew.
    fn run<T>(
        &mut self,
        operation: impl AsyncFnOnce(&Database) -> Result<T, Failure>,
    ) -> Result<T, Error> {
        self.connect()?;
        let Some(link) = &self.link else {
            return Err(Error::Unavailable("the database is not open".to_owned()));
        };
        match self.runtime.block_on(operation(&link.db)) {
            Ok(value) => Ok(value),
            Err(Failure::Authority(error)) => Err(error),
            Err(Failure::Storage(error @ StorageError::InvalidRow { .. })) => {
                Err(Error::Damaged(error.to_string()))
            }
            Err(Failure::Storage(error)) => {
                if error.is_transient() {
                    self.disconnect();
                }
                Err(Error::Unavailable(error.to_string()))
            }
        }
    }
}

impl Drop for SqlStore {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// The failure of a binary that is older than the tables.
fn too_new(found: u64, known: u64) -> Error {
    Error::Unavailable(format!(
        "the tables have version {found} and this binary knows version {known}"
    ))
}

/// What a node does in the place of a migration: it fails with [`Error::Empty`] when
/// the tables are absent, and when they are newer than this binary knows.
async fn probe(db: &Database) -> Result<(), Failure> {
    let count = |rows: Vec<Vec<sibuna_storage::Cell>>| {
        rows.first().and_then(|row| row.first()).and_then(sibuna_storage::Cell::as_i64)
    };
    if count(db.fetch_all(HAS_TABLES, &[]).await?).unwrap_or(0) == 0 {
        return Err(Error::Empty.into());
    }
    let found = count(db.fetch_all(SCHEMA_VERSION, &[]).await?).unwrap_or(0).max(0) as u64;
    if found > SCHEMA.latest() {
        return Err(too_new(found, SCHEMA.latest()).into());
    }
    Ok(())
}

/// Reads the columns that every listing of revisions selects first.
fn entry(columns: &mut Columns) -> Result<Entry, StorageError> {
    let number = columns.integer("revision")?;
    let origin = columns.text("origin")?;
    let restored: Option<u64> = columns.optional_integer("restored")?;
    let origin = match (origin.as_str(), restored) {
        ("apply", None) => Origin::Apply,
        ("rollback", Some(restored)) => Origin::Rollback(restored),
        _ => return Err(columns.invalid("origin")),
    };
    Ok(Entry {
        number,
        origin,
        digest: columns.text("digest")?,
        source_name: columns.text("source_name")?,
        source_digest: columns.text("source_digest")?,
        author: columns.text("author")?,
        note: columns.text("note")?,
        committed_at: columns.integer("committed_at")?,
    })
}

async fn head(db: &Database) -> Result<Head, Failure> {
    let row = db.fetch_all(HEAD, &[]).await?.into_iter().next();
    let Some(row) = row else {
        return Err(Error::Damaged("the table edge_head has no row".to_owned()).into());
    };
    let mut columns = Columns::new(row, "edge_head");
    Ok(Head { revision: columns.integer("revision")?, digest: columns.text("digest")? })
}

async fn revision(db: &Database, number: u64) -> Result<Revision, Failure> {
    let row = db.fetch_all(READ_REVISION, &[int(number)?.into()]).await?.into_iter().next();
    let Some(row) = row else { return Err(Error::Unknown(number).into()) };
    let mut columns = Columns::new(row, "edge_revisions");
    let entry = entry(&mut columns)?;
    let revision =
        Revision { entry, document: columns.text("document")?, source: columns.bytes("source")? };
    revision.verify(number)?;
    Ok(revision)
}

async fn commit(db: &Database, expected: u64, draft: &Draft<'_>) -> Result<u64, Failure> {
    let next = expected.checked_add(1).ok_or(Error::Conflict { expected, found: 0 })?;
    let committed = Revision::from_draft(next, draft);
    let (origin, restored) = match draft.origin {
        Origin::Apply => ("apply", None),
        Origin::Rollback(restored) => ("rollback", Some(int(restored)?)),
    };
    let mut tx = db.begin().await?;
    // The row of the head is the lock. A second writer waits here, then changes no row.
    if tx.execute(MOVE_HEAD, &[int(next)?.into(), int(expected)?.into()]).await? != 1 {
        let row = tx.fetch_all(HEAD_NUMBER, &[]).await?.into_iter().next();
        let found = match row {
            Some(row) => Columns::new(row, "edge_head").integer("revision")?,
            None => 0,
        };
        return Err(Error::Conflict { expected, found }.into());
    }
    let params = [
        int(next)?.into(),
        origin.into(),
        Param::Int(restored),
        draft.document.into(),
        committed.entry.digest.as_str().into(),
        draft.source.into(),
        draft.source_name.into(),
        committed.entry.source_digest.as_str().into(),
        draft.author.into(),
        draft.note.into(),
        int(draft.now)?.into(),
    ];
    tx.execute(INSERT_REVISION, &params).await?;
    tx.commit().await?;
    Ok(next)
}

async fn history(db: &Database, limit: usize) -> Result<Vec<Entry>, Failure> {
    let limit = limit.min(MAX_HISTORY) as i64;
    let rows = db.fetch_all(READ_HISTORY, &[limit.into()]).await?;
    let entries = rows.into_iter().map(|row| entry(&mut Columns::new(row, "edge_revisions")));
    Ok(entries.collect::<Result<_, _>>()?)
}

async fn report(db: &Database, report: &NodeReport) -> Result<(), Failure> {
    let detail = clip(&report.detail, MAX_DETAIL);
    let params = [
        report.node.as_str().into(),
        int(report.applied)?.into(),
        report.digest.as_str().into(),
        int(report.refused)?.into(),
        detail.as_str().into(),
        int(report.seen_at)?.into(),
    ];
    db.execute(WRITE_REPORT, &params).await?;
    Ok(())
}

async fn nodes(db: &Database) -> Result<Vec<NodeReport>, Failure> {
    let rows = db.fetch_all(READ_NODES, &[(MAX_NODES as i64).into()]).await?;
    let mut reports = Vec::with_capacity(rows.len());
    for row in rows {
        let mut columns = Columns::new(row, "edge_nodes");
        reports.push(NodeReport {
            node: columns.text("node")?,
            applied: columns.integer("applied")?,
            digest: columns.text("digest")?,
            refused: columns.integer("refused")?,
            detail: columns.text("detail")?,
            seen_at: columns.integer("seen_at")?,
        });
    }
    Ok(reports)
}

impl Store for SqlStore {
    fn head(&mut self) -> Result<Head, Error> {
        self.run(head)
    }

    fn revision(&mut self, number: u64) -> Result<Revision, Error> {
        self.run(async |db| revision(db, number).await)
    }

    fn commit(&mut self, expected: u64, draft: &Draft<'_>) -> Result<u64, Error> {
        draft.check()?;
        self.run(async |db| commit(db, expected, draft).await)
    }

    fn history(&mut self, limit: usize) -> Result<Vec<Entry>, Error> {
        self.run(async |db| history(db, limit).await)
    }

    fn report(&mut self, node: &NodeReport) -> Result<(), Error> {
        self.run(async |db| report(db, node).await)
    }

    fn nodes(&mut self) -> Result<Vec<NodeReport>, Error> {
        self.run(nodes)
    }

    fn wait(&mut self, timeout: Duration) -> Woken {
        let wake = Arc::clone(&self.wake);
        let waited =
            self.runtime.block_on(async { tokio::time::timeout(timeout, wake.notified()).await });
        if waited.is_ok() { Woken::Notified } else { Woken::TimedOut }
    }
}

/// The dialect of the open database, for the tests that state which backend ran.
impl SqlStore {
    /// Whether the store is connected to PostgreSQL. `None` before the first use.
    pub fn is_postgres(&self) -> Option<bool> {
        self.link.as_ref().map(|link| link.db.dialect() == Dialect::Postgres)
    }
}
