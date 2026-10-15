//! The harness of the console storage tests: every test runs on SQLite and, when
//! `SIBUNA_TEST_DATABASE_URL` names a PostgreSQL database, on PostgreSQL too, each time on
//! a fresh, fully migrated schema of its own.
//!
//! `sibuna-storage` keeps its own `testing::for_each_backend` private for now (SID 0013
//! plans to export it), so this file provides the equivalent. It needs a tokio runtime but
//! may not depend on tokio, so it borrows the storage thread's runtime: it starts a real
//! `Storage` on a temporary SQLite file with the console migrations in `Hooks`, and runs the
//! test inside `Storage::with_database`. The SQLite test uses that database; the PostgreSQL
//! test opens its own pool, on a schema named after the test, from inside the same job.
//!
//! A test body is an async closure taking the `Database`; it panics on failure. A panic is
//! caught on the storage thread and re-raised on the test thread with the backend's name.

#![allow(dead_code)]

use std::any::Any;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll};

use sibuna_console_protocol::auth::{Factor, Session};
use sibuna_console_protocol::{CredentialKind, Role, Text, auth, users};
use sibuna_console_storage::{CONSOLE, Credential, accounts};
use sibuna_core::Config;
use sibuna_storage::schema::{CORE, migrate};
use sibuna_storage::{
    Cell, Database, Dialect, Hooks, Sql, Storage, StorageError, Target, Transaction,
};

/// The environment variable naming a PostgreSQL database whose role may create schemas.
pub const POSTGRES_ENV: &str = "SIBUNA_TEST_DATABASE_URL";
/// The time the tests run at, in Unix seconds (2027-01-15).
pub const NOW: u64 = 1_800_000_000;

/// Serialises the tests of one test binary, so that at most one test holds PostgreSQL
/// connections at a time (several agents and binaries share one server).
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Runs `test` on a fresh SQLite database and, when [`POSTGRES_ENV`] is set and the crate
/// is built with `postgres`, on a fresh PostgreSQL schema named after `name`.
pub fn for_each_backend<F, Fut>(name: &str, test: F)
where
    F: Fn(Database) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let postgres = std::env::var(POSTGRES_ENV).ok().filter(|_| cfg!(feature = "postgres"));
    let dir = std::env::temp_dir().join(format!("sibuna-cstore-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let Some(storage) = start_host(&dir, postgres.as_deref()) else { return };
    if cfg!(feature = "sqlite") {
        let sqlite_test = test.clone();
        let outcome = storage.with_database(move |db| async move {
            // The host already applied both sets; applying them again must change nothing.
            migrate(&db, &[CORE, CONSOLE], NOW).await?;
            Ok(CatchUnwind(Box::pin(sqlite_test(db))).await)
        });
        report(name, "SQLite", outcome);
    }
    if let Some(base) = postgres {
        let schema = schema_name(name);
        let outcome = storage.with_database(move |_| run_postgres(base, schema, test));
        report(name, "PostgreSQL", outcome);
    }
    drop(storage);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Starts the storage thread whose runtime runs the tests: on a temporary SQLite file with
/// the console migrations in `Hooks`, or, in a build without SQLite, on the PostgreSQL test
/// database itself (whose default schema then holds the core tables; the tests use schemas
/// of their own). Returns `None` when no backend is available.
fn start_host(dir: &std::path::Path, postgres: Option<&str>) -> Option<Storage> {
    let (config, hooks) = if cfg!(feature = "sqlite") {
        let data_dir = Some(dir.to_string_lossy().into_owned());
        let hooks = Hooks { migrations: vec![CONSOLE], ..Hooks::default() };
        (Config { data_dir, ..Config::default() }, hooks)
    } else {
        let database_url = Some(postgres?.to_owned());
        (Config { database_url, ..Config::default() }, Hooks::default())
    };
    Some(Storage::start(&config, hooks).expect("start the storage thread"))
}

async fn run_postgres<F, Fut>(
    base: String,
    schema: String,
    test: F,
) -> Result<Result<(), String>, StorageError>
where
    F: Fn(Database) -> Fut,
    Fut: Future<Output = ()> + 'static,
{
    let admin = Database::open(&Target::Postgres(base.clone())).await?;
    let script = format!("DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema}");
    admin.execute_script(&script).await?;
    admin.close().await;
    let db = Database::open(&Target::Postgres(with_search_path(&base, &schema))).await?;
    migrate(&db, &[CORE, CONSOLE], NOW).await?;
    migrate(&db, &[CORE, CONSOLE], NOW).await?;
    let outcome = CatchUnwind(Box::pin(test(db.clone()))).await;
    db.close().await;
    let admin = Database::open(&Target::Postgres(base)).await?;
    admin.execute_script(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE")).await?;
    admin.close().await;
    Ok(outcome)
}

fn report(name: &str, backend: &str, outcome: Result<Result<(), String>, StorageError>) {
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(message)) => panic!("{name} failed on {backend}: {message}"),
        Err(error) => panic!("{name} could not run on {backend}: {error:?}"),
    }
}

/// A schema name of at most 63 bytes, unique per process and test.
fn schema_name(name: &str) -> String {
    let mut schema = format!("cs_{}_{name}", std::process::id());
    schema.truncate(63);
    schema
}

/// Returns `base` with `search_path` set to `schema` for every connection.
fn with_search_path(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-c%20search_path%3D{schema}")
}

/// Polls a test body, turning a panic into an error message so the storage thread survives.
struct CatchUnwind<F>(Pin<Box<F>>);

impl<F: Future<Output = ()>> Future for CatchUnwind<F> {
    type Output = Result<(), String>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = &mut self.get_mut().0;
        match std::panic::catch_unwind(AssertUnwindSafe(|| inner.as_mut().poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(())) => Poll::Ready(Ok(())),
            Err(payload) => Poll::Ready(Err(panic_message(payload))),
        }
    }
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => payload.downcast_ref::<&str>().map_or("panic", |s| s).to_owned(),
    }
}

/// Returns the scratch directory of a test, for tests that need files.
pub fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("sibuna-cstore-scratch-{}-{name}", std::process::id()))
}

// ---- Fixtures --------------------------------------------------------------------------

/// Returns 32 bytes of `byte`, a stand-in for a digest.
pub fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Creates the bootstrap administrator `admin` and returns its id.
pub async fn bootstrap_admin(tx: &mut Transaction) -> u64 {
    let input = auth::Bootstrap {
        username: Text::new("admin").expect("name"),
        password_hash: Text::new("$argon2id$admin").expect("hash"),
        must_change: false,
        password_expires: 0,
    };
    accounts::bootstrap(tx, &input, NOW).await.expect("bootstrap").id
}

/// Signs `user` in at `revision` with a session whose cookie digest is `digest(byte)` and
/// whose CSRF digest is `digest(byte + 1)`, and returns the cookie credential.
pub async fn sign_in(tx: &mut Transaction, user: u64, revision: u64, byte: u8) -> Credential {
    let session = Session {
        factor: Factor::None,
        user,
        revision,
        digest: digest(byte),
        csrf_digest: digest(byte.wrapping_add(1)),
        expires: NOW + 43_200,
        client: Text::new("192.0.2.1").expect("client"),
        agent_digest: Text::default(),
    };
    accounts::insert_session(tx, &session, NOW).await.expect("sign in");
    cookie(byte)
}

/// Returns the cookie credential of the session [`sign_in`] made with `byte`.
pub fn cookie(byte: u8) -> Credential {
    Credential {
        kind: CredentialKind::Session,
        digest: digest(byte),
        csrf_digest: digest(byte.wrapping_add(1)),
        require_totp: false,
        client: Some("192.0.2.1".into()),
    }
}

/// Returns the protocol's management credential block matching [`cookie`].
pub fn auth_block(byte: u8) -> users::Auth {
    users::Auth {
        session_digest: digest(byte),
        csrf_digest: digest(byte.wrapping_add(1)),
        require_totp: false,
        client: Text::new("192.0.2.1").expect("client"),
    }
}

/// Creates an account named `name` with `role` through the administrator `admin`, then
/// clears its temporary password state directly, and returns its id.
pub async fn create_account(
    tx: &mut Transaction,
    admin: &Credential,
    name: &str,
    role: Role,
) -> u64 {
    let input = users::Create {
        auth: users::Auth::default(),
        username: Text::new(name).expect("name"),
        role,
        password_hash: Text::new("$argon2id$user").expect("hash"),
    };
    let saved = accounts::create_user(tx, admin, &input, NOW).await.expect("create account");
    tx.execute(
        Sql::both(
            "UPDATE console_users SET must_change = FALSE, password_expires_at = NULL \
             WHERE id = $1",
        ),
        &[i64::try_from(saved.id).expect("id").into()],
    )
    .await
    .expect("clear temporary password");
    saved.id
}

/// One audit row as tests compare it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Audited {
    pub id: i64,
    pub action: String,
    pub actor: Option<i64>,
    pub actor_role: Option<String>,
    pub subject: Option<i64>,
    pub target: Option<String>,
    pub client_ip: Option<String>,
}

/// Returns every audit row, oldest first.
pub async fn audit_rows(tx: &mut Transaction) -> Vec<Audited> {
    let sql = Sql::both(
        "SELECT id, action, actor, actor_role, subject, target, client_ip \
         FROM console_audit ORDER BY id",
    );
    let rows = tx.fetch_all(sql, &[]).await.expect("audit rows");
    rows.into_iter()
        .map(|row| Audited {
            id: int(&row[0]),
            action: text(&row[1]),
            actor: row[2].as_i64(),
            actor_role: row[3].as_str().map(str::to_owned),
            subject: row[4].as_i64(),
            target: row[5].as_str().map(str::to_owned),
            client_ip: row[6].as_str().map(str::to_owned),
        })
        .collect()
}

/// Returns the actions of every audit row, oldest first.
pub async fn audit_actions(tx: &mut Transaction) -> Vec<String> {
    audit_rows(tx).await.into_iter().map(|row| row.action).collect()
}

/// Returns the summary columns of audit row `id` as compact text.
pub async fn summaries(tx: &mut Transaction, id: i64) -> (Option<String>, Option<String>) {
    let sql = Sql {
        sqlite: "SELECT before_summary, after_summary FROM console_audit WHERE id = $1",
        postgres: "SELECT CAST(before_summary AS TEXT), CAST(after_summary AS TEXT) \
                   FROM console_audit WHERE id = $1",
    };
    let rows = tx.fetch_all(sql, &[id.into()]).await.expect("summaries");
    let row = rows.into_iter().next().expect("one audit row");
    (row[0].as_str().map(compact), row[1].as_str().map(compact))
}

/// Returns a stored JSON document without insignificant white space, so tests compare
/// SQLite's text and PostgreSQL's `JSONB` rendering (`{"a": 1}`) alike.
pub fn compact(json: &str) -> String {
    let value = sibuna_json::parse(json.as_bytes()).expect("stored JSON");
    let mut writer = sibuna_json::Writer::new(String::new());
    writer.value(&value).expect("write JSON");
    writer.into_inner()
}

/// Returns the single integer `sql` yields.
pub async fn scalar(tx: &mut Transaction, sql: &'static str) -> i64 {
    let rows = tx.fetch_all(Sql::both(sql), &[]).await.expect(sql);
    rows.first().and_then(|row| row.first()).and_then(Cell::as_i64).expect(sql)
}

/// Returns the integer a cell holds; panics otherwise.
pub fn int(cell: &Cell) -> i64 {
    cell.as_i64().expect("an integer cell")
}

/// Returns the text a cell holds; panics otherwise.
pub fn text(cell: &Cell) -> String {
    cell.as_str().expect("a text cell").to_owned()
}

// ---- Literals for direct writes ----------------------------------------------------------

/// Returns a byte-string literal of `len` bytes of `byte` in the dialect of `db`.
pub fn bytes(dialect: Dialect, len: usize, byte: u8) -> String {
    let hex = format!("{byte:02x}").repeat(len);
    match dialect {
        Dialect::Sqlite => format!("X'{hex}'"),
        Dialect::Postgres => format!("'\\x{hex}'::bytea"),
    }
}

/// Inserts one row into `table` with `columns` set to the literal SQL `values`, outside any
/// transaction, as an operator writing SQL directly would.
pub async fn insert(
    db: &Database,
    table: &str,
    values: &[(&str, String)],
) -> Result<(), StorageError> {
    let columns: Vec<&str> = values.iter().map(|(column, _)| *column).collect();
    let literals: Vec<&str> = values.iter().map(|(_, value)| value.as_str()).collect();
    let sql =
        format!("INSERT INTO {table} ({}) VALUES ({})", columns.join(", "), literals.join(", "));
    db.execute_script(&sql).await
}

// ---- Concurrency ---------------------------------------------------------------------------

/// Runs two futures concurrently on the current task and returns both outputs. Each await
/// of one (a statement on its own connection) lets the other run, so two transactions
/// interleave as two nodes' transactions would.
pub async fn join<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output)
where
    A::Output: Unpin,
    B::Output: Unpin,
{
    Join { a: Box::pin(a), b: Box::pin(b), a_out: None, b_out: None }.await
}

struct Join<A: Future, B: Future> {
    a: Pin<Box<A>>,
    b: Pin<Box<B>>,
    a_out: Option<A::Output>,
    b_out: Option<B::Output>,
}

impl<A: Future, B: Future> Future for Join<A, B>
where
    A::Output: Unpin,
    B::Output: Unpin,
{
    type Output = (A::Output, B::Output);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // The futures are boxed and the outputs `Unpin`, so the struct is `Unpin`.
        let this = self.get_mut();
        if this.a_out.is_none()
            && let Poll::Ready(out) = this.a.as_mut().poll(cx)
        {
            this.a_out = Some(out);
        }
        if this.b_out.is_none()
            && let Poll::Ready(out) = this.b.as_mut().poll(cx)
        {
            this.b_out = Some(out);
        }
        match (this.a_out.take(), this.b_out.take()) {
            (Some(a), Some(b)) => Poll::Ready((a, b)),
            (a, b) => {
                this.a_out = a;
                this.b_out = b;
                Poll::Pending
            }
        }
    }
}
