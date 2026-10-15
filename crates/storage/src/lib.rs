//! Sibuna's persistent layer (SID 0011): dynamic policies, IP reputation and incident
//! forensics in SQLite (one node, `--data-dir`) or PostgreSQL (a cluster,
//! `--database-url`), through `sqlx`.
//!
//! The request path never waits on the database. One storage thread owns a current-thread
//! tokio runtime and the connection pool:
//!
//! ```text
//!  request threads                         storage thread (tokio, one pool)
//!  ---------------                         --------------------------------
//!  Storage::record_incident --> ring of 512 --> every --storage-poll-ms:
//!       (copy, never blocks;                     1. write up to 32 incidents in one
//!        full ring drops + counts)                  transaction, receipt-guarded
//!                                                2. revision changed or ban expired?
//!  daemon <-- Hooks::publish(PolicySnapshot) <--    load rows, re-check revision, publish
//!                                                3. Hooks::on_tick (the console's work)
//! ```
//!
//! - [`Storage::start`] opens the configured [`Database`], applies the numbered
//!   [`schema`] migrations, loads the incident receipt and the campaign window, publishes
//!   the first [`PolicySnapshot`] and starts the thread. [`Storage::shutdown`] flushes and
//!   stops it.
//! - [`Storage::submit`] queues other work (bans, searches, the console's queries) for the
//!   storage thread and returns a [`Ticket`] at once; [`Storage::with_database`] submits and
//!   waits. [`Storage::ban_address`] and [`Storage::search_incidents`] are the common cases.
//! - [`Database`] is a dialect-neutral handle: statements take [`Param`]s bound to `$1`,
//!   `$2`, ... and return rows of owned [`Cell`]s, so every query is written once and only
//!   SQL text that differs between dialects is written twice ([`Sql`]). Each table the
//!   storage layer reads has one row struct ([`PolicyRow`], [`InspectionRow`],
//!   [`ReputationRow`], [`IncidentReceipt`], [`IncidentHit`]) decoded by one function with a
//!   [`Columns`] reader, and each enumerated column one enum ([`PolicyAction`],
//!   [`ChallengeAlgorithm`], [`InspectionMode`]) whose `as_str` binds and whose `parse`
//!   decodes.
//! - The [`schema`] is typed (SID 0011, "Schema and migrations"): `STRICT` tables on SQLite,
//!   `CHECK` constraints that mirror the Rust types, and an index for every query, so the
//!   database refuses a row the row structs could not hold.
//! - [`read_database_url_file`] reads `--database-url-file`.
//! - [`tls`] reads libpq's `sslmode` and `sslrootcert` from the URL, says what protects the
//!   connection ([`Protection`]) and refuses a mode that needs TLS in a build without the
//!   `postgres-tls` feature, which enables sqlx's rustls client with ring and the system
//!   trust store (SID 0012).
//! - [`search`] is the search language of SID 0013: canonical tokens, which the incident
//!   writer indexes, and queries translated for both backends, which
//!   [`Database::search_incidents`] and the console's Events page evaluate.
//! - For the console (SID 0013, "Changes to the core storage"; SID 0011, revision of
//!   2026-10-15): [`Hooks::on_incidents`] writes the incident sidecars in the batch's
//!   transaction, [`Hooks::on_committed`] hears about each batch once it is confirmed
//!   committed, [`Hooks::on_snapshot`] reads the page templates into
//!   [`PolicySnapshot::pages`], [`Database::delete_incidents`]
//!   is retention's deletion, [`Transaction::bound_work`] bounds the work of aggregate reads,
//!   and [`testing::for_each_backend`] (feature `testing`) runs a test on every backend.
//!
//! Under PostgreSQL the revision triggers also `NOTIFY sibuna_policy`, and the thread
//! `LISTEN`s so a node ticks at once when another node changes the policy.
//!
//! # Changes from the Zig version
//!
//! The Zig layer (`persistent.zig`, `persistent_policy.zig`, `policy_inspection.zig`,
//! `policy_limits.zig`, `database.zig`) is the specification. The port differs deliberately
//! as follows.
//!
//! - Zaxonlite is gone (SID 0011). SQLite serves one node, PostgreSQL a cluster. The peer
//!   specification parser, the cluster TLS options, the startup retry tied to leader
//!   election and the bounded close of a consensus member are gone with it; startup retries
//!   only transient connection errors, for [`STARTUP_TIMEOUT`].
//! - Every statement binds its values. The SQL quoting function and its test are gone. A
//!   replayed batch is no longer the retained SQL text but the retained prepared batch
//!   (ids, embeddings, campaigns), written again under the same receipt guard.
//! - The schema is versioned by numbered migrations in `sibuna_schema(component, version,
//!   applied_at)`; the `component` column lets the console add its own numbered migrations
//!   without making nodes that lack it refuse the database. The core schema is one baseline
//!   migration. The `policy_format` key and the additive `limit_config` upgrade of
//!   `policy_limits.zig` are gone: Zaxonlite data is not migrated (SID 0011).
//! - The key/value table `sibuna_meta` is gone. The policy revision is the single row of
//!   `policy_revision`, and each node's incident receipt is its row of `incident_receipts`
//!   (Zig's `incident_cursor_<node>` key); the replay guard reads that row.
//! - The schema is typed: SQLite tables are `STRICT`, enumerated columns (action,
//!   algorithm, inspection modes) and bounded integers have `CHECK` constraints, and stored
//!   names are the lowercase ones (`deny`, not `DENY`). Rule limits are the typed columns
//!   `limit_rate`, `limit_window_seconds` and `limit_ban_seconds` ([`RuleLimits`]) instead
//!   of the JSON document `limit_config`; matchers stay JSON, checked with `json_valid` on
//!   SQLite and stored as `JSONB` on PostgreSQL. Incidents reference their node's receipt.
//!   Zig read every cell as text and parsed it; a stored value of the wrong type or range is
//!   now refused when it is written.
//! - sqlite-vec and `incidents_vec` are gone: the embedding is a 256-byte column of
//!   `security_incidents`, and campaigns are assigned in memory over the most recent 16,384
//!   embeddings of all nodes (see [`campaigns`]). Incidents older than the window are not
//!   compared, as SID 0011 records.
//! - Full-text search has one language on both backends (SID 0013, "Search"): Rust
//!   tokenizes paths and payloads into canonical tokens, SQLite's `incidents_fts` uses the
//!   `ascii` tokenizer over them, PostgreSQL stores a `tsvector` that Rust writes, and a
//!   query is parsed in Rust and translated, so both return the same matches. Zig passed the
//!   query to FTS5 `MATCH` unchanged.
//! - The engine is not built here. The storage thread hands plain rows
//!   ([`PolicySnapshot`]) to the daemon's publish hook, which builds the engine, adds the
//!   file policy and returns whether it published; a refusal keeps the old revision
//!   applied, as a failed Zig loader did. Matcher and limit documents are therefore
//!   validated by the policy crate, not here; this crate decodes typed columns and bounds the
//!   number of rows ([`policy::MAX_POLICY_ROWS`], [`policy::MAX_REPUTATION_ROWS`]). Zig
//!   skipped reputation rows it could not read; the typed schema cannot hold such rows.
//! - Incident user agents, paths and payloads are raw bytes (`BLOB` / `BYTEA`) as in Zig,
//!   but full-text search indexes their canonical tokens, so on SQLite `incidents_fts` holds
//!   its own text instead of being Zig's external-content table over the incident rows. The
//!   client address, method and category are text (NUL dropped, invalid UTF-8 as U+FFFD).
//! - Under PostgreSQL a batch with honeypot bans locks the revision row first, so two nodes
//!   banning the same addresses in different orders cannot deadlock. Statement triggers
//!   also cover `TRUNCATE`.
//! - The console's sidecars (evidence, heads, country) are written by the console's
//!   [`Hooks::on_incidents`] in the batch's transaction, as Zig appended them to the batch's
//!   SQL. The ring record carries the evidence and the redacted heads, as Zig's did.
//! - Errors are a [`StorageError`] enum; the thread reports recovered errors through
//!   [`Hooks::on_error`] instead of printing.
//! - Building a snapshot takes a little memory each time (owned `String`s), where Zig
//!   reused two arenas; rebuilds are rare and run on the storage thread, never on a
//!   request.
//!
//! # Zig machinery that Rust deleted
//!
//! SID 0011 is the specification; the following Zig mechanisms existed only to manage
//! memory or lifetimes by hand and were not ported.
//!
//! - Double-buffered engine slots (`spare`, `owned_slot`, the reader-count spin before
//!   reuse, re-publishing the caller's slot at shutdown): the daemon publishes an
//!   `Arc<Engine>` built from each [`PolicySnapshot`] (SID 0010); the old engine is freed
//!   when its last request drops it, so this crate owns no engine at all.
//! - One arena per slot, reset before each rebuild: snapshot rows own their text, and
//!   `Drop` frees a rejected or replaced snapshot.
//! - SQL text built with a quoting function, and the retained `pending_sql` buffer with its
//!   manual `dupe`/`free` ownership: bound parameters ([`Param`]) and a retained
//!   `PreparedBatch` value that a failed write simply keeps.
//! - `IncidentRecord` with `undefined` arrays and separate length fields: a fixed-capacity
//!   field type that copies and exposes only its initialised prefix.
//! - The `?*anyopaque` hook context and `recordIncidentHook` cast: [`Storage::record_incident`]
//!   on a shared reference; the ring is reached through an `Arc`.
//! - `maxInt(u64)` as "no expiry", `version = 0` as "nothing applied": `Option<u64>`.
//! - Every cell read as text and parsed by position: one typed row struct per table, decoded
//!   in `SELECT` order by [`Columns`], with enums for enumerated columns.
//! - `open`/`stop`/`shutdown` with `errdefer` chains, `worker_done` polling and the global
//!   `close_done` flag of the bounded close: [`Storage::start`] builds everything on the
//!   storage thread and reports through a channel; [`Storage::shutdown`] (or `Drop`) joins
//!   the thread, which bounds its own flush and close with `tokio::time::timeout`.
//! - The console mailbox (32 fixed slots with tickets, states, abandonment and completion
//!   events): a bounded channel of [`JOB_QUEUE`] boxed jobs, each answering through a
//!   one-shot channel of its own that a [`Ticket`] owns, so a caller that gives up simply
//!   drops its ticket, and a slot can never be recycled under a running job or hand one
//!   caller's result to another. A full queue refuses at once with [`StorageError::Busy`],
//!   and the storage thread runs at most [`JOBS_PER_TICK`] jobs before it checks its tick,
//!   as Zig's tick took at most 16. Jobs still queued at shutdown are dropped unrun and
//!   their tickets report [`StorageError::Stopped`], as Zig's stop cancelled them. The
//!   mailbox's urgent and background priorities are not kept: jobs run in order.
//! - `Db` as a tagged union with `unreachable` arms for builds without a cluster: the
//!   [`Database`] enum has exactly the variants of the enabled cargo features.

// The daemon leaves this crate out entirely for the in-memory build (SID 0011), so a build
// of it without either backend is a mistake worth stopping early.
#[cfg(not(any(feature = "sqlite", feature = "postgres")))]
compile_error!("sibuna-storage needs the `sqlite` or the `postgres` feature");

pub mod campaigns;
mod database;
mod error;
mod incidents;
mod listen;
pub mod policy;
pub mod schema;
pub mod search;
mod storage;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod tls;
mod url_file;
mod worker;

pub use campaigns::{CAMPAIGN_DISTANCE, DIMENSIONS, Embedding, WINDOW};
pub use database::{
    ACQUIRE_TIMEOUT, BUSY_TIMEOUT, Cell, Columns, Database, Dialect, POOL_CONNECTIONS, Param, Row,
    SQLITE_FILE, Sql, Target, Transaction, WorkBound,
};
pub use error::{StorageError, UrlFileProblem};
pub use incidents::{
    BatchIncident, INCIDENT_BATCH, INCIDENT_QUEUE, IncidentHit, IncidentReceipt, MAX_SEARCH_QUERY,
    MAX_SEARCH_RESULTS,
};
pub use listen::POLICY_CHANNEL;
pub use policy::{
    ChallengeAlgorithm, InspectionMode, InspectionRow, PageTemplate, PolicyAction, PolicyRow,
    PolicySnapshot, ReputationRow, RuleLimits,
};
pub use schema::{Migration, MigrationSet};
pub use storage::{
    BorrowedFuture, Committed, CommittedHook, EmbedFn, ErrorFn, Hooks, IncidentHook, JOB_QUEUE,
    JOBS_PER_TICK, LocalFuture, MAX_BACKOFF, MAX_NODE_ID, MIN_POLL, PublishFn, SHUTDOWN_TIMEOUT,
    STARTUP_TIMEOUT, SnapshotHook, Storage, TickHook, Ticket,
};
pub use tls::{POSTGRES_TLS, PostgresTls, Protection, SslMode};
pub use url_file::{MAX_URL_FILE, read_database_url_file};
