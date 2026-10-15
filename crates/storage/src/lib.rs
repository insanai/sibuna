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
//! - [`Storage::with_database`] runs other work (bans, searches, the console's queries) on
//!   the storage thread; [`Storage::ban_address`] and [`Storage::search_incidents`] are the
//!   common cases.
//! - [`Database`] is a dialect-neutral handle: statements take [`Param`]s bound to `$1`,
//!   `$2`, ... and return rows of owned [`Cell`]s, so every query is written once and only
//!   SQL text that differs between dialects is written twice ([`Sql`]).
//! - [`read_database_url_file`] reads `--database-url-file`.
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
//!   applied_at)`. The table has a `component` column beyond SID 0011's two columns, so the
//!   console can add its own numbered migrations without making nodes that lack it refuse
//!   the database. The `policy_format` key and the additive `limit_config` upgrade of
//!   `policy_limits.zig` are replaced by migration 1, which has the column.
//! - sqlite-vec and `incidents_vec` are gone: the embedding is a 256-byte column of
//!   `security_incidents`, and campaigns are assigned in memory over the most recent 16,384
//!   embeddings of all nodes (see [`campaigns`]). Incidents older than the window are not
//!   compared, as SID 0011 records.
//! - PostgreSQL full-text search uses a generated `tsvector` with the `simple`
//!   configuration (no stemming, like FTS5's default tokenizer) and `websearch_to_tsquery`,
//!   so a query string never fails to parse there; SQLite keeps FTS5 `MATCH` syntax.
//! - The engine is not built here. The storage thread hands plain rows
//!   ([`PolicySnapshot`]) to the daemon's publish hook, which builds the engine, adds the
//!   file policy and returns whether it published; a refusal keeps the old revision
//!   applied, as a failed Zig loader did. Matcher and limit documents are therefore
//!   validated by the policy crate, not here; this crate checks column types and bounds the
//!   number of rows ([`policy::MAX_POLICY_ROWS`], [`policy::MAX_REPUTATION_ROWS`]).
//! - Incident user agents, paths and payloads are raw bytes (`BLOB` / `BYTEA`) as in Zig,
//!   but full-text search indexes a lossy UTF-8 rendering (NUL dropped, invalid sequences
//!   U+FFFD), because PostgreSQL text holds neither. On SQLite `incidents_fts` therefore
//!   holds its own text instead of being Zig's external-content table over the incident
//!   rows; on PostgreSQL the rendering is the column `search_text`. The client address,
//!   method and category are text, rendered the same way.
//! - Under PostgreSQL a batch with honeypot bans locks the revision row first, so two nodes
//!   banning the same addresses in different orders cannot deadlock. Statement triggers
//!   also cover `TRUNCATE`.
//! - The console's sidecars (evidence, heads, country) are not written yet; the console port
//!   adds them with its own migrations and [`Hooks::on_tick`].
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
//! - `open`/`stop`/`shutdown` with `errdefer` chains, `worker_done` polling and the global
//!   `close_done` flag of the bounded close: [`Storage::start`] builds everything on the
//!   storage thread and reports through a channel; [`Storage::shutdown`] (or `Drop`) joins
//!   the thread, which bounds its own flush and close with `tokio::time::timeout`.
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
mod storage;
#[cfg(test)]
mod testing;
mod url_file;
mod worker;

pub use campaigns::{CAMPAIGN_DISTANCE, DIMENSIONS, Embedding, WINDOW};
pub use database::{
    ACQUIRE_TIMEOUT, BUSY_TIMEOUT, Cell, Database, Dialect, POOL_CONNECTIONS, Param, Row,
    SQLITE_FILE, Sql, Target, Transaction,
};
pub use error::{StorageError, UrlFileProblem};
pub use incidents::{
    INCIDENT_BATCH, INCIDENT_QUEUE, IncidentHit, MAX_SEARCH_QUERY, MAX_SEARCH_RESULTS,
};
pub use listen::POLICY_CHANNEL;
pub use policy::{InspectionRow, PolicyRow, PolicySnapshot, ReputationRow};
pub use schema::{Migration, MigrationSet};
pub use storage::{
    EmbedFn, ErrorFn, Hooks, LocalFuture, MAX_BACKOFF, MAX_NODE_ID, MIN_POLL, PublishFn,
    SHUTDOWN_TIMEOUT, STARTUP_TIMEOUT, Storage, TickHook,
};
pub use url_file::{MAX_URL_FILE, read_database_url_file};
