//! The console's storage (SID 0013): typed tables and transactional invariants over the
//! dialect-neutral database handle of `sibuna-storage` (SID 0011), on SQLite for one node
//! and PostgreSQL for a cluster.
//!
//! # Shape
//!
//! - [`schema::CONSOLE`] is the component `console` of `sibuna_schema`: one baseline
//!   migration with every console table and index, for both dialects. The daemon passes it
//!   in `Hooks::migrations`.
//! - Every invariant that a Zig trigger enforced is enforced by exactly one function here,
//!   which runs all of its statements in the caller's transaction. The database's `NOT
//!   NULL`, `CHECK` and foreign-key constraints are the second line of defence. No console
//!   table has a trigger.
//! - A storage function borrows `&mut Transaction` and never commits; the caller (a console
//!   route handler, through `Storage::with_database`) begins, calls one function, and
//!   commits. Failures are [`ConsoleStorageError`] values; a failed function leaves its
//!   transaction uncommitted, so dropping it rolls everything back. Time is a parameter
//!   (`now`, Unix seconds), read once by the caller.
//!
//! ```text
//! storage.with_database(move |db| async move {
//!     let mut tx = db.begin().await?;
//!     let result = tokens::create_token(&mut tx, &credential, &create, now).await;
//!     if result.is_ok() { tx.commit().await?; }
//!     Ok(result)
//! })
//! ```
//!
//! # Modules
//!
//! | Module         | Contents                                                           |
//! |----------------|--------------------------------------------------------------------|
//! | [`schema`]     | the `console` migration set and the list of its tables             |
//! | [`row`]        | [`row::Fields`], the row reader; binding unsigned values           |
//! | [`lock`]       | capacity locks, step 1 of the lock order                           |
//! | [`access`]     | credentials, route requirements, S37 `authorize_in`                |
//! | [`revision`]   | S38: the policy revision of workflows                              |
//! | [`audit`]      | S29 `append_audit`, S39 `record_export`, the Audit page, summaries |
//! | [`accounts`]   | S1 to S6: accounts, sessions, second factors, the users page       |
//! | [`tokens`]     | S7 to S9: API tokens and the tokens page                           |
//! | [`kiosk`]      | S10 and S11: kiosk grants and exchanges                            |
//!
//! # Adding a subsystem
//!
//! Each further route group of SID 0013 (policy, reputation, pages, settings,
//! notifications, nodes, GeoIP, observations, rankings, rule hits, retention, search) is a
//! module of its own, `src/<subsystem>.rs` (or a directory with submodules once it nears
//! the file limit), added to the list below. Its tables already exist in version 1 of
//! [`schema::CONSOLE`]; a change to them is a new migration appended to that set. A module
//! follows the pattern of [`tokens`]:
//!
//! 1. A module comment with the table of invariants it enforces (S-numbers of SID 0013)
//!    and the one function that enforces each. No other function writes the rows an
//!    invariant governs.
//! 2. Statements are `const` [`sibuna_storage::Sql`] values at module level with bound
//!    parameters; text that differs between dialects is written twice (`Sql { sqlite,
//!    postgres }`), otherwise `Sql::both`. Flags are bound as integers and written
//!    `($n <> 0)`, compared with `NOT column`, and set with `TRUE`/`FALSE`, which both
//!    dialects accept. PostgreSQL row locks are `FOR UPDATE` in the PostgreSQL text only.
//! 3. Each table the module reads has a row struct decoded with [`row::Fields`], one call
//!    per column in `SELECT` order, and each enumerated column an enum with `as_str` and
//!    `parse` naming exactly the values of its `CHECK`. Protocol types are used where they
//!    are the natural input or output.
//! 4. A mutation runs, in this order: validation of its input
//!    ([`ConsoleStorageError::InvalidInput`]); [`access::authorize_in`] with the route's
//!    [`access::Need`]; [`lock::lock_capacity`] for a bounded insert, then
//!    [`revision::lock`] for a policy workflow; its reads and conditional writes; then
//!    [`revision::advance`]; and [`audit::append_audit`] last. Audit summaries are built
//!    with [`audit::summary::Summary`] from named fields only.
//! 5. Tests live in `tests/invariants/<subsystem>.rs` (and constraint tests in
//!    `tests/constraints/<subsystem>.rs`), one per invariant, each run on both backends
//!    through `common::for_each_backend`.
//!
//! # Changes from the Zig version
//!
//! The Zig stores (`console_store*.zig`, `console_auth_commands.zig`) and the triggers of
//! schema version 40 (`libs/console/src/schema*.zig`) are the specification of behaviour.
//! SID 0013 records the redesign; in brief:
//!
//! - Triggers, one-row stage tables, the `console_password_rotation` table and the
//!   `WITH a AS (...) INSERT ... SELECT` authorization statements are replaced by Rust
//!   functions that read the principal, check it and write, in one transaction, with typed
//!   results instead of change counts that included trigger writes.
//! - Digests, envelopes and other binary values are `BLOB`/`BYTEA`, not hex text; absent
//!   values are `NULL`, not `0` or `''`; flags are booleans on PostgreSQL.
//! - Tokens are no longer mirrored as session rows. A token authenticates from
//!   `console_tokens` alone and stops when its creator's revision moves.
//! - Audit identifiers come from the cluster-wide cursor row `console_audit_cursor`
//!   instead of a trigger that renumbered rows through `sibuna_meta`.
//! - `console_user_activity` is `console_users.last_login_at`.
//! - Enabling TOTP writes `user.revoke` and then `totp.enable`, as Zig's trigger chain did.
//!   A kiosk exchange writes `kiosk.exchange` and `session.create` but no longer moves the
//!   granting account's last sign-in time (SID 0013, review of 2026-10-15).
//! - A kiosk exchange consumes the grant and inserts the session in one transaction: a
//!   failed insert leaves the code usable, where Zig could lose it.
//! - Only browser sessions are touched by activity; a kiosk session keeps
//!   `idle_expires_at = expires_at` (SID 0013). Zig's touch also shortened a kiosk
//!   session's idle deadline to 30 minutes.
//! - Credentials are looked up by the kind the server received (cookie or bearer); Zig's
//!   storage-side rechecks accepted either kind for one digest.
//! - On PostgreSQL, capacity-checked inserts take an advisory lock per table, account
//!   changes lock the actor's and the target's rows in id order and recheck the actor,
//!   and every conditional update is re-evaluated after its row lock; Zig serialised all
//!   of it through one replicated SQL batch.
//!
//! # Zig machinery that Rust deleted
//!
//! - The 32-slot mailbox with tickets, owned payload copies and release functions: storage
//!   functions take borrowed Rust arguments and return owned values; `sibuna-storage`'s
//!   bounded job queue carries the calls.
//! - Fixed SQL buffers, hex formatting buffers (`bytesToHex`) and parameter arrays sized by
//!   hand: bound parameters of the right type.
//! - The `std.json` arena on the stack with `secureZero` for summary views: a parsed value
//!   that is dropped after [`audit::summary::copy`] returns.

// The crate needs a backend: storage without SQLite or PostgreSQL has nothing to store in.
#[cfg(not(any(feature = "sqlite", feature = "postgres")))]
compile_error!("sibuna-console-storage needs the `sqlite` or the `postgres` feature");

pub mod access;
pub mod accounts;
pub mod audit;
mod error;
pub mod kiosk;
pub mod lock;
pub mod revision;
pub mod row;
pub mod schema;
pub mod tokens;

pub use access::{Credential, Need};
pub use error::ConsoleStorageError;
pub use schema::CONSOLE;
