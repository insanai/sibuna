//! The Sibuna daemon: a web firewall and anti-crawler reverse proxy (SID 0002 to SID 0004,
//! SID 0009 to SID 0011).
//!
//! The binary (`main.rs`) only collects its arguments and calls [`cli::run`]. Everything else
//! is this library, so the end-to-end tests boot the real server in-process with
//! [`Daemon::start`] (or [`Running::start`] for a hand-built engine).
//!
//! # Architecture
//!
//! ```text
//!  accept workers (--workers)          connection threads (<= --max-connections)
//!  --------------------------          -----------------------------------------
//!  listener.accept()  --launch-->  connection::serve: 64 KiB read buffer, loop:
//!     | over the bound: 503            read head, buffer body (chunked decoded in place)
//!                                      dispatch: ban -> /__sibuna/ routes -> GCRA ->
//!                                        policy (EngineCache) -> quota -> session ->
//!                                        proxy (sibuna-net) | forward-auth | page
//!  reaper thread: cuts idle sockets      storage thread (optional): incidents, rebuilds
//!                                        engines and publishes them into the EngineSlot
//! ```
//!
//! - [`server`]: the shared state ([`Server`]), the accept workers and the stop sequence.
//! - [`slot`]: engine publication: an `Arc<Engine>` behind a generation counter that
//!   request threads read with one acquire load ([`EngineCache`]).
//! - [`daemon`]: the engine, the optional storage layer and the server together.
//! - [`cli`]: the command line, the master secret, the policy file, the banner.
//! - [`signals`]: SIGINT and SIGTERM through a `sigwait` thread (the only `unsafe` code).
//! - [`assets`]: the embedded WebAssembly solver, worker script and interstitial.
//! - `recipe` and, with storage, `persistent`: how engines are built, from the policy file
//!   and from stored policy rows.
//! - With the console, [`console`]: the `--console*` options, the console server started
//!   beside the data plane, `init-admin`, and the request path's telemetry behind the
//!   private `telemetry` seams.
//!
//! Cargo features: `sqlite` and `postgres` select the storage backends of
//! `sibuna-storage`; `postgres-tls` adds TLS to the PostgreSQL connections (`sslmode` and
//! `sslrootcert` in the URL); `console` adds the console server (SID 0007), which needs
//! storage. The default is `sqlite` and `console`. Without features
//! (`--no-default-features`) the daemon is the in-memory firewall and depends on no crate
//! outside the workspace; with them it adds exactly sqlx and tokio (storage) and rustls,
//! ring and the system trust store (the console's outbound TLS and PostgreSQL TLS, SID
//! 0012). A build without `postgres-tls` refuses a URL whose `sslmode` needs TLS, and the
//! startup lines warn when the database connection is not encrypted and verified.
//!
//! # Changes from the Zig version
//!
//! `apps/sibuna/src/{main,server,response_pages,challenge_page,challenge_observe,
//! connection_tasks,connection_idle,shutdown,storage,persistent_policy,policy_inspection,
//! policy_limits}.zig` and the end-to-end suite are the specification. Every route, status,
//! header and body is unchanged. Deliberate differences:
//!
//! - Storage is SQLite or PostgreSQL (SID 0011); the banner and help name them, and a build
//!   without storage refuses the storage options with a hint.
//! - Engine snapshots are `Arc<Engine>` values published through [`EngineSlot`]. Zig's two
//!   engine slots with reader counts, the writer's spin until readers drained and the arenas
//!   reset per rebuild are gone; a request reads the engine through its connection's
//!   [`EngineCache`], and an old
//!   engine is freed when the last cache holding it refreshes or closes. The 128-byte copy of
//!   the deciding rule's name remains: it ends the decision's borrow of the engine so the
//!   response can be written while the cache refreshes.
//! - Signals: Zig installed a handler that set a flag and polled it every 100 ms. We block
//!   SIGINT and SIGTERM and wait for them with `sigwait` on a dedicated thread, which wakes
//!   the main thread at once.
//! - Connection threads and the task table are `std::thread`s in a [`tasks::TaskPool`] with
//!   the same lowest-free-slot policy; a panicking connection frees its slot (a drop guard).
//!   The idle table and the origin pool come from `sibuna-net`, whose sockets are reference
//!   counted, so the reaper can never shut down a reused descriptor.
//! - An accept error other than an interrupted call pauses the worker for 1 ms instead of
//!   retrying at once, so running out of descriptors does not spin a CPU.
//! - Request references on HTML pages come from a per-thread xorshift generator seeded from
//!   the standard library's random hash keys; Zig drew them from the system CSPRNG. They are
//!   references, not secrets.
//! - Messages about the master secret, the policy file and the listener name I/O failures
//!   by Zig's error names where one corresponds (`FileNotFound`, `AccessDenied`,
//!   `AddressInUse`), else by the Rust description.
//! - `console` on a build without the console names the cargo feature in its hint.
//! - The console's request telemetry (outcome counters, samples, challenge observations,
//!   rule hits, origin head capture) is reached through the private `telemetry` seams:
//!   without the `console` feature they are empty inline functions, without `--console`
//!   each is one untaken branch. A warm request allocates nothing either way
//!   (`tests/steady_state.rs`).
//! - Security fixes of 2026-10-15 (approved by the maintainer): a trusted forwarded client
//!   is the `X-Forwarded-For` entry `--trusted-hops` from the right, not the leftmost one
//!   a client writes, and must parse as an address (see `context`); limits and bans key on
//!   the canonical address, IPv6 aggregated to `--ipv6-prefix`; the challenge budget has
//!   its own limiter table; tables are sized by `--rate-table-cells`, `--ban-table-slots`
//!   and `--spent-tags`; the honeypot bans only top-level requests (`Sec-Fetch-Dest`
//!   absent or `document`, `Sec-Fetch-Site` not `cross-site`); every session cookie value
//!   is tried, up to eight. New counters follow Zig's in the metrics exposition.
//!
//! # Zig machinery that Rust deleted
//!
//! - `EngineSlot.readers` with `acquireEngine`/`releaseEngine` and `publishEngine`'s spin:
//!   `Arc` reference counting and [`EngineCache`].
//! - `Persistent.spare`/`owned_slot` and the slot re-publication at shutdown: the storage
//!   thread builds a fresh `Engine` from each snapshot and publishes it; nothing is reused.
//! - `Hooks.context: ?*anyopaque` with casts: a boxed closure ([`server::Hooks`]).
//! - `IdleTable` slot locks and `undefined` streams, `Pool` descriptor tables: `sibuna-net`.
//! - `defer`/`errdefer` teardown chains in `main`: [`Daemon`] and [`Running`] stop in `Drop`.
//! - The process-lifetime arena for arguments and policy text: owned `String`s and `Vec`s.

//! # Performance
//!
//! Measured against the Zig 0.16 daemon (ReleaseFast) on one Ryzen 9 5950X, both in memory
//! with the flags and workloads of the Zig `benchmarks/tools.py` (`--shield --workers 4
//! --algorithm hashcash --difficulty 8 --rate-limit 100000000`, daemon pinned to four CPUs,
//! `caddy respond` as the origin, `wrk -t2 -c64`, five-second runs, medians of three):
//!
//! | workload (req/s, p50/p99 in us) | Zig req/s | Rust req/s | Zig         | Rust        |
//! |---------------------------------|-----------|------------|-------------|-------------|
//! | admitted with session, proxied  | 111,490   | 125,728    | 510 / 2,374 | 433 / 2,586 |
//! | challenged (interstitial)       | 192,145   | 197,245    | 162 / 350   | 161 / 327   |
//! | static allowed, proxied         | 117,360   | 127,913    | 482 / 2,462 | 420 / 2,633 |
//! | WAF denied (with session)       | 207,279   | 210,054    | 152 / 336   | 151 / 305   |
//!
//! `wrk` keeps 64 requests in flight, so on the CPU-bound proxied paths the faster daemon
//! also sees more requests queued per CPU; its p99 there is the scheduler's tail at a higher
//! rate. At equal offered load (an open-loop generator sending at a fixed rate and timing
//! from the intended send, as `wrk2` does) the Rust daemon's tail is lower:
//!
//! | proxied workload, rate | Zig p50 / p99 / p99.9 (us) | Rust p50 / p99 / p99.9 (us) |
//! |------------------------|----------------------------|-----------------------------|
//! | admitted, 45,000/s     | 134 / 262 / 871            | 127 / 249 / 622             |
//! | admitted, 60,000/s     | 149 / 577 / 3,021          | 132 / 462 / 2,125           |
//! | admitted, 75,000/s     | 162 / 1,841 / 4,883        | 136 / 1,059 / 2,897         |
//! | admitted, 90,000/s     | 1,640 / 70,191 / 108,208   | 250 / 3,933 / 8,517         |
//! | static, 60,000/s       | 142 / 404 / 1,580          | 131 / 356 / 1,652           |
//! | static, 80,000/s       | 174 / 2,290 / 5,113        | 145 / 1,907 / 4,848         |
//!
//! A warm keep-alive connection serves every decision without a heap allocation
//! (`tests/steady_state.rs` counts them).
//!
//! # Tests
//!
//! `tests/e2e.rs` is the Zig end-to-end suite, scenario for scenario; `tests/storage.rs` runs
//! policy reloads, persistent honeypot bans and incident recording against SQLite (and
//! PostgreSQL with `SIBUNA_TEST_DATABASE_URL`); `tests/cli.rs` runs the binary. With
//! `SIBUNA_ZIG_BINARY` naming a Zig build, `tests/cli.rs` and `tests/zig_parity.rs` compare
//! the two daemons byte for byte (masking only random and time-dependent values) and check
//! that sessions and tickets minted by one are accepted by the other. Clients see an error
//! explanation only where Zig sent one (a rejected solution); an invalid session cookie falls
//! through to the challenge, unexplained.

pub mod assets;
mod challenge;
pub mod cli;
mod client_writer;
mod connection;
#[cfg(feature = "console")]
pub mod console;
mod context;
pub mod daemon;
mod dispatch;
mod incidents;
mod pages;
#[cfg(feature = "storage")]
pub mod persistent;
pub mod recipe;
mod routes;
pub mod server;
pub mod signals;
pub mod slot;
pub mod tasks;
mod telemetry;

pub use challenge::extract_json_string;
pub use daemon::{Daemon, DaemonOptions, StartError};
pub use recipe::Recipe;
pub use server::{Hooks, IncidentHook, Options, Running, Server, VERSION};
pub use slot::{EngineCache, EngineSlot};
