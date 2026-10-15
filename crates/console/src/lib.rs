//! The Sibuna console server (SID 0007): routes, authentication, the live hub, collectors,
//! management peers and outbound jobs, on the bounded listener of `sibuna-serve` and the
//! storage thread of `sibuna-storage`.
//!
//! The daemon starts the console with a [`Config`] (from its `--console*` flags) and
//! [`Inputs`] (the storage thread, the data plane's telemetry, the GeoIP slot, the
//! [`Node`] implementation, keys, embedded assets and a clock):
//!
//! ```text
//! let inputs = Inputs { node_id, version, ..Inputs::new(storage, node, boot) };
//! let console = Console::start(config, inputs)?;
//! println!("console on {} ({} bytes reserved)", console.origin(), console.reserved_bytes());
//! ...
//! console.stop();
//! ```
//!
//! # Threads
//!
//! ```text
//! request threads (data plane)                       storage thread (SID 0011)
//!   count/offer -> ConsoleTelemetry (atomics, rings)   incident batch -> on_incidents
//!   record hits -> rule-hit counters                     (sidecars, country by GeoSlot)
//!   read the drain flag                                  -> commit -> on_committed
//!          |                                             -> ConsoleIncidents ring
//! console (this crate)                                 runs submitted jobs (<= 32 queued)
//!   listener: acceptor, watchdog, <= 96 workers -------> transact / run (wait <= 10 s)
//!     each WebSocket: worker writes, scoped reader
//!   collector (250 ms) -------------------------------> background tickets (<= 4 jobs)
//!   hub feeder (100 ms, fan-out at 1 Hz) -------------> background tickets
//!   probe (5 s), notifier, peer workers (<= 8), one GeoIP import on demand
//! ```
//!
//! No console thread runs on a data-plane thread or takes a lock a request thread holds
//! (SID 0007, Invariants I1 to I3). [`Console::stop`] joins every console thread.
//!
//! # Request pipeline
//!
//! The listener hands each request to the dispatcher (`dispatch.rs`): ingress, deadline,
//! world geometry, digest-named assets and the shell, route lookup (`routes.rs`), bearer
//! admission, the `Origin` check, the principal (resolved by storage), restricted accounts,
//! scope, role and kiosk checks, CSRF and the mutation allowance; then the route's handler
//! in `api/`. Every failure is `{"error":CODE,"hint":...}` with the Zig hint texts.
//!
//! # Units and their interfaces
//!
//! The port is split into units (the console port plan, section 3). This crate's foundation
//! (U1) declares every cross-unit interface with the public names the later units keep;
//! each later unit replaces the bodies of the modules it owns. Stub bodies answer 503
//! `CONSOLE004` (routes), return "unavailable" values, or do nothing (threads).
//!
//! - **U1** (this foundation): `console`, `shared`, `config/`, `host`, `keys`, `clock`,
//!   `random`, `routes`, `dispatch`, `assets`, `limits`, `storage`, `http/`, `geo/slot`,
//!   the stubs below, and `tests/support`. Its interface is listed after this list.
//! - **U2** owns `api/{session,totp,users,tokens,kiosk,audit}`, `auth/`, `client`,
//!   `command/`:
//!   - `auth::password::Verifier::new(&Setup) -> Result<Verifier, VerifierError>`
//!   - `command::run(&[String], &mut dyn Write) -> Result<(), CommandError>`, which the
//!     daemon calls for `sibuna console ...`
//! - **U3** owns `api/{policies,workflows,country,pages,settings,notifications,nodes,`
//!   `events,export,security,challenges,minutes,rule_hits,ranking_history}` and `nodes`:
//!   - `api::pages::Drafts::new(&Setup) -> Drafts`
//!   - `nodes::Commands::new(&Setup) -> Commands`
//!   - `nodes::Commands::retry(&self, &Shared)`, called by the collector every tick
//! - **U4** owns `collector/` and `api/live`:
//!   - `collector::Live::new(&Setup) -> Live`
//!   - `Live::stats(&self, &Shared) -> StatsSnapshot`
//!   - `Live::timeline(&self, &Shared, &timeline::Query)`
//!     `-> Result<timeline::Page, LiveError>`
//!   - `Live::rankings(&self, &Shared) -> Result<rankings::Page, LiveError>`
//!   - `Live::challenges(&self, &Shared) -> Result<challenges::Snapshot, LiveError>`
//!   - `collector::run(&Shared)`, the collector thread
//! - **U5** owns `hub/` and `api/stream`:
//!   - `hub::Hub::new(&Setup) -> Hub`
//!   - `Hub::attach(&self) -> Result<Subscription, HubError>` (browsers, at most 64)
//!   - `Hub::attach_peer(&self) -> Result<Subscription, HubError>` (peers, at most 16)
//!   - `Hub::detach(&self, Subscription)`
//!   - `Hub::command(&self, &Subscription, &Command) -> Result<(), HubError>`
//!   - `Hub::take(&self, &Subscription, Duration) -> Option<Item>` (`Item::Frame` or
//!     `Item::Gap`)
//!   - `Hub::stop(&self)`, called first by `Console::stop`
//!   - `hub::run(&Shared)`, the feeder thread
//! - **U6** owns `notify/`, `geo/{import,download,embedded}`, `api/geoip` and `probe`:
//!   - `notify::Notifier::new(&Setup) -> Notifier`
//!   - `Notifier::raise(&self, Event, u64, &str)`, called by the collector
//!   - `Notifier::test_destination(&self, &Shared, &Destination, &Read) -> Delivery`,
//!     called by `api/notifications`
//!   - `notify::run(&Shared)`, the notifier thread
//!   - `geo::Importer::new(&Setup) -> Importer`
//!   - `Importer::restore(&self, &Shared) -> Result<(), ImportError>`, called by
//!     `Console::start`
//!   - `Importer::status(&self) -> ImportStatus`
//!   - `Importer::stop(&self)`, called by `Console::stop`
//!   - `probe::Probes::new(&Setup) -> Probes`
//!   - `Probes::snapshot(&self, &mut Vec<nodes::Probe>)`
//!   - `probe::run(&Shared)`, the probe thread
//! - **U7** owns `peer/` and `api/peer`:
//!   - `peer::Peers::new(&Setup) -> Peers`
//!   - `Peers::reports(&self, u64, &mut Vec<nodes::Peer>)`
//!   - `Peers::snapshots(&self, &mut Vec<Observation>)`
//!   - `Peers::contains(&self, u32) -> bool`
//!   - `peer::run(&Shared)`, the parent of the peer workers
//! - **U8** (the daemon, `cmd/sibuna`) implements [`Node`] and registers
//!   [`snapshot_hook`], [`committed_hook`],
//!   `sidecars::incident_hook(Some(geo.country_lookup()))` and `console_storage::CONSOLE`
//!   with the storage thread.
//!
//! What U1 provides to every unit:
//!
//! - Route handlers: `fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) ->
//!   Result<(), RouteError>`. `dispatch::Call` carries the route, the principal, the
//!   presented credential, the client `http::origin::Origin` captured before the body,
//!   and `now`; `Call::auth` and `Call::credential` build the protocol's `users::Auth` and
//!   the storage credential. `http::RouteError` maps to the Zig replies (400
//!   `CONSOLE002`, 503 `CONSOLE003`, 429 `CONSOLE003` for the verifier, 503
//!   `CONSOLEQUORUM`, 503 `CONSOLE004`, or any status and code).
//! - `http::body::read_json` (bounded body into a protocol type, wiped after decoding);
//!   `http::reply` (`json`, `json_bytes` with extra fields such as `Set-Cookie`, `fail`,
//!   `hint`); `http::credential` (`presented`, `session_token`, `check_csrf`,
//!   `csrf_token`, `parse_bearer`, the cookie name).
//! - Storage: `storage::ConsoleStorage` in `Shared::storage`: `transact(job)` for HTTP
//!   (one transaction, committed on success, waits at most 10 s), `run(job)`, and
//!   `submit_background(job) -> BackgroundTicket` for background tasks (at most 4 jobs
//!   together; `try_take` never blocks). `storage::StorageFailure::route_error` maps a
//!   failure with the route's own code.
//! - `Shared`: configuration, `shared::Identity` (node, boot, version, proxy mode,
//!   challenge defaults, origin), keys, the clock (`now`, `monotonic_ms`), the [`Node`],
//!   telemetry, incident feed, metrics, the [`GeoSlot`], assets, `login_limiter`
//!   (`limits::Limiter`), `query_budget` (`limits::QueryBudget`), every service, and
//!   `sleep(Duration) -> bool` (wakes when the console stops), `is_stopping`,
//!   `needs_totp`, `is_restricted`.
//! - [`random::fill`] and [`random::array`] (`/dev/urandom`).
//!
//! # Changes from the Zig version
//!
//! - The console mailbox (`mailbox.zig`, `bounded_mailbox*.zig`) is gone: storage calls are
//!   jobs on the storage thread's bounded queue with tickets (`Storage::submit`), HTTP
//!   handlers wait at most 10 s, background tasks hold at most 4 jobs (SID 0011, revision
//!   of 2026-10-15). A full queue answers 503 `CONSOLE003` (decision 8); Zig answered 429.
//!   The urgent and background priorities are gone; jobs run in order.
//! - `/console/stream` is gone and a policy import is the single route `policies/import`
//!   (SID 0007 and SID 0013 revision notes).
//! - An unknown `GET` under `/console/` (outside `api/` and `assets/`) answers the shell, as
//!   SID 0007's router section specifies; Zig answered 404.
//! - The listener may bind port 0 (tests); the origin is then derived from the bound
//!   address. The daemon's flag parser still refuses port 0. Until the shared state is
//!   built, requests are answered 503 `CONSOLE004`.
//! - Trusted proxy networks are parsed once at start, not per request; the GeoIP generation
//!   is an `Arc` read without holding a lock during lookup.
//! - The advertised URL's authority must be printable ASCII, as the origin's already had
//!   to be; Zig accepted control characters there.
//! - `about` reports the console component's schema version (1), not Zig's 40.
//! - Budget: recomputed for the Rust layout (receive buffers on worker stacks, scoped
//!   stream readers, rings allocated on demand within the same bounds, 34 bytes per GeoIP
//!   range).
//! - Assets are passed in by the daemon ([`AssetBytes`]) instead of `@embedFile`, so this
//!   crate builds without the WebAssembly module.
//!
//! # Zig machinery that Rust deleted
//!
//! - `App.init`/`deinit` with `errdefer` chains and `gpa.create`/`destroy`: [`Console`]
//!   owns an `Arc<Shared>`; `Drop` stops everything started so far.
//! - Fixed `p.Bytes(N)` configuration fields with lengths: `String` and `Vec` checked by
//!   [`Config::validate`].
//! - `secureZero` at every exit for keys and tokens: [`ConsoleKey`] wipes on drop;
//!   token buffers are wiped where they are hashed.
//! - The GeoIP registry mutex held during lookups and the explicit `deinit` of replaced
//!   generations: an `Arc` per generation.
//! - `?*anyopaque` handler contexts: the listener's handler is a closure over the shared
//!   state.

// The foundation (unit U1) declares the interfaces that units U2 to U7 implement and call;
// until they land, much of it has no caller yet. Remove this allow when the last unit has
// landed (U8, milestone B), so dead code is reported again.
#![allow(dead_code)]

mod api;
mod assets;
mod auth;
mod client;
mod clock;
mod collector;
pub mod command;
pub mod config;
mod console;
mod dispatch;
mod geo;
mod host;
mod http;
mod hub;
mod keys;
mod limits;
mod nodes;
mod notify;
mod peer;
mod probe;
pub mod random;
mod routes;
mod shared;
mod storage;

pub use api::policies::PolicyBase;
pub use assets::AssetBytes;
pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{Budget, Config, ConfigError};
pub use console::{Console, Inputs, StartError};
pub use geo::{GeoSlot, SlotError};
pub use host::{Node, RuleHitSample};
pub use keys::{ConsoleKey, KeyError, Keys, load_key};
pub use storage::{committed_hook, snapshot_hook};
