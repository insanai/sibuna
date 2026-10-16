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
//! The port was split into units (the console port plan, section 3). The foundation (U1)
//! declared every cross-unit interface; each later unit implemented the modules it owned
//! and added the interfaces below. Every unit has landed.
//!
//! - **U1** (foundation): `console`, `shared`, `config/`, `host`, `keys`, `clock`,
//!   `random`, `routes`, `dispatch`, `assets`, `limits`, `storage`, `http/`, `geo/slot`
//!   and `tests/support`. Its interface for every unit is listed after this list.
//! - **U2** owns `api/{session,totp,users,tokens,kiosk,audit}`, `auth/`, `client`,
//!   `command/`:
//!   - `auth::password::Verifier::new(&Setup) -> Result<Verifier, VerifierError>`
//!   - `client::send(&Endpoint, &Request, &Limits) -> Result<Response, ClientError>` and
//!     `client::send_cancellable(.., cancel: &dyn Fn() -> bool)`, which gives up within
//!     about a second of `cancel` turning true (the notifier, the GeoIP download)
//!   - [`command::run`]`(&[String], &mut dyn Write) -> Result<(), CommandError>` and
//!     [`command::run_with`]`(args, out, notes)`, which also writes progress lines and the
//!     sign-out warning to `notes`; the daemon calls `run_with` for `sibuna console ...`
//!     with standard output and standard error
//! - **U3** owns `api/{policies,workflows,country,pages,settings,notifications,nodes,`
//!   `events,export,security,challenges,minutes,rule_hits,ranking_history}` and `nodes`:
//!   - [`PolicyBase`]: the daemon's WAF switch, policy file, global limiter, honeypot ban
//!     and built-in challenge page, given as `Inputs::policy`
//!   - `api::pages::Drafts::new(&Setup) -> Drafts`
//!   - `nodes::Commands::new(&Setup) -> Commands`; `execute(&Shared, &Credential,
//!     &Command) -> Result<Receipt, RouteError>` (intent, rechecks, effect through the
//!     [`Node`], completion); `retry(&Shared)`, called by the collector every tick;
//!     `control_revision`, `is_pending`, `uptime_ms` and `pending_receipt(&[u8; 16])` for
//!     `nodes/local`
//!   - the aggregate reads take the work bound of [`Config::query_steps`]
//! - **U4** owns `collector/` and `api/live`:
//!   - `collector::Live::new(&Setup) -> Live`; the views `stats(&Shared) ->
//!     StatsSnapshot`, `timeline(&Shared, &timeline::Query) -> Result<timeline::Page,
//!     LiveError>`, `rankings(&Shared) -> Result<rankings::Page, LiveError>`,
//!     `challenges(&Shared) -> Result<challenges::Snapshot, LiveError>`
//!   - `Live::record_coverage(&Shared) -> RecordCoverage` (`fill_records`,
//!     `fill_difficulty` complete the stored challenge pages with node-owned counters)
//!   - `Live::request_announce(control_revision)`, called by `nodes` after an applied
//!     command
//!   - `collector::live::configured_bin(&Defaults) -> u8` and
//!     `challenge_snapshot(&Metrics, Defaults, u8, now) -> challenges::Snapshot`
//!   - `collector::dashboard::Frame`: `new()`, `collect(&local, &observations, now)` and
//!     `view(node) -> View`, the dashboard frame merging local and peer views (U5)
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
//!   - `notify::target`: `validate_webhook`, `validate_syslog`, `target_host`,
//!     `envelope_subject` and `is_address_allowed`, shared by delivery and the
//!     destination routes
//!   - `notify::run(&Shared)`, the notifier thread
//!   - `geo::Importer::with_embedded(&Setup, Option<&'static [u8]>) -> Importer`, over
//!     the daemon's embedded snapshot ([`Inputs::geoip_embedded`])
//!   - `Importer::restore(&self, &Shared) -> Result<(), ImportError>`, called by
//!     `Console::start`
//!   - `Importer::start(&self, &Shared, ImportRequest) -> Result<(), ImportError>` (one
//!     import thread at a time), `status(&self) -> ImportStatus`, `shown(&self) -> Shown`
//!     (the generation the GeoIP page shows)
//!   - `Importer::stop(&self)`, called by `Console::stop`
//!   - `probe::Probes::new(&Setup) -> Probes`
//!   - `Probes::snapshot(&self, &mut Vec<nodes::Probe>)`
//!   - `probe::run(&Shared)`, the probe thread
//! - **U7** owns `peer/` and `api/peer`:
//!   - `peer::Peers::new(&Setup) -> Peers`
//!   - `Peers::reports(&self, u64, &mut Vec<nodes::Peer>)`
//!   - `Peers::snapshots(&self, &mut Vec<Observation>)`
//!   - `Peers::contains(&self, u32) -> bool`
//!   - `Peers::admit(&Transcript, &[u8; 32], now) -> Result<Inbound, StoreError>` (the
//!     inbound `/console/peer` route; dropping `Inbound` releases the link),
//!     `activate`, `publish` and `failed` (the outbound workers),
//!     `submit(node, Kind, Cursor, now) -> Result<Ticket, StoreError>` (peer queries of
//!     the timeline and rankings routes), `targets`, `self_node`, `key` and `stop`
//!   - `peer::run(&Shared)`, the parent of the peer workers
//!   - `sibuna_tls::testing` (feature `testing`): `Ingress::start(Leaf)`, `forward_to`,
//!     `forwarded`, `refused`, and `ca_file()`, a TLS-terminating test proxy with a
//!     private CA
//! - **U8** (the daemon, `cmd/sibuna`) implements [`Node`] (drain flag, ban gauge and
//!   clear, rule-hit samples with the retired generation's final counters
//!   ([`RuleHitSample::retired`]), applied revision, connection count, the published
//!   engine) and registers [`snapshot_hook`], [`committed_hook`],
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
//!   (one transaction, committed on success, waits at most 10 s) and
//!   `submit_background(job) -> BackgroundTicket` for background tasks (at most 4 jobs
//!   together; `try_take` never blocks). `storage::StorageFailure::route_error` maps a
//!   failure with the route's own code.
//! - `Shared`: configuration, `shared::Identity` (node, boot, version, proxy mode,
//!   challenge defaults, origin), keys, the clock (`now`, `monotonic_ms`), the [`Node`],
//!   telemetry, incident feed, metrics, the [`GeoSlot`], assets, `login_limiter`
//!   (`limits::Limiter`), `query_budget` (`limits::QueryBudget`), every service, and
//!   `sleep(Duration) -> bool` (wakes when the console stops), `is_stopping`,
//!   `needs_totp`, `is_restricted`.
//! - [`random::fill`] and [`random::array`] (`/dev/urandom`; `BCryptGenRandom` on Windows).
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
//!   crate builds without the WebAssembly module; so is the embedded GeoIP snapshot, which
//!   the daemon's build validates (decision 7).
//! - The SQLite step bound of aggregate reads is [`Config::query_steps`], checked by
//!   [`Config::validate`] (Zig checked it only in the daemon's flag parser).
//! - Services that ran on Zig's storage owner run on console threads: rule hits are
//!   sampled from the published engine through [`Node`] once a second; the daemon keeps a
//!   retired generation's counters until a sample read their final values, so the cutover
//!   loses no hit counted before the publication (`collector::journal::rule_hits`).
//!   Membership announcements and node-command completions are background jobs.
//! - `nodes/local` reports the daemon's open data-plane connections
//!   ([`Node::connection_count`]).
//! - A peer that becomes `rejected` (refused certificate or proof) writes one
//!   `peer.rejected` audit row (SID 0012); a peer whose worker cannot start is reported
//!   `stale` instead of staying `unobserved`.
//! - The modules `collector`, `hub`, `api::stream`, `nodes`, `peer`, `geo::import` and
//!   `probe` list their own changes.
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
