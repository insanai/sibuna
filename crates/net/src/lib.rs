//! Sibuna's streaming reverse proxy and connection helpers.
//!
//! - [`stream_proxy`] forwards one admitted request to the origin and streams the response
//!   back: hop-by-hop fields dropped, audit fields (`X-Forwarded-For`, `X-Forwarded-Proto`,
//!   `X-Real-IP`, `X-Sibuna-Status`, `X-Sibuna-Rule`) added, bodies relayed as they arrive,
//!   chunked uploads re-framed (SID 0009), the origin head parsed only for its framing
//!   ([`parse_response_head`]) and the body relayed exactly. WebSocket upgrades are relayed
//!   both ways after a validated 101.
//! - [`Pool`] is the origin pool: idle keep-alive origin sockets, reused only after a fully
//!   framed response.
//! - [`idle`] is the registry of the idle reaper: [`IdleTable`], [`Lease`] and [`Activity`]
//!   give activity-based deadlines on the client and origin sockets.
//! - [`buffered`] holds the fixed-buffer [`buffered::Reader`] and [`buffered::Writer`] the
//!   connection loop uses.
//! - [`connect`] bounds connects, reads and writes for probes; [`outbound`] validates and pins
//!   management destinations.
//!
//! # Deadlines
//!
//! `--idle-timeout` is the longest silence on a connection. A request head must arrive
//! within it (the daemon touches its [`Lease`] after each request). An origin response
//! refreshes it on every read, and a silent origin is cut on both sockets. A proxied upload
//! must deliver 16 KiB per period. `--websocket-idle-timeout` bounds an upgraded connection;
//! traffic either way refreshes it.
//!
//! # Changes from the Zig version
//!
//! `libs/net/src/{proxy,proxy_upgrade,duplex,connect,outbound}.zig` and
//! `apps/sibuna/src/connection_idle.zig` are the specification. Every byte on the wire is
//! unchanged; `tests/zig_vectors.rs` replays scenarios recorded from the Zig 0.16 proxy and
//! compares what the origin and the client receive. The port differs as follows.
//!
//! - **Request bytes are borrowed, not re-read.** Zig handed the proxy the connection reader
//!   and relied on "the request slices stay valid until the next fill". Here the proxy borrows
//!   the parsed [`sibuna_http::Request`] and the bytes already read after it
//!   ([`Client::pending`]), and reads further client bytes from the socket into the
//!   [`Workspace`]'s upload buffer. The borrow checker now proves the request is never read
//!   after its buffer is refilled. Because the proxy cannot hand back what it read, the client
//!   connection is kept only when the body was fully buffered, which is exactly when the Zig
//!   daemon kept it.
//! - **Fixed buffers live in a [`Workspace`]** allocated once per connection, instead of
//!   stack arrays per exchange; the origin reader and writer borrow them.
//! - **Descriptor lifetimes are ownership.** Zig tracked every active origin socket in an
//!   8,192-entry table under the pool lock so shutdown could interrupt it without touching a
//!   reused descriptor. Here the origin socket is an `Arc<TcpStream>`; the [`Activity`]
//!   holds a clone while the exchange runs, and [`IdleTable::shutdown`] cuts it, so the
//!   descriptor cannot close (or be reused) while anyone can reach it. The idle table holds a
//!   `try_clone` of each client socket for the same reason. [`Lease`] unregisters on drop.
//!   `Pool::shutdown` only stops pooling and connecting.
//! - **No global mutex on the request path.** The origin pool is striped (16 stripes of 16
//!   sockets, a lock each, with a per-thread home stripe) instead of one spin lock; the idle
//!   table has per-slot locks and atomic stamps as before.
//! - **The upgrade relay uses two threads** (a scoped thread for the client-to-origin
//!   direction) and socket timeouts instead of one thread with `poll(2)`, which `std` does not
//!   expose; the private `duplex` module says why. Behaviour is the same: half closes are
//!   propagated, a failure cuts both sockets, and the idle bound covers both directions.
//! - **Errors and sinks.** `ClientWriteFailed` is [`ProxyError::ClientFailed`] (it also
//!   covered client reads). The `?*u16` status out-parameter is `Option<&mut u16>` and the
//!   head sink is a closure, `Option<&mut dyn FnMut(&[u8])>`.
//! - **Defensive bounds.** An origin chunk size near 2^64 no longer overflows `size + 2`; a
//!   request body longer than its declared length is cut to the length; a head trickled byte
//!   by byte is searched incrementally.
//! - **Connect helpers.** `std::net::TcpStream::connect_timeout` and socket timeouts replace
//!   the hand-driven non-blocking connect and `poll(2)` loop; [`connect::wake_listener`] is
//!   the daemon's `requestStop` wake-up.
//! - **Outbound HTTPS** goes through the installed `curl` with the address pinned, since the
//!   workspace has no TLS implementation; plain HTTP is spoken directly. Resolution cannot be
//!   cancelled, so the Zig `Canceled` error is gone.
//! - **Clock.** Stamps are milliseconds of a monotonic clock that starts at the first use in
//!   the process ([`idle::now_ms`]) instead of Zig's awake clock.
//!
//! # Safety and performance
//!
//! Untrusted bytes (client requests, origin responses) never reach an index that can fail, an
//! unchecked addition or an unbounded allocation; the response head parser, the chunked
//! response relay and the upload re-chunking are fuzzed against plain reference
//! implementations (200,000, 200,000 and 100,000 mutated inputs). In the steady state a
//! proxied request allocates nothing: `tests/steady_state.rs` counts the proxying thread's
//! allocations over 500 keep-alive requests and finds none.
//!
//! Measured on the development machine with `--release` (Zig with `-OReleaseFast`, same
//! inputs): parsing an eight-field origin head takes 322 ns against Zig's 1,674 ns, and a
//! keep-alive `GET` with a 1 KiB response proxied over loopback takes 29.8 us against Zig's
//! 31.9 us. The Zig benchmark suite measures no primitive of this crate.

pub mod buffered;
pub mod connect;
mod duplex;
mod fields;
pub mod idle;
pub mod outbound;
mod pool;
mod proxy;
mod relay;
mod request;
mod response;
mod upgrade;

pub use idle::{Activity, IdleTable, Lease, reaper_interval};
pub use pool::Pool;
pub use proxy::{
    Audit, CONNECT_TIMEOUT, Client, Exchange, HeadSink, ProxyError, Upload, Workspace,
    stream_proxy,
};
pub use response::{Framing, MAX_RESPONSE_HEAD, ResponseHead, parse_response_head};
