//! A bounded HTTP/1.1 listener with joinable workers, deadlines and WebSocket upgrades.
//!
//! This is the service kernel of SID 0007: the console's listener, with no firewall,
//! storage or application knowledge. The application supplies a [`Handler`]; the kernel
//! supplies the rest.
//!
//! - [`Server::start`] binds a socket and starts one acceptor and one watchdog thread. Each
//!   admitted connection gets one of `max_slots` (default 96) slots and a worker thread of
//!   its own, with a 16 KiB receive buffer on its stack. A full table is answered with 503
//!   and `Retry-After: 1`; a head longer than the buffer with 431.
//! - Every connection carries one request. The handler receives a [`Context`]: the parsed
//!   head (by `sibuna_http::parse_request`), the peer address, [`Context::header`] which
//!   refuses repeated fields, [`Context::body`] bounded by the caller's buffer and answering
//!   `Expect: 100-continue`, the deadline, and the three response writers
//!   [`Context::respond`], [`Context::respond_cached`] and [`Context::respond_isolated`]
//!   with the console's security fields.
//! - Deadlines (head 10 s, body 30 s, response 30 s, or what the handler sets with
//!   [`Context::extend`]) are enforced by the watchdog, which shuts down the socket of an
//!   expired connection and so wakes whatever blocks on it.
//! - [`Context::upgrade`] accepts a WebSocket upgrade under an admission [`Class`] and hands
//!   the handler a [`WebSocket`]: a `FrameReader` and a [`Sender`] over the same socket.
//!   [`Admission`] keeps `http_reserved` slots that browser and peer streams can never take.
//! - [`Server::stop`] joins every thread the server started; no detached work survives it.
//!
//! ```no_run
//! use sibuna_serve::{Context, Options, ServeError, Server};
//!
//! let handler = |context: &mut Context<'_>| -> Result<(), ServeError> {
//!     context.respond(200, b"text/plain", b"bounded service", &[])
//! };
//! let server = Server::start("127.0.0.1:0".parse().unwrap(), handler, Options::default())?;
//! // ... serve until shutdown ...
//! server.stop();
//! # Ok::<(), sibuna_serve::StartError>(())
//! ```
//!
//! # Changes from the Zig version
//!
//! `libs/serve/src/{kernel,context,admission,stack}.zig` are the specification. The codec,
//! frame reader and handshake helpers of `websocket{,_io,_upgrade}.zig` live in
//! `sibuna_http::websocket`, with their tests. Bytes on the wire are unchanged: the 503 and
//! 431 replies, the 100 Continue and 101 heads, and each response's status line (Zig's
//! reason phrases), `connection`/`content-length` spelling and security fields are those of
//! Zig 0.16's `std.http.Server` as the console used it. The port differs as follows.
//!
//! - Heads are parsed by `sibuna_http::parse_request` instead of `std.http.Server`. Its
//!   grammar is stricter (whitespace before a colon, more than 32 fields and conflicting
//!   framing are refused), and the refusal is the same: the connection closes without a
//!   reply. Zig's other refusals are kept: methods outside Zig's `std.http.Method`, a
//!   repeated `Content-Length`, and a head ending in a bare `\n\n`.
//! - A body cut short by the peer is [`ServeError::EndOfStream`]; Zig's `readSliceShort`
//!   returned the truncated body as if complete.
//! - The application's state is owned by the [`Handler`] (a closure or a type) instead of
//!   an `*anyopaque` beside a function pointer, and handler errors are counted in
//!   [`Counters`] instead of logged: libraries never print.
//! - [`Admission`] is wired into the listener: a connection is admitted as HTTP and
//!   [`Context::upgrade`] transfers it to its class. Zig's kernel counted the 96 slots and
//!   the console kept a separate 64-subscriber counter, leaving `admission.zig` an unwired
//!   reference; the bounds are the same (96 slots, 64 browsers, 16 HTTP slots reserved).
//! - Deadlines are kept in milliseconds instead of whole seconds, so a 10-second deadline
//!   is 10 seconds rather than 9 to 10. Timeouts are [`Options`] fields with Zig's values as
//!   defaults.
//! - The extra header fields of a response are not limited to four: they are written
//!   straight to the socket instead of being copied into a ten-entry array. Invalid fields
//!   are [`ServeError::InvalidResponse`] instead of a debug assertion.
//! - Memory management is Rust's: the kernel is an `Arc` instead of a heap object freed by
//!   `stop`, `Drop` replaces the `errdefer` chains and the `defer` that frees a slot (it runs
//!   even if a handler panics), the watchdog holds a duplicated socket handle instead of
//!   sharing a descriptor under a lock, a [`Context`] borrows its buffer and socket so no
//!   slice can outlive the connection, and a [`WebSocket`] borrows the context so no HTTP
//!   response can follow an upgrade.
//! - The thread stack no longer adds Zig's 256 KiB thread-local signal stack ([`stack`]).
//! - The acceptor sleeps 10 ms after a failed `accept` instead of retrying at once, and
//!   stop retries its wake-up connection for up to ten seconds.

#![warn(missing_docs)]

mod admission;
mod body;
mod context;
mod deadline;
mod error;
mod head;
mod response;
mod server;
pub mod stack;
#[cfg(test)]
mod test_util;
mod websocket;

pub use admission::{Admission, AdmissionError, Capacity, Class};
pub use context::{Context, Input};
pub use deadline::Deadline;
pub use error::{ServeError, StartError};
pub use head::MAX_HEAD;
pub use response::{CONSOLE_POLICY, ISOLATED_POLICY, phrase};
pub use server::{Counters, Handler, Options, Server};
pub use websocket::{Sender, WebSocket};
