//! Blocking outbound TLS for the Sibuna console, through rustls (SID 0012).
//!
//! The console connects out to other consoles (management peer WebSockets), to webhook
//! receivers, to GeoIP publishers, and the `sibuna console` command talks to a remote
//! console. All of these go through this crate, which is the only one that depends on
//! `rustls`, `ring` and `rustls-native-certs`. The data plane never uses it.
//!
//! ```text
//!   Trust ---load---> Connector (Arc<ClientConfig>, built once)
//!                         |
//!   TcpStream ---connect(tcp, server_name, deadline)---> TlsStream: Read + Write
//! ```
//!
//! The policy is fixed: TLS 1.3 and 1.2 with the `ring` provider's default cipher suites;
//! certificates checked against the system roots or the operator's CA file; host-name
//! verification always on, with no way to turn it off; plain HTTP only to a literal
//! loopback address ([`is_plaintext_allowed`]), decided before connecting; and a deadline
//! over connect, handshake and exchange. Failures carry a plain-language
//! [`TlsError::hint`] and never fall back to plaintext.
//!
//! For the common one-shot case, [`connect`] resolves, connects and handshakes in one
//! call. The console itself builds one [`Connector`] at start-up, resolves and checks
//! addresses against its outbound policy (`sibuna-net`), and calls
//! [`Connector::connect_address`].
//!
//! With the `testing` feature, [`testing::Ingress`] is a TLS-terminating proxy for tests
//! of other crates: it presents a fixed test certificate (signed by the test CA of
//! [`testing::ca_file`], or deliberately wrong) and relays to a plain TCP listener, as the
//! HTTPS ingress in front of a console does (SID 0012). Only dev-dependencies enable it.
//!
//! # Changes from the Zig version
//!
//! - Zig's `std.http.Client` carried its own TLS client and certificate bundle per client
//!   value; the bundle was rescanned for every new client. Here the trust store is read
//!   once into a [`Connector`] whose configuration is shared by reference count, and the
//!   explicit `deinit` of the client and bundle is replaced by `Drop`.
//! - Zig ran each request against a concurrent sleeping task and cancelled the loser to
//!   enforce deadlines. Here a deadline is an [`std::time::Instant`]: the socket timeouts
//!   are re-armed to the time left before every socket operation, so neither the handshake
//!   nor the exchange can outlive it, and no second thread is needed.
//! - Zig's bundle skipped CA certificates already expired when the file was read. rustls
//!   (webpki) uses a trust anchor's name and key only and ignores its validity period, the
//!   convention of RFC 5280; the leaf and intermediates are still checked for expiry.
//! - The per-connection 6 MiB allocation ceiling of the Zig peer client is not carried
//!   over: rustls bounds its own buffers (handshake messages, records, and 64 KiB of
//!   buffered plaintext by default).

mod connector;
mod error;
mod plaintext;
mod stream;
mod trust;

#[cfg(feature = "testing")]
pub mod testing;

use std::net::ToSocketAddrs;
use std::time::Instant;

pub use connector::Connector;
pub use error::{CaFileProblem, CertificateProblem, TlsError};
pub use plaintext::{connect_plain, is_plaintext_allowed};
pub use stream::TlsStream;
pub use trust::{MAX_CA_FILE_BYTES, Trust};

/// The most addresses [`connect`] tries for one host, as sibuna-net's outbound bound.
pub const MAX_ADDRESSES: usize = 16;

/// Resolves `host`, connects to `port` and completes a TLS handshake that authenticates
/// `host` against `trust`, all before `deadline` (except name resolution, which the system
/// resolver bounds). Addresses are tried in order until one succeeds or the deadline
/// passes, at most [`MAX_ADDRESSES`] of them, as the Zig peer client did.
///
/// This loads `trust` on every call, which suits a one-shot command such as the
/// `sibuna console` client. It applies no address policy: a daemon that must keep a name
/// from reaching private networks resolves and checks the addresses itself and calls
/// [`Connector::connect_address`].
///
/// # Errors
///
/// The trust errors of [`Connector::load`], [`TlsError::InvalidServerName`],
/// [`TlsError::Unresolved`], or the error of the last address tried.
pub fn connect(
    host: &str,
    port: u16,
    trust: &Trust,
    deadline: Instant,
) -> Result<TlsStream, TlsError> {
    let connector = Connector::load(trust)?;
    let bare = host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(host);
    let addresses =
        (bare, port).to_socket_addrs().map_err(|_| TlsError::Unresolved(host.to_owned()))?;
    let mut last = TlsError::Unresolved(host.to_owned());
    for address in addresses.take(MAX_ADDRESSES) {
        match connector.connect_address(address, host, deadline) {
            Ok(stream) => return Ok(stream),
            // A bad name stays bad, and a timeout means the deadline has passed.
            Err(
                error @ (TlsError::InvalidServerName(_)
                | TlsError::ConnectTimeout
                | TlsError::HandshakeTimeout),
            ) => return Err(error),
            Err(error) => last = error,
        }
    }
    Err(last)
}
