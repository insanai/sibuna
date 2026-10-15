//! The client configuration, built once, and the handshake under a deadline.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::error::TlsError;
use crate::stream::TlsStream;
use crate::trust::Trust;

/// A shared, immutable TLS client configuration: the trust anchors, TLS 1.3 and 1.2 with
/// the `ring` provider's default cipher suites, and no client certificate.
///
/// Building one reads the trust store, so a program builds it once at start-up and clones
/// it (a reference count) into every thread that connects. The configuration also holds
/// rustls' in-memory session cache, so later connections to the same server resume.
#[derive(Clone, Debug)]
pub struct Connector {
    config: Arc<ClientConfig>,
    root_count: usize,
}

impl Connector {
    /// Loads the anchors `trust` names and builds the configuration.
    ///
    /// # Errors
    ///
    /// The trust errors of [`Trust`] ([`TlsError::NoTrustAnchors`],
    /// [`TlsError::SystemRoots`], [`TlsError::CaFile`]), or [`TlsError::Handshake`] in
    /// the unexpected case that rustls refuses the protocol versions.
    pub fn load(trust: &Trust) -> Result<Connector, TlsError> {
        let roots = trust.load_roots()?;
        let root_count = roots.len();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(TlsError::Handshake)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Connector { config: Arc::new(config), root_count })
    }

    /// The number of trust anchors loaded.
    pub fn root_count(&self) -> usize {
        self.root_count
    }

    /// Runs the TLS handshake over the connected `tcp` and authenticates `server_name`,
    /// all before `deadline`. `server_name` is a DNS name or an IP address literal (IPv6
    /// with or without brackets); it is sent as SNI when it is a name, and the certificate
    /// must list it either way.
    ///
    /// The returned stream keeps `deadline` for the exchange that follows; see
    /// [`TlsStream::set_deadline`]. The socket's read and write timeouts are changed.
    ///
    /// # Errors
    ///
    /// [`TlsError::InvalidServerName`], [`TlsError::HandshakeTimeout`],
    /// [`TlsError::Closed`], [`TlsError::Io`], [`TlsError::Certificate`] or
    /// [`TlsError::Handshake`]. On error the socket is dropped (closed).
    pub fn connect(
        &self,
        mut tcp: TcpStream,
        server_name: &str,
        deadline: Instant,
    ) -> Result<TlsStream, TlsError> {
        let name = parse_server_name(server_name)?;
        let mut connection = ClientConnection::new(Arc::clone(&self.config), name)
            .map_err(TlsError::from_rustls)?;
        handshake(&mut connection, &mut tcp, deadline)?;
        Ok(TlsStream::new(StreamOwned::new(connection, tcp), Some(deadline)))
    }

    /// Connects TCP to `address` and then runs [`Connector::connect`], all before
    /// `deadline`. This is the pinned connection of the console: the caller resolves the
    /// host and checks every address against its policy first, then authenticates the
    /// original `server_name` over the chosen address.
    ///
    /// # Errors
    ///
    /// [`TlsError::ConnectTimeout`] or [`TlsError::Connect`] for the TCP step, then the
    /// errors of [`Connector::connect`].
    pub fn connect_address(
        &self,
        address: SocketAddr,
        server_name: &str,
        deadline: Instant,
    ) -> Result<TlsStream, TlsError> {
        // Refuse a bad name before opening a connection we would only close again.
        parse_server_name(server_name)?;
        let tcp = connect_tcp(address, deadline)?;
        self.connect(tcp, server_name, deadline)
    }
}

/// Accepts `name`, `1.2.3.4`, `::1` and `[::1]`.
fn parse_server_name(text: &str) -> Result<ServerName<'static>, TlsError> {
    let invalid = || TlsError::InvalidServerName(text.to_owned());
    match text.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
        // Brackets belong to IPv6 literals only.
        Some(inner) => {
            let ip: Ipv6Addr = inner.parse().map_err(|_| invalid())?;
            Ok(ServerName::IpAddress(IpAddr::V6(ip).into()))
        }
        None => ServerName::try_from(text.to_owned()).map_err(|_| invalid()),
    }
}

/// Connects TCP before `deadline`, with Nagle's algorithm off: TLS writes whole records,
/// and request-response exchanges should not wait for a delayed acknowledgement.
pub(crate) fn connect_tcp(address: SocketAddr, deadline: Instant) -> Result<TcpStream, TlsError> {
    let remaining = remaining(deadline).ok_or(TlsError::ConnectTimeout)?;
    let tcp = TcpStream::connect_timeout(&address, remaining).map_err(|error| {
        if is_timeout(&error) { TlsError::ConnectTimeout } else { TlsError::Connect(error) }
    })?;
    tcp.set_nodelay(true).map_err(TlsError::Connect)?;
    Ok(tcp)
}

/// Drives the handshake one socket operation at a time, re-arming the socket timeouts
/// before each, so the whole handshake (not each read) is bounded by `deadline`; a server
/// that trickles one byte at a time cannot stretch it.
fn handshake(
    connection: &mut ClientConnection,
    tcp: &mut TcpStream,
    deadline: Instant,
) -> Result<(), TlsError> {
    while connection.is_handshaking() {
        arm(tcp, deadline)?;
        if connection.wants_write() {
            connection.write_tls(tcp).map_err(handshake_io)?;
        } else if connection.wants_read() {
            if connection.read_tls(tcp).map_err(handshake_io)? == 0 {
                return Err(TlsError::Closed);
            }
            if let Err(error) = connection.process_new_packets() {
                // Tell the server why, as the protocol asks; a failure to do so changes
                // nothing for us.
                let _ = connection.write_tls(tcp);
                return Err(TlsError::from_rustls(error));
            }
        } else {
            // rustls always wants one or the other while handshaking.
            return Err(TlsError::Closed);
        }
    }
    // The client's last flight (TLS 1.3 Finished) may still be queued.
    while connection.wants_write() {
        arm(tcp, deadline)?;
        connection.write_tls(tcp).map_err(handshake_io)?;
    }
    Ok(())
}

/// Sets both socket timeouts to the time left before `deadline`.
fn arm(tcp: &TcpStream, deadline: Instant) -> Result<(), TlsError> {
    let left = remaining(deadline).ok_or(TlsError::HandshakeTimeout)?;
    tcp.set_read_timeout(Some(left)).map_err(TlsError::Io)?;
    tcp.set_write_timeout(Some(left)).map_err(TlsError::Io)
}

fn handshake_io(error: io::Error) -> TlsError {
    if is_timeout(&error) { TlsError::HandshakeTimeout } else { TlsError::Io(error) }
}

/// The time left before `deadline`, or `None` once it has passed.
pub(crate) fn remaining(deadline: Instant) -> Option<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    (!left.is_zero()).then_some(left)
}

/// A socket timeout shows as `WouldBlock` on Unix and `TimedOut` on Windows.
pub(crate) fn is_timeout(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_names_are_dns_names_or_address_literals() {
        for name in ["localhost", "peer.example", "127.0.0.1", "::1", "[::1]", "[2001:db8::1]"] {
            assert!(parse_server_name(name).is_ok(), "{name}");
        }
        for name in ["", "a b", "[::1", "exa mple.com", "[localhost]", "host/path"] {
            assert!(
                matches!(parse_server_name(name), Err(TlsError::InvalidServerName(_))),
                "{name}"
            );
        }
    }

    #[test]
    fn a_passed_deadline_has_no_time_left() {
        assert_eq!(remaining(Instant::now()), None);
        assert!(remaining(Instant::now() + Duration::from_secs(5)).is_some());
        let error = connect_tcp("127.0.0.1:9".parse().unwrap(), Instant::now());
        assert!(matches!(error, Err(TlsError::ConnectTimeout)));
    }
}
