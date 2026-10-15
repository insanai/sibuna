//! The one place plain HTTP is allowed: a literal loopback address.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Instant;

use crate::connector::connect_tcp;
use crate::error::TlsError;

/// Whether plain (unencrypted) HTTP may be spoken to `host`: only when it is a literal
/// loopback address, `127.0.0.0/8` or `::1`, with or without IPv6 brackets.
///
/// Names are refused, `localhost` included, because a resolver or a hosts file could send
/// them anywhere; so are IPv4-mapped IPv6 forms such as `::ffff:127.0.0.1`. The rule is
/// the Zig CLI client's `validateOrigin`, and SID 0012 makes it the rule for every
/// outbound connection of the console.
pub fn is_plaintext_allowed(host: &str) -> bool {
    loopback_literal(host).is_some()
}

/// Connects plain TCP to `host:port` before `deadline`, after checking the loopback rule
/// of [`is_plaintext_allowed`]. The check happens before any connection is attempted.
///
/// # Errors
///
/// [`TlsError::PlaintextRefused`] when `host` is not a literal loopback address, otherwise
/// [`TlsError::ConnectTimeout`] or [`TlsError::Connect`].
pub fn connect_plain(host: &str, port: u16, deadline: Instant) -> Result<TcpStream, TlsError> {
    let ip = loopback_literal(host).ok_or_else(|| TlsError::PlaintextRefused(host.to_owned()))?;
    connect_tcp(SocketAddr::new(ip, port), deadline)
}

fn loopback_literal(host: &str) -> Option<IpAddr> {
    let bare = host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']'));
    let ip = match bare {
        // Brackets belong to IPv6 only.
        Some(inner) => IpAddr::V6(inner.parse().ok()?),
        None => host.parse().ok()?,
    };
    // `Ipv6Addr::is_loopback` is exactly `::1`, as Zig's check was.
    ip.is_loopback().then_some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cases of the Zig CLI test "CLI origins forbid plaintext remote authorities".
    #[test]
    fn plaintext_only_to_literal_loopback() {
        for host in ["127.0.0.1", "127.1.2.3", "::1", "[::1]", "0:0:0:0:0:0:0:1"] {
            assert!(is_plaintext_allowed(host), "{host}");
        }
        for host in [
            "localhost",
            "192.0.2.1",
            "10.0.0.1",
            "::ffff:127.0.0.1",
            "[127.0.0.1]",
            "[::1",
            "::1]",
            "0.0.0.0",
            "::",
            "",
            "127.0.0.1 ",
            "127.0.0.1:80",
        ] {
            assert!(!is_plaintext_allowed(host), "{host}");
        }
    }

    #[test]
    fn plaintext_to_a_remote_host_is_refused_before_connecting() {
        // 192.0.2.0/24 is TEST-NET-1: a connection attempt would hang, so returning at
        // once shows no attempt was made.
        let started = Instant::now();
        let deadline = started + std::time::Duration::from_secs(30);
        for host in ["192.0.2.1", "localhost", "example.com"] {
            let refused = connect_plain(host, 80, deadline);
            assert!(matches!(refused, Err(TlsError::PlaintextRefused(ref h)) if h == host));
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    /// Deterministic fuzz: arbitrary bytes never panic, and acceptance implies loopback.
    #[test]
    fn arbitrary_hosts_never_panic() {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet = b"0123456789abcdef:.[]x ";
        let mut host = String::with_capacity(48);
        for _ in 0..100_000 {
            host.clear();
            for _ in 0..next() % 40 {
                host.push(char::from(alphabet[(next() % alphabet.len() as u64) as usize]));
            }
            if let Some(ip) = loopback_literal(&host) {
                assert!(ip.is_loopback(), "{host}");
            }
        }
    }
}
