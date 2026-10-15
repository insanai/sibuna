//! Bounded connections for probes and management traffic, and socket options.
//!
//! Every function here waits at most until a deadline: the connect itself, and each read and
//! write, so a silent peer cannot hold a probe thread past its budget. The Zig version had to
//! drive a non-blocking `connect` and `poll(2)` by hand because its runtime panicked on connect
//! timeouts; `std` gives the same bounds through `connect_timeout` and per-socket read and
//! write timeouts.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// The bound of [`connect_bounded`], as in the Zig daemon.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The peer could not be reached, or did not answer, before the deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Unreachable;

impl fmt::Display for Unreachable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("peer unreachable before the deadline")
    }
}

impl std::error::Error for Unreachable {}

/// Disables Nagle's algorithm on a connected stream. Sibuna coalesces each message in its
/// writer and flushes only before it would wait, so a kernel hold-back saves no packets and
/// delays the next small write until the peer acknowledges the last, up to its delayed-ACK
/// timer (40 ms on Linux). Failure only leaves the default behaviour, so it is ignored.
pub fn set_no_delay(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
}

/// Connects to `address`, waiting at most [`CONNECT_TIMEOUT`].
///
/// # Errors
///
/// [`Unreachable`] when the connection fails or the wait ends.
pub fn connect_bounded(address: SocketAddr) -> Result<TcpStream, Unreachable> {
    TcpStream::connect_timeout(&address, CONNECT_TIMEOUT).map_err(|_| Unreachable)
}

/// Connects to `address`, waiting at most until `deadline`.
///
/// # Errors
///
/// [`Unreachable`] when the deadline has passed, the connection fails or the wait ends.
pub fn connect_deadline(address: SocketAddr, deadline: Instant) -> Result<TcpStream, Unreachable> {
    let left = time_left(deadline)?;
    TcpStream::connect_timeout(&address, left).map_err(|_| Unreachable)
}

fn time_left(deadline: Instant) -> Result<Duration, Unreachable> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(Unreachable),
    }
}

/// Writes all of `bytes`, each write waiting at most until `deadline`.
///
/// # Errors
///
/// [`Unreachable`] when a write fails or the deadline passes first.
pub fn write_bounded(
    mut stream: &TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), Unreachable> {
    let mut offset = 0;
    while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
        stream.set_write_timeout(Some(time_left(deadline)?)).map_err(|_| Unreachable)?;
        match stream.write(rest) {
            Ok(0) => return Err(Unreachable),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Unreachable),
        }
    }
    Ok(())
}

/// Reads until the peer closes, `out` is full, or the deadline passes; returns the number of
/// bytes read.
///
/// # Errors
///
/// [`Unreachable`] when a read fails or the deadline passes before the peer closes or `out`
/// fills.
pub fn read_bounded(
    mut stream: &TcpStream,
    out: &mut [u8],
    deadline: Instant,
) -> Result<usize, Unreachable> {
    let mut length = 0;
    while let Some(space) = out.get_mut(length..).filter(|space| !space.is_empty()) {
        stream.set_read_timeout(Some(time_left(deadline)?)).map_err(|_| Unreachable)?;
        match stream.read(space) {
            Ok(0) => return Ok(length),
            Ok(count) => length += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Unreachable),
        }
    }
    Ok(length)
}

/// Wakes up to `count` threads blocked in `accept` on a listener bound to `address` by
/// connecting to it and closing at once, so they can see a stop flag. An unspecified address
/// (`0.0.0.0` or `::`) is reached through loopback. Stops at the first failed connect. The
/// daemon's `requestStop` used this to stop without closing a descriptor under a blocked
/// `accept`.
pub fn wake_listener(address: SocketAddr, count: usize) {
    let mut target = address;
    if target.ip().is_unspecified() {
        let loopback = match address {
            SocketAddr::V4(_) => std::net::IpAddr::from([127, 0, 0, 1]),
            SocketAddr::V6(_) => std::net::IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1u16]),
        };
        target.set_ip(loopback);
    }
    for _ in 0..count {
        if connect_bounded(target).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn bounded_io_round_trip_and_deadlines() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let client = connect_deadline(address, deadline).unwrap();
        set_no_delay(&client);
        assert!(client.nodelay().unwrap());
        let (server, _) = listener.accept().unwrap();
        write_bounded(&client, b"ping", deadline).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut out = [0u8; 16];
        assert_eq!(read_bounded(&server, &mut out, deadline).unwrap(), 4);
        assert_eq!(&out[..4], b"ping");
        // A silent peer ends the read at the deadline.
        let soon = Instant::now() + Duration::from_millis(100);
        assert_eq!(read_bounded(&client, &mut out, soon), Err(Unreachable));
        assert_eq!(connect_deadline(address, Instant::now()).err(), Some(Unreachable));
    }

    #[test]
    fn wake_listener_reaches_an_unspecified_bind() {
        let listener = TcpListener::bind("0.0.0.0:0").unwrap();
        let address = listener.local_addr().unwrap();
        wake_listener(address, 2);
        listener.accept().unwrap();
        listener.accept().unwrap();
    }
}
