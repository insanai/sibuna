//! One DNS question and its answer: over UDP, and over TCP when the answer was cut.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use super::wire;

/// The largest answer read over UDP.
const MAX_UDP: usize = 4096;
/// A message over this size goes over TCP at once (the safe size of RFC 9715).
const MAX_UDP_REQUEST: usize = 1232;
/// The most datagrams read while we wait for ours.
const MAX_DATAGRAMS: usize = 8;

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "no answer in time")
}

/// The time left until `deadline`, or the error of a timeout.
fn left(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() { Err(timed_out()) } else { Ok(left) }
}

/// Sends `request` to `server` and returns the answer with the same identifier. The
/// whole exchange takes at most `timeout`. An answer is at most 4096 bytes over UDP and
/// 65535 bytes over TCP. The caller checks the content.
pub fn exchange(server: SocketAddr, request: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    if request.len() <= MAX_UDP_REQUEST {
        let answer = exchange_udp(server, request, deadline)?;
        if !wire::is_truncated(&answer) {
            return Ok(answer);
        }
    }
    exchange_tcp(server, request, deadline)
}

fn exchange_udp(server: SocketAddr, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
    let socket = match server {
        SocketAddr::V4(_) => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?,
        SocketAddr::V6(_) => UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?,
    };
    // A connected socket takes datagrams of the server only.
    socket.connect(server)?;
    socket.send(request)?;
    let mut buffer = vec![0; MAX_UDP];
    for _ in 0..MAX_DATAGRAMS {
        socket.set_read_timeout(Some(left(deadline)?))?;
        let length = match socket.recv(&mut buffer) {
            Ok(length) => length,
            Err(error) if is_timeout(&error) => return Err(timed_out()),
            Err(error) => return Err(error),
        };
        if length >= 2 && request.starts_with(&buffer[..2]) {
            buffer.truncate(length);
            return Ok(buffer);
        }
    }
    Err(timed_out())
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

fn exchange_tcp(server: SocketAddr, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
    let length = u16::try_from(request.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the message is too long"))?;
    let mut stream = TcpStream::connect_timeout(&server, left(deadline)?)?;
    stream.set_write_timeout(Some(left(deadline)?))?;
    let mut framed = Vec::with_capacity(request.len() + 2);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(request);
    stream.write_all(&framed)?;
    let mut prefix = [0; 2];
    read_exact(&mut stream, &mut prefix, deadline)?;
    let mut answer = vec![0; usize::from(u16::from_be_bytes(prefix))];
    read_exact(&mut stream, &mut answer, deadline)?;
    Ok(answer)
}

/// Fills `buffer` from the stream before `deadline`.
fn read_exact(stream: &mut TcpStream, buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        stream.set_read_timeout(Some(left(deadline)?))?;
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => filled += count,
            Err(error) if is_timeout(&error) => return Err(timed_out()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
