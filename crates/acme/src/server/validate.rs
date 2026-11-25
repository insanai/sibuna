//! The HTTP-01 validation of the ACME server (RFC 8555, section 8.3): one outbound
//! request, with every bound that keeps it from being a tool for request forgery.
//!
//! ```text
//! resolve NAME          the resolver of the system
//!   |  keep the first address inside a range of `allow`; none: do not connect
//! connect ADDRESS:PORT  the address that was checked, never the name again
//!   |  GET /.well-known/acme-challenge/TOKEN, Host: NAME
//! read                  at most 8 KiB of header and 1 KiB of body, 10 seconds in all
//!   |  status 200 only; a redirect is a failure
//! compare               the body without white space at its ends = TOKEN.THUMBPRINT
//! ```

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::error::printable;

/// The time to connect.
const CONNECT: Duration = Duration::from_secs(5);
/// The time for the whole validation after the name is resolved.
const TOTAL: Duration = Duration::from_secs(10);
/// The most bytes of the header of the response.
const MAX_HEAD: usize = 8 * 1024;
/// The most bytes of the body of the response.
const MAX_BODY: usize = 1024;
/// The most addresses of a name that are looked at.
const MAX_ADDRESSES: usize = 16;

/// An address range: an address and the number of its leading bits that count.
pub type Range = (IpAddr, u8);

/// Whether `address` lies inside `range`. An IPv4 address inside an IPv6 address
/// counts as the IPv4 address.
pub fn in_range(address: IpAddr, range: Range) -> bool {
    let bits = |address: IpAddr| match address.to_canonical() {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32),
        IpAddr::V6(v6) => (u128::from(v6), 128),
    };
    let ((address, width), (base, base_width)) = (bits(address), bits(range.0));
    let prefix = u32::from(range.1);
    if width != base_width || prefix > width {
        return false;
    }
    let shift = width - prefix;
    shift >= 128 || (address >> shift) == (base >> shift)
}

/// What one validation needs.
#[derive(Clone, Copy, Debug)]
pub struct Target<'a> {
    /// The name under validation, a host name in lower case.
    pub name: &'a str,
    /// The token of the challenge.
    pub token: &'a str,
    /// The body that proves the name: the token, a dot and the thumbprint of the
    /// account key.
    pub expected: &'a str,
    /// The port to connect to: 80, unless the configuration says otherwise.
    pub port: u16,
    /// The ranges that the validation may connect into.
    pub ranges: &'a [Range],
}

/// The first address of the name that lies inside a range.
fn permitted_address(target: &Target<'_>) -> Result<SocketAddr, String> {
    let resolved = (target.name, target.port)
        .to_socket_addrs()
        .map_err(|_| format!("The name {} does not resolve.", target.name))?;
    let mut seen = 0;
    for address in resolved.take(MAX_ADDRESSES) {
        seen += 1;
        if target.ranges.iter().any(|range| in_range(address.ip(), *range)) {
            return Ok(address);
        }
    }
    Err(format!(
        "None of the {seen} address(es) of {} is one that this server may validate.",
        target.name
    ))
}

/// Reads the response until its end, a bound or the deadline. Returns the header
/// without its final blank line, and the body as far as it was read.
fn read_response(stream: &mut TcpStream, deadline: Instant) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        let head_end = bytes.windows(4).position(|window| window == b"\r\n\r\n");
        let full = match head_end {
            Some(end) => bytes.len() - (end + 4) > MAX_BODY,
            None if bytes.len() > MAX_HEAD => return Err("The header is too long.".to_owned()),
            None => false,
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("The response took too long.".to_owned());
        }
        let _ = stream.set_read_timeout(Some(left));
        let count = if full { 0 } else { stream.read(&mut buffer).unwrap_or(0) };
        if count == 0 {
            let end = head_end.ok_or("The response has no header.")?;
            let body = bytes.split_off(end + 4);
            bytes.truncate(end);
            return Ok((bytes, body));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

/// The status code of the first line of a header.
fn status(head: &[u8]) -> Option<u16> {
    let line = head.split(|byte| *byte == b'\n').next()?;
    let mut words = std::str::from_utf8(line).ok()?.split_ascii_whitespace();
    words.next().filter(|version| version.starts_with("HTTP/1."))?;
    words.next()?.parse().ok()
}

/// Validates one name with HTTP-01. Blocks for at most the time of the resolver of
/// the system plus 10 seconds. The error is a sentence for the client: it says what
/// failed and holds nothing of the response but its status.
pub fn http01(target: &Target<'_>) -> Result<(), String> {
    let address = permitted_address(target)?;
    let deadline = Instant::now() + TOTAL;
    let refused = |_| format!("No connection to {address} for {}.", target.name);
    let mut stream = TcpStream::connect_timeout(&address, CONNECT).map_err(refused)?;
    let _ = stream.set_write_timeout(Some(CONNECT));
    let host = match target.port {
        80 => target.name.to_owned(),
        port => format!("{}:{port}", target.name),
    };
    let request = format!(
        "GET /.well-known/acme-challenge/{} HTTP/1.1\r\nHost: {host}\r\n\
         User-Agent: sibuna-acme-server\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        target.token
    );
    stream.write_all(request.as_bytes()).map_err(|_| "The request could not be sent.")?;
    let (head, body) = read_response(&mut stream, deadline)?;
    match status(&head) {
        Some(200) => {}
        Some(code @ 300..=399) => {
            return Err(format!("The answer is a redirect ({code}). This server follows none."));
        }
        Some(code) => return Err(format!("The answer has the status {code}, not 200.")),
        None => return Err("The answer is no HTTP response.".to_owned()),
    }
    let chunked =
        head.to_ascii_lowercase().windows(26).any(|w| w == b"transfer-encoding: chunked");
    if chunked {
        return Err("The answer is chunked. This server reads a plain body only.".to_owned());
    }
    let found = String::from_utf8_lossy(body.get(..body.len().min(MAX_BODY)).unwrap_or_default());
    if found.trim() == target.expected {
        return Ok(());
    }
    let shown = printable(found.trim(), 64);
    Err(format!("The body is not the key authorization of the challenge. It begins: {shown}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::net::TcpListener;

    use super::*;

    /// Serves `response` to every connection on a loopback port, on a thread that
    /// lives as long as the test process. Returns the port and what was asked.
    fn responder(response: &'static str) -> (u16, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buffer = [0; 2048];
                let count = stream.read(&mut buffer).unwrap_or(0);
                let _ = sender.send(String::from_utf8_lossy(&buffer[..count]).into_owned());
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (port, receiver)
    }

    const LOOPBACK: &[Range] = &[(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 0)), 8)];

    fn target<'a>(port: u16, ranges: &'a [Range]) -> Target<'a> {
        Target { name: "localhost", token: "tok-1", expected: "tok-1.thumb", port, ranges }
    }

    #[test]
    fn ranges_compare_the_leading_bits_of_one_family() {
        let range = |text: &str, prefix| (text.parse::<IpAddr>().unwrap(), prefix);
        let inside = |address: &str, range| in_range(address.parse().unwrap(), range);
        assert!(
            inside("10.1.2.3", range("10.0.0.0", 8)) && !inside("11.0.0.1", range("10.0.0.0", 8))
        );
        assert!(inside("192.0.2.7", range("192.0.2.7", 32)));
        assert!(!inside("192.0.2.8", range("192.0.2.7", 32)));
        assert!(inside("203.0.113.9", range("0.0.0.0", 0)) && !inside("::1", range("0.0.0.0", 0)));
        assert!(inside("fd00::5", range("fd00::", 8)) && !inside("fe80::1", range("fd00::", 8)));
        assert!(inside("::1", range("::", 0)) && !inside("10.0.0.1", range("::", 0)));
        // An IPv4 address inside an IPv6 address is the IPv4 address.
        assert!(inside("::ffff:10.1.2.3", range("10.0.0.0", 8)));
        assert!(!inside("10.0.0.1", range("10.0.0.0", 33)));
    }

    #[test]
    fn the_key_authorization_validates_and_the_request_is_the_fixed_one() {
        let (port, asked) =
            responder("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\ntok-1.thumb\r\n");
        assert_eq!(http01(&target(port, LOOPBACK)), Ok(()));
        let request = asked.recv().unwrap();
        assert!(request.starts_with("GET /.well-known/acme-challenge/tok-1 HTTP/1.1\r\n"));
        assert!(request.contains(&format!("\r\nHost: localhost:{port}\r\n")), "{request}");
    }

    #[test]
    fn an_address_outside_the_ranges_is_not_contacted() {
        let (port, asked) = responder("HTTP/1.1 200 OK\r\n\r\ntok-1.thumb");
        let elsewhere: &[Range] = &[(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 0)), 8)];
        let error = http01(&target(port, elsewhere)).unwrap_err();
        assert!(error.contains("may validate"), "{error}");
        assert!(http01(&target(port, &[])).is_err());
        assert!(asked.try_recv().is_err());
        let missing = Target { name: "no-such-name.invalid", ..target(port, LOOPBACK) };
        assert!(http01(&missing).unwrap_err().contains("does not resolve"));
    }

    #[test]
    fn a_redirect_another_status_and_another_body_fail() {
        let (port, _asked) = responder(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/x\r\nContent-Length: 0\r\n\r\n",
        );
        let error = http01(&target(port, LOOPBACK)).unwrap_err();
        assert!(error.contains("redirect (302)") && !error.contains("127.0.0.1:1"), "{error}");
        let (port, _asked) = responder("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        assert!(http01(&target(port, LOOPBACK)).unwrap_err().contains("status 404"));
        let (port, _asked) = responder("HTTP/1.1 200 OK\r\n\r\ntok-1.other\x1b[31m");
        let error = http01(&target(port, LOOPBACK)).unwrap_err();
        assert!(error.contains("tok-1.other?[31m"), "{error}");
        let (port, _asked) = responder("SSH-2.0-OpenSSH\r\n\r\n");
        assert!(http01(&target(port, LOOPBACK)).unwrap_err().contains("no HTTP response"));
        let (port, _asked) = responder(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\ntok-1.thumb\r\n0\r\n\r\n",
        );
        assert!(http01(&target(port, LOOPBACK)).unwrap_err().contains("chunked"));
        // Nobody listens: the port of a listener that is gone.
        let gone = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert!(http01(&target(gone, LOOPBACK)).unwrap_err().contains("No connection"));
    }

    #[test]
    fn a_response_over_the_bounds_is_cut_or_refused() {
        // A body that goes on after the key authorization is not read to its end.
        let long: &'static str = Box::leak(
            format!("HTTP/1.1 200 OK\r\n\r\n{}", "x".repeat(64 * 1024)).into_boxed_str(),
        );
        let (port, _asked) = responder(long);
        assert!(
            http01(&target(port, LOOPBACK)).unwrap_err().contains("not the key authorization")
        );
        let head: &'static str = Box::leak(
            format!("HTTP/1.1 200 OK\r\nX: {}\r\n", "y".repeat(16 * 1024)).into_boxed_str(),
        );
        let (port, _asked) = responder(head);
        assert!(http01(&target(port, LOOPBACK)).unwrap_err().contains("header is too long"));
    }
}
