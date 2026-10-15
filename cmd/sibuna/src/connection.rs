//! The per-connection loop: read a head, buffer what fits of the body, dispatch.
//!
//! A connection owns one 64 KiB read buffer and one 16 KiB write buffer for the life of the
//! socket. The request head, its fields, cookies, the buffered body and every policy input
//! are slices of the read buffer, so classification, challenge verification and the proxy
//! hand-off allocate nothing. The borrow checker proves that no slice is read after the
//! buffer is refilled.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use sibuna_http::Method;
use sibuna_http::chunked::Decoder;
use sibuna_http::response::{self, Status};
use sibuna_http::{ParseError, Request, Version, parse_request};
use sibuna_net::Upload;
use sibuna_net::Workspace;
use sibuna_net::buffered::{ReadError, Reader, Writer};

use crate::client_writer::ClientWriter;
use crate::context::Ctx;
use crate::server::Server;
use crate::slot::EngineCache;

/// The connection buffer: one request head and as much of its body as fits.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// The longest request head accepted.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// The most requests one connection serves; the last response announces the close.
pub const MAX_REQUESTS_PER_CONNECTION: u32 = 4096;
/// The declared length of a chunked body whose end is not yet buffered.
pub const UNKNOWN_LENGTH: usize = usize::MAX;
const WRITE_BUFFER: usize = 16 * 1024;

/// The client side of a connection that outlives each request.
pub(crate) struct Link<'c, W> {
    pub server: &'c Server,
    pub stream: &'c TcpStream,
    pub writer: W,
    pub workspace: Workspace,
    pub cache: EngineCache,
    pub activity: &'c sibuna_net::Activity,
    /// The last request this connection may serve: its response announces the close.
    pub last: bool,
}

/// Serves one accepted connection until it closes, fails, is reaped or reaches the request
/// bound.
pub fn serve(server: &Server, stream: &TcpStream) {
    let Some(lease) = server.idle.register(stream) else { return };
    if server.is_stopping() {
        return;
    }
    bound_client_writes(server, stream);
    let mut read_buffer = [0u8; MAX_REQUEST_BYTES];
    let mut write_buffer = [0u8; WRITE_BUFFER];
    // The normal forms of the request path and of a forwarded path, both from one head.
    let mut path_buffer = [0u8; MAX_HEAD_BYTES];
    let mut reader = Reader::new(stream, &mut read_buffer[..]);
    let mut peer = PeerText::default();
    peer.format(stream.peer_addr().ok());
    let mut link = Link {
        server,
        stream,
        writer: ClientWriter::new(Writer::new(stream, &mut write_buffer[..])),
        workspace: Workspace::new(),
        cache: EngineCache::new(),
        activity: lease.activity(),
        last: false,
    };
    for served in 0..MAX_REQUESTS_PER_CONNECTION {
        link.last = served + 1 == MAX_REQUESTS_PER_CONNECTION;
        if !serve_one(&mut reader, &mut link, peer.as_bytes(), &mut path_buffer) {
            break;
        }
        lease.touch();
    }
}

/// Gives the client socket a write timeout of the idle timeout: a client that accepts no
/// byte for that long fails the write and loses the connection, however busy the origin is.
/// The idle reaper bounds silence; this bounds a stalled reader on its own (SID 0002).
fn bound_client_writes(server: &Server, stream: &TcpStream) {
    let seconds = server.config.idle_timeout_seconds;
    if seconds > 0 {
        let _ = stream.set_write_timeout(Some(Duration::from_secs(u64::from(seconds))));
    }
}

/// How a request head ended.
enum Head {
    /// The head is complete; its length includes the blank line.
    Complete(usize),
    /// The client closed cleanly between requests.
    Closed,
    /// The head exceeds [`MAX_HEAD_BYTES`].
    TooLarge,
    /// The connection failed or closed inside a head.
    Failed,
}

/// Buffers bytes until a complete head is present, searching only the new bytes.
fn read_head(reader: &mut Reader<'_, &TcpStream>) -> Head {
    let mut searched: usize = 0;
    loop {
        let bytes = reader.buffered();
        let from = searched.saturating_sub(3);
        if let Some(at) = find_blank_line(bytes.get(from..).unwrap_or_default()) {
            let length = from + at + 4;
            return if length > MAX_HEAD_BYTES { Head::TooLarge } else { Head::Complete(length) };
        }
        if bytes.len() >= MAX_HEAD_BYTES {
            return Head::TooLarge;
        }
        searched = bytes.len();
        match reader.fill_more() {
            Ok(_) => {}
            Err(ReadError::EndOfStream) if searched == 0 => return Head::Closed,
            Err(_) => return Head::Failed,
        }
    }
}

fn find_blank_line(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Serves one request; `paths` holds the normal forms of its paths. Returns whether the
/// connection may serve another.
fn serve_one<W: Write>(
    reader: &mut Reader<'_, &TcpStream>,
    link: &mut Link<'_, ClientWriter<W>>,
    peer: &[u8],
    paths: &mut [u8],
) -> bool {
    link.writer.begin_response(false);
    let head_len = match read_head(reader) {
        Head::Complete(length) => length,
        Head::TooLarge => {
            let text = b"Request head exceeds 16 KB";
            let _ = response::write_text(&mut link.writer, Status::HeadersTooLarge, text, false);
            return false;
        }
        Head::Closed | Head::Failed => return false,
    };
    let framing = {
        let bytes = reader.buffered();
        let head = bytes.get(..head_len).unwrap_or_default();
        let request = match parse_request(head) {
            Ok(request) => request,
            Err(error) => return reject_head(link, error),
        };
        // Every response to HEAD, Sibuna's own included, is a head without a body.
        link.writer.begin_response(request.method == Method::Head);
        if has_repeated_host(&request) {
            return reject_repeated_host(link);
        }
        let declared = request.content_length().unwrap_or(0);
        if !expect_continue(link, &request, declared, peer) {
            return false;
        }
        if declared == 0 && !request.chunked {
            // No body: the head parsed above is the request; nothing moves in the buffer.
            let upload = Upload::declared(&request);
            let pending = bytes.get(head_len..).unwrap_or_default();
            let keep = dispatch(link, request, pending, upload, 0, peer, paths);
            reader.consume(head_len);
            return keep;
        }
        (declared, request.chunked)
    };
    serve_with_body(reader, link, peer, paths, head_len, framing)
}

/// Buffers the body, then dispatches the request with it.
fn serve_with_body<W: Write>(
    reader: &mut Reader<'_, &TcpStream>,
    link: &mut Link<'_, W>,
    peer: &[u8],
    paths: &mut [u8],
    head_len: usize,
    (declared, chunked): (usize, bool),
) -> bool {
    let buffered = if chunked {
        buffer_chunked(reader, head_len)
    } else {
        buffer_length(reader, head_len, declared)
    };
    let (body_len, declared, upload) = match buffered {
        Ok(body) => body,
        Err(fault) => {
            let declared = if chunked { UNKNOWN_LENGTH } else { declared };
            return reject_body(reader, link, peer, head_len, declared, fault);
        }
    };
    let bytes = reader.buffered();
    // The head was parsed before the body moved the buffer; parsing is deterministic.
    let Ok(mut request) = parse_request(bytes.get(..head_len).unwrap_or_default()) else {
        return false;
    };
    request.body = bytes.get(head_len..head_len + body_len).unwrap_or_default();
    let pending = bytes.get(head_len + body_len..).unwrap_or_default();
    let keep = dispatch(link, request, pending, upload, declared, peer, paths);
    reader.consume(head_len + body_len);
    keep
}

/// Puts the request path in normal form, then dispatches the request. A path without a
/// normal form is answered 400 and the connection closed.
fn dispatch<W: Write>(
    link: &mut Link<'_, W>,
    request: Request<'_>,
    pending: &[u8],
    upload: Upload,
    declared_body: usize,
    peer: &[u8],
    paths: &mut [u8],
) -> bool {
    let Ok((request, spare)) = crate::dispatch::normalize_target(request, paths) else {
        link.server.metrics.parse_errors.bump();
        let _ = response::write_400(&mut link.writer, b"Malformed request target");
        return false;
    };
    let mut ctx = Ctx::new(link, request, peer, declared_body);
    ctx.pending = pending;
    ctx.upload = upload;
    crate::dispatch::dispatch(&mut ctx, spare).unwrap_or(false)
}

/// Why a body could not be buffered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyFault {
    Truncated,
    Malformed,
}

impl BodyFault {
    fn text(self) -> &'static [u8] {
        match self {
            BodyFault::Truncated => b"Truncated request body",
            BodyFault::Malformed => b"Malformed chunked request body",
        }
    }
}

/// Buffers up to one connection buffer of a `Content-Length` body. Returns the buffered
/// length, the declared length and the upload framing.
fn buffer_length(
    reader: &mut Reader<'_, &TcpStream>,
    head_len: usize,
    declared: usize,
) -> Result<(usize, usize, Upload), BodyFault> {
    let fits = declared.min(MAX_REQUEST_BYTES - head_len);
    reader.fill(head_len + fits).map_err(|_| BodyFault::Truncated)?;
    Ok((fits, declared, Upload::Length(declared as u64)))
}

/// Decodes a chunked body in place behind the head until it ends or the buffer is full (SID
/// 0009). Each step's framing is cut out of the buffer so the decoded prefix stays contiguous
/// for inspection; a body that ends here is forwarded with its length, otherwise the decoder
/// carries on in the proxy with the bytes still buffered.
fn buffer_chunked(
    reader: &mut Reader<'_, &TcpStream>,
    head_len: usize,
) -> Result<(usize, usize, Upload), BodyFault> {
    let mut decoder = Decoder::new();
    let mut decoded = 0;
    loop {
        let start = head_len + decoded;
        let window = reader.buffered_mut().get_mut(start..).unwrap_or_default();
        let step = decoder.decode(window).map_err(|_| BodyFault::Malformed)?;
        reader.remove(start + step.output, start + step.consumed);
        decoded += step.output;
        if decoder.is_done() {
            return Ok((decoded, decoded, Upload::Length(decoded as u64)));
        }
        if reader.buffered_len() == reader.capacity() {
            return Ok((decoded, UNKNOWN_LENGTH, Upload::Chunked(decoder)));
        }
        reader.fill_more().map_err(|_| BodyFault::Truncated)?;
    }
}

/// Answers a head that does not parse.
fn reject_head<W: Write>(link: &mut Link<'_, W>, error: ParseError) -> bool {
    link.server.metrics.parse_errors.bump();
    let writer = &mut link.writer;
    let _ = if error == ParseError::UnsupportedTransferEncoding {
        let text = b"Transfer coding not supported";
        response::write_text(writer, Status::NotImplemented, text, false)
    } else {
        response::write_400(writer, b"Malformed HTTP request")
    };
    false
}

/// True when `request` has more than one `Host` field. RFC 9112 section 3.2 requires a 400:
/// recipients disagree on which one counts, and a `Connection` field naming `host` once
/// made the proxy drop both.
fn has_repeated_host(request: &Request<'_>) -> bool {
    let mut hosts = request.headers().iter().filter(|h| h.name.eq_ignore_ascii_case(b"host"));
    hosts.next().is_some() && hosts.next().is_some()
}

/// Answers a request with more than one `Host` field.
fn reject_repeated_host<W: Write>(link: &mut Link<'_, W>) -> bool {
    link.server.metrics.parse_errors.bump();
    let _ = response::write_400(&mut link.writer, b"Malformed HTTP request: repeated Host field");
    false
}

/// The head identifies an external request even when its body is incomplete or malformed.
fn reject_body<W: Write>(
    reader: &Reader<'_, &TcpStream>,
    link: &mut Link<'_, W>,
    peer: &[u8],
    head_len: usize,
    declared: usize,
    fault: BodyFault,
) -> bool {
    let bytes = reader.buffered();
    if let Ok(request) = parse_request(bytes.get(..head_len).unwrap_or_default()) {
        let mut ctx = Ctx::new(link, request, peer, declared);
        crate::telemetry::record_outcome(&mut ctx, crate::telemetry::Outcome::Other, 400);
        crate::telemetry::observe_rejected_body(&ctx);
    }
    let _ = response::write_400(&mut link.writer, fault.text());
    false
}

/// A client may wait for 100 Continue before sending any body. We complete that exchange
/// locally; policy still checks the buffered prefix before any body reaches the origin.
/// Returns false when the expectation is refused (417).
fn expect_continue<W: Write>(
    link: &mut Link<'_, W>,
    request: &Request<'_>,
    declared: usize,
    peer: &[u8],
) -> bool {
    let mut count = 0;
    let mut supported = true;
    for header in request.headers().iter().filter(|h| h.name.eq_ignore_ascii_case(b"expect")) {
        count += 1;
        supported = supported && header.value.eq_ignore_ascii_case(b"100-continue");
    }
    if count == 0 {
        return true;
    }
    if !supported || count != 1 || request.version != Version::Http11 {
        let mut ctx = Ctx::new(link, request.clone(), peer, declared);
        crate::telemetry::record_outcome(&mut ctx, crate::telemetry::Outcome::Other, 400);
        let text = b"Unsupported expectation";
        let _ = response::write_text(&mut link.writer, Status::ExpectationFailed, text, false);
        return false;
    }
    if declared != 0 || request.chunked {
        let sent = link.writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        return sent.and_then(|()| link.writer.flush()).is_ok();
    }
    true
}

/// The peer address as text, formatted once per connection.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PeerText {
    bytes: [u8; 48],
    len: usize,
}

impl Default for PeerText {
    fn default() -> PeerText {
        PeerText { bytes: [0; 48], len: 0 }
    }
}

impl PeerText {
    /// Formats `address` as the Zig daemon did: dotted IPv4, or eight uncompressed
    /// lower-case hexadecimal groups for IPv6. An unknown peer is `0.0.0.0`.
    pub(crate) fn format(&mut self, address: Option<SocketAddr>) {
        let mut cursor = &mut self.bytes[..];
        let written = match address {
            Some(SocketAddr::V4(v4)) => {
                let [a, b, c, d] = v4.ip().octets();
                write!(cursor, "{a}.{b}.{c}.{d}")
            }
            Some(SocketAddr::V6(v6)) => {
                let groups = v6.ip().segments();
                write!(
                    cursor,
                    "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    groups[0],
                    groups[1],
                    groups[2],
                    groups[3],
                    groups[4],
                    groups[5],
                    groups[6],
                    groups[7]
                )
            }
            None => cursor.write_all(b"0.0.0.0"),
        };
        let remaining = cursor.len();
        self.len = if written.is_ok() { 48 - remaining } else { 0 };
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddrV6};

    use super::*;

    #[test]
    fn peers_are_formatted_as_the_zig_daemon_did() {
        let mut peer = PeerText::default();
        peer.format(Some("203.0.113.9:4000".parse().unwrap()));
        assert_eq!(peer.as_bytes(), b"203.0.113.9");
        let address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        peer.format(Some(SocketAddr::V6(SocketAddrV6::new(address, 80, 0, 0))));
        assert_eq!(peer.as_bytes(), b"2001:db8:0:0:0:0:0:1");
        peer.format(None);
        assert_eq!(peer.as_bytes(), b"0.0.0.0");
    }

    #[test]
    fn the_blank_line_search_finds_the_end_of_a_head() {
        assert_eq!(find_blank_line(b"GET / HTTP/1.1\r\n\r\nbody"), Some(14));
        assert_eq!(find_blank_line(b"GET / HTTP/1.1\r\n"), None);
    }
}
