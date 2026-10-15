//! The console's blocking HTTP/1.1 client (unit U2; Zig's `console_client.zig`), used by the
//! `sibuna console` commands, GeoIP downloads and webhook deliveries.
//!
//! One call is one exchange on a new connection: [`send`] connects, writes the request with
//! `Connection: close`, reads the response head (at most 16 KiB, parsed by
//! `sibuna_net::parse_response_head`) and then the body, framed by
//! `Content-Length`, the chunked coding or the end of the connection, never more than the
//! caller's bound. Everything, from connecting to the last byte, finishes before one
//! deadline. Redirects are not followed: a 3xx response is returned as it is, and the
//! caller decides (the commands refuse it; a GeoIP download follows one redirect itself).
//!
//! ```text
//! Origin::parse("https://console.example")          split_url("https://host/a/b?c")
//!        |                                                 |
//! Endpoint { origin, address: None, connector }     (Origin, "/a/b?c")
//!        |
//! send(&endpoint, &Request { method, target, fields, body, .. },
//!      &Limits { deadline, max_body }) -> Response { status, head, body }
//! ```
//!
//! Transport rules (SID 0012): `https` goes through `sibuna_tls` with the caller's
//! [`Connector`] (its trust store, host-name verification always on); plain `http` is
//! allowed only to a literal loopback address, checked when the origin is parsed and again
//! before connecting. A caller that applies an address policy (webhooks) resolves the name
//! itself, checks every address, and pins the chosen one in [`Endpoint::address`]; without a
//! pinned address the host is resolved with the system resolver, which the deadline does
//! not bound.
//!
//! # Changes from Zig
//!
//! - Zig raced each request against a sleeping task and cancelled the loser; here the
//!   deadline is an [`Instant`] and the socket timeouts are re-armed before every read and
//!   write, so no second thread is needed. No operation blocks longer than [`SLICE`]
//!   before the deadline and the caller's cancellation check ([`send_cancellable`]) are
//!   looked at again, so a stopping console never waits for a silent server.
//! - Zig's endpoint enum and its fixed paths are gone: callers pass the request-target, so
//!   one client serves the commands, downloads and webhooks.
//! - A `Content-Encoding` other than `identity` is refused, as Zig refused it; a 1xx
//!   interim response is refused too (the client never asks for one).

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use sibuna_crypto::ct;
use sibuna_http::chunked::Decoder;
use sibuna_net::{Framing, MAX_RESPONSE_HEAD, parse_response_head};
use sibuna_tls::{Connector, TlsError, TlsStream};

/// The longest origin accepted.
pub const MAX_ORIGIN: usize = 255;
/// The longest request-target accepted.
pub const MAX_TARGET: usize = 4096;
/// The most addresses tried for one host name.
pub const MAX_ADDRESSES: usize = 16;
/// The longest one read or write blocks before the deadline and the cancellation check
/// are looked at again.
pub const SLICE: Duration = Duration::from_millis(250);
/// The longest one connection attempt waits: attempts start at [`SLICE`] and double up to
/// this, so a server more than 250 ms away can still answer a SYN.
const MAX_CONNECT_SLICE: Duration = Duration::from_secs(1);

/// The scheme of an [`Origin`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// Plain HTTP, only to a literal loopback address.
    Http,
    /// HTTP over TLS.
    Https,
}

/// A validated origin: `http://` or `https://`, then a host and an optional port, and
/// nothing else (no user information, path, query or fragment).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Origin {
    text: String,
    scheme: Scheme,
    host: String,
    port: u16,
}

impl Origin {
    /// Parses `text` with the rules of Zig's `validateOrigin`: at most 255 bytes, scheme
    /// `http` or `https`, an authority of printable ASCII without `/ ? # @ % \`, a non-empty
    /// host, a port from 1 to 65535 when given; `http` only to a literal loopback address
    /// (127.0.0.0/8 or `::1`).
    ///
    /// Fails with [`ClientError::InvalidOrigin`] for a malformed origin and with
    /// [`ClientError::InsecureOrigin`] for plain HTTP to any other host.
    pub fn parse(text: &str) -> Result<Origin, ClientError> {
        let invalid = ClientError::InvalidOrigin;
        if text.len() > MAX_ORIGIN {
            return Err(invalid);
        }
        let (scheme, authority) = match text.strip_prefix("https://") {
            Some(authority) => (Scheme::Https, authority),
            None => (Scheme::Http, text.strip_prefix("http://").ok_or(invalid)?),
        };
        let printable = |byte: u8| byte > 32 && byte < 127 && !b"/?#@%\\".contains(&byte);
        if authority.is_empty() || !authority.bytes().all(printable) {
            return Err(ClientError::InvalidOrigin);
        }
        let (host, port) = split_authority(authority).ok_or(ClientError::InvalidOrigin)?;
        let default = if scheme == Scheme::Https { 443 } else { 80 };
        let port = port.unwrap_or(default);
        if scheme == Scheme::Http && !sibuna_tls::is_plaintext_allowed(host) {
            return Err(ClientError::InsecureOrigin);
        }
        Ok(Origin { text: text.to_owned(), scheme, host: host.to_owned(), port })
    }

    /// Borrows the origin as given; requests send it as their `Origin` field.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the scheme.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Borrows the host as written (an IPv6 literal keeps its brackets).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the port, the scheme's default when none was written.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the `Host` field value: the host, and the port unless it is the default.
    pub fn authority(&self) -> String {
        let default = if self.scheme == Scheme::Https { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Splits `host[:port]` or `[v6]:port`; `None` for an empty host, a bad port or port 0.
fn split_authority(authority: &str) -> Option<(&str, Option<u16>)> {
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']')?;
        let (host, rest) = authority.split_at(end + 1);
        match rest {
            "" => (host, None),
            rest => (host, Some(rest.strip_prefix(':')?)),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() || host == "[]" || (!host.starts_with('[') && host.contains(':')) {
        return None;
    }
    let port = match port {
        None => None,
        Some(digits) => {
            if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            Some(digits.parse::<u16>().ok().filter(|&port| port != 0)?)
        }
    };
    Some((host, port))
}

/// Splits an absolute URL into its [`Origin`] and request-target (`/` when it has no path),
/// for downloads and redirects.
///
/// Fails like [`Origin::parse`], and with [`ClientError::InvalidOrigin`] for a target with
/// a fragment, a space, a control byte or more than [`MAX_TARGET`] bytes.
pub fn split_url(url: &str) -> Result<(Origin, &str), ClientError> {
    let start = if url.starts_with("https://") { 8 } else { 7 };
    let end = url.get(start..).and_then(|rest| rest.find(['/', '?']).map(|at| at + start));
    let (origin, target) = url.split_at(end.unwrap_or(url.len()));
    let origin = Origin::parse(origin)?;
    let target = if target.is_empty() { "/" } else { target };
    if target.starts_with('?') || !valid_target(target) {
        return Err(ClientError::InvalidOrigin);
    }
    Ok((origin, target))
}

fn valid_target(target: &str) -> bool {
    target.len() <= MAX_TARGET
        && target.starts_with('/')
        && target.bytes().all(|byte| byte > 32 && byte < 127 && byte != b'#')
}

/// Where a request goes.
#[derive(Clone, Copy, Debug)]
pub struct Endpoint<'a> {
    /// The server's origin; its host is the TLS server name and the `Host` field.
    pub origin: &'a Origin,
    /// For `https`, the address to connect to, already resolved and checked by the caller;
    /// `None` resolves the host. Ignored for `http`, which always connects to the loopback
    /// literal of the origin.
    pub address: Option<SocketAddr>,
    /// The TLS configuration; required for `https`.
    pub connector: Option<&'a Connector>,
}

/// The request method.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`, without a body.
    #[default]
    Get,
    /// `POST`, with a body (possibly empty) and its content type.
    Post,
}

/// One request.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// The method.
    pub method: Method,
    /// The request-target: a path starting with `/`, with an optional query.
    pub target: &'a str,
    /// Further header fields, such as `Origin`, `Cookie` or `Authorization`. `Host`,
    /// `Connection`, `Accept-Encoding`, `Content-Type` and `Content-Length` are written by
    /// the client.
    pub fields: &'a [(&'a str, &'a str)],
    /// The body of a `POST`.
    pub body: &'a [u8],
    /// The content type of a `POST` body.
    pub content_type: &'a str,
}

impl Default for Request<'_> {
    fn default() -> Self {
        Request {
            method: Method::Get,
            target: "/",
            fields: &[],
            body: &[],
            content_type: "application/json",
        }
    }
}

/// The bounds of one exchange.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Connecting, writing and reading all finish before this.
    pub deadline: Instant,
    /// The most body bytes accepted.
    pub max_body: usize,
}

/// A response. The head and body are wiped when it is dropped: they may hold a session
/// cookie, a token or a temporary password.
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The head, status line and fields, without the blank line.
    pub head: Vec<u8>,
    /// The body, decoded from the chunked coding when it was chunked.
    pub body: Vec<u8>,
}

impl Response {
    /// Returns the value of the only field named `name` (case-insensitive), trimmed; `None`
    /// when it is absent, repeated or not text.
    pub fn header<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        let mut values = self.headers(name);
        let first = values.next()?;
        values.next().is_none().then_some(first)
    }

    /// Returns the values of every field named `name` (case-insensitive), trimmed.
    pub fn headers<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        let text = std::str::from_utf8(&self.head).unwrap_or_default();
        text.split("\r\n").skip(1).filter_map(move |line| {
            let (field, value) = line.split_once(':')?;
            field.eq_ignore_ascii_case(name).then(|| value.trim_matches([' ', '\t']))
        })
    }
}

impl fmt::Debug for Response {
    /// Shows the status and sizes only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("head", &self.head.len())
            .field("body", &self.body.len())
            .finish()
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        ct::zeroize(&mut self.head);
        ct::zeroize(&mut self.body);
    }
}

/// Why an exchange failed.
#[derive(Debug)]
pub enum ClientError {
    /// The origin or URL is malformed.
    InvalidOrigin,
    /// Plain HTTP was asked for a host that is not a literal loopback address.
    InsecureOrigin,
    /// A header field or the target would break the request.
    InvalidRequest,
    /// HTTPS was asked for without a TLS configuration.
    TlsRequired,
    /// Connecting, the TLS handshake, or the server's certificate failed.
    Tls(TlsError),
    /// Reading or writing failed, or the server closed early.
    Transport(io::Error),
    /// The deadline passed.
    Deadline,
    /// The response head or body is larger than its bound.
    TooLarge,
    /// The response is not well-formed HTTP/1.1, or uses an encoding the client refuses.
    InvalidResponse,
}

impl ClientError {
    /// Returns a sentence that tells the operator how to proceed.
    pub fn hint(&self) -> &'static str {
        match self {
            ClientError::InvalidOrigin | ClientError::InsecureOrigin => {
                "Use HTTPS or literal loopback HTTP."
            }
            ClientError::InvalidRequest => "Check the request fields.",
            ClientError::TlsRequired => "Configure the trust store for HTTPS.",
            ClientError::Tls(error) => error.hint(),
            ClientError::Transport(_)
            | ClientError::Deadline
            | ClientError::TooLarge
            | ClientError::InvalidResponse => {
                "Outcome unknown. Query the affected resource before retrying."
            }
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::InvalidOrigin => f.write_str("the origin or URL is malformed"),
            ClientError::InsecureOrigin => {
                f.write_str("plain HTTP is allowed only to a literal loopback address")
            }
            ClientError::InvalidRequest => f.write_str("a request field is malformed"),
            ClientError::TlsRequired => f.write_str("HTTPS needs a TLS configuration"),
            ClientError::Tls(error) => error.fmt(f),
            ClientError::Transport(error) => write!(f, "the connection failed: {error}"),
            ClientError::Deadline => f.write_str("the server did not answer before the deadline"),
            ClientError::TooLarge => f.write_str("the response is larger than allowed"),
            ClientError::InvalidResponse => f.write_str("the response is not valid HTTP"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Tls(error) => Some(error),
            ClientError::Transport(error) => Some(error),
            _ => None,
        }
    }
}

impl From<TlsError> for ClientError {
    fn from(error: TlsError) -> ClientError {
        match error {
            TlsError::ConnectTimeout | TlsError::HandshakeTimeout => ClientError::Deadline,
            TlsError::PlaintextRefused(_) => ClientError::InsecureOrigin,
            other => ClientError::Tls(other),
        }
    }
}

/// Maps a socket error: a timeout is the deadline.
fn io_error(error: io::Error) -> ClientError {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ClientError::Deadline,
        _ => ClientError::Transport(error),
    }
}

/// `GET target` from `endpoint` with `fields`; see [`send`].
///
/// Fails like [`send`].
#[cfg(test)]
pub fn get(
    endpoint: &Endpoint<'_>,
    target: &str,
    fields: &[(&str, &str)],
    limits: &Limits,
) -> Result<Response, ClientError> {
    send(endpoint, &Request { method: Method::Get, target, fields, ..Request::default() }, limits)
}

/// `POST target` to `endpoint` with `fields` and a JSON `body`; see [`send`].
///
/// Fails like [`send`].
#[cfg(test)]
pub fn post_json(
    endpoint: &Endpoint<'_>,
    target: &str,
    fields: &[(&str, &str)],
    body: &[u8],
    limits: &Limits,
) -> Result<Response, ClientError> {
    let request = Request { method: Method::Post, target, fields, body, ..Request::default() };
    send(endpoint, &request, limits)
}

/// Runs one exchange: connects to `endpoint`, writes `request`, and reads the response
/// within `limits`. The connection is closed when this returns.
///
/// Fails with [`ClientError::InvalidRequest`] for a target or field that would break the
/// request (checked before connecting), [`ClientError::InsecureOrigin`] or
/// [`ClientError::TlsRequired`] before connecting, [`ClientError::Tls`] when connecting or
/// the handshake fails, [`ClientError::Deadline`] when the deadline passes,
/// [`ClientError::TooLarge`] for a head over 16 KiB or a body over `limits.max_body`,
/// [`ClientError::InvalidResponse`] for a malformed response, a 1xx status or a content
/// coding, and [`ClientError::Transport`] when the connection fails or ends early.
pub fn send(
    endpoint: &Endpoint<'_>,
    request: &Request<'_>,
    limits: &Limits,
) -> Result<Response, ClientError> {
    send_cancellable(endpoint, request, limits, &|| false)
}

/// Runs one exchange as [`send`] does, and also gives up when `cancel` returns true: no
/// socket operation, connection attempt or TLS handshake step blocks longer than
/// [`SLICE`] (a connection attempt at most one second) before `cancel` is called again. A
/// stopping console passes its stop flag, so a server that never answers cannot hold it
/// until the deadline. Name resolution without a pinned address is not covered: it waits
/// for the system resolver, which its own configuration bounds.
///
/// Fails like [`send`]; a canceled exchange fails with [`ClientError::Deadline`].
pub fn send_cancellable(
    endpoint: &Endpoint<'_>,
    request: &Request<'_>,
    limits: &Limits,
    cancel: &dyn Fn() -> bool,
) -> Result<Response, ClientError> {
    let mut head = request_head(endpoint.origin, request)?;
    let mut stream = match connect(endpoint, limits.deadline, cancel) {
        Ok(stream) => stream,
        Err(error) => {
            ct::zeroize(&mut head);
            return Err(error);
        }
    };
    let written = stream
        .write_all(&head)
        .and_then(|()| stream.write_all(request.body))
        .and_then(|()| stream.flush());
    ct::zeroize(&mut head);
    written.map_err(io_error)?;
    read_response(&mut stream, limits.max_body)
}

/// Writes the request head; refuses fields and targets that would break it.
fn request_head(origin: &Origin, request: &Request<'_>) -> Result<Vec<u8>, ClientError> {
    let text_ok = |text: &str| text.bytes().all(|byte| byte == b'\t' || (32..127).contains(&byte));
    let field_ok = |(name, value): &(&str, &str)| {
        sibuna_http::is_valid_token(name.as_bytes()) && text_ok(value)
    };
    if !valid_target(request.target)
        || !text_ok(request.content_type)
        || !request.fields.iter().all(field_ok)
    {
        return Err(ClientError::InvalidRequest);
    }
    let method = if request.method == Method::Post { "POST" } else { "GET" };
    let mut head = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n",
        request.target,
        origin.authority()
    );
    for (name, value) in request.fields {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    if request.method == Method::Post {
        head.push_str("Content-Type: ");
        head.push_str(request.content_type);
        head.push_str("\r\nContent-Length: ");
        head.push_str(&request.body.len().to_string());
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    Ok(head.into_bytes())
}

/// A plain TCP socket whose reads and writes block at most [`SLICE`] at a time and give
/// up at the deadline or when `cancel` returns true; both end as
/// [`io::ErrorKind::TimedOut`].
pub(crate) struct Socket<'a> {
    tcp: TcpStream,
    deadline: Instant,
    cancel: &'a dyn Fn() -> bool,
}

impl<'a> Socket<'a> {
    /// Connects to `address` before `deadline`, in attempts of [`SLICE`] growing to one
    /// second, calling `cancel` after each attempt that timed out.
    ///
    /// Fails with [`io::ErrorKind::TimedOut`] at the deadline or when canceled, and with
    /// the connection's error.
    pub(crate) fn connect(
        address: SocketAddr,
        deadline: Instant,
        cancel: &'a dyn Fn() -> bool,
    ) -> io::Result<Socket<'a>> {
        let mut slice = SLICE;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || cancel() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            match TcpStream::connect_timeout(&address, left.min(slice)) {
                Ok(tcp) => return Ok(Socket { tcp, deadline, cancel }),
                Err(error) if is_timeout(&error) => slice = (slice * 2).min(MAX_CONNECT_SLICE),
                Err(error) => return Err(error),
            }
        }
    }

    /// Returns `TimedOut` once the deadline has passed or `cancel` returns true.
    fn check(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline || (self.cancel)() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }

    /// Sets both socket timeouts to the time left, at most [`SLICE`].
    fn arm(&self) -> io::Result<()> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.tcp.set_read_timeout(Some(left.min(SLICE)))?;
        self.tcp.set_write_timeout(Some(left.min(SLICE)))
    }
}

/// A socket timeout shows as `WouldBlock` on Unix and `TimedOut` on Windows.
fn is_timeout(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

impl Read for Socket<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            self.arm()?;
            match self.tcp.read(buffer) {
                Err(error) if is_timeout(&error) => self.check()?,
                other => return other,
            }
        }
    }
}

impl Write for Socket<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            self.arm()?;
            match self.tcp.write(buffer) {
                Err(error) if is_timeout(&error) => self.check()?,
                other => return other,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

/// A connection whose every operation waits at most [`SLICE`] before the deadline and the
/// cancellation are checked again.
enum Stream<'a> {
    Plain(Socket<'a>),
    Tls { tls: Box<TlsStream>, deadline: Instant, cancel: &'a dyn Fn() -> bool },
}

impl Stream<'_> {
    /// Runs `operation` on the TLS stream in slices: rustls keeps its state across a
    /// socket timeout, so a timed-out read or write is retried until the deadline passes
    /// or `cancel` returns true.
    fn tls_slices<T>(
        tls: &mut TlsStream,
        deadline: Instant,
        cancel: &dyn Fn() -> bool,
        mut operation: impl FnMut(&mut TlsStream) -> io::Result<T>,
    ) -> io::Result<T> {
        loop {
            let now = Instant::now();
            if now >= deadline || cancel() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            tls.set_deadline(Some(deadline.min(now + SLICE)))?;
            match operation(tls) {
                Err(error) if is_timeout(&error) => {}
                other => return other,
            }
        }
    }
}

impl Read for Stream<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(socket) => socket.read(buffer),
            Stream::Tls { tls, deadline, cancel } => {
                Stream::tls_slices(tls, *deadline, *cancel, |tls| tls.read(buffer))
            }
        }
    }
}

impl Write for Stream<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(socket) => socket.write(buffer),
            Stream::Tls { tls, deadline, cancel } => {
                Stream::tls_slices(tls, *deadline, *cancel, |tls| tls.write(buffer))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(socket) => socket.flush(),
            Stream::Tls { tls, deadline, cancel } => {
                Stream::tls_slices(tls, *deadline, *cancel, TlsStream::flush)
            }
        }
    }
}

/// Returns the address of a plain-HTTP host: a literal loopback address, with or without
/// IPv6 brackets.
fn plaintext_address(host: &str) -> Option<IpAddr> {
    if !sibuna_tls::is_plaintext_allowed(host) {
        return None;
    }
    host.trim_start_matches('[').trim_end_matches(']').parse().ok()
}

/// Connects TCP in slices and runs the TLS handshake for `server_name` in slices.
fn connect_tls<'a>(
    connector: &Connector,
    address: SocketAddr,
    server_name: &str,
    deadline: Instant,
    cancel: &'a dyn Fn() -> bool,
) -> Result<Stream<'a>, TlsError> {
    let socket = Socket::connect(address, deadline, cancel).map_err(|error| {
        if is_timeout(&error) { TlsError::ConnectTimeout } else { TlsError::Connect(error) }
    })?;
    // Nagle's algorithm only delays a request-response exchange; failure changes nothing.
    let _ = socket.tcp.set_nodelay(true);
    let tls = connector.connect_cancellable(socket.tcp, server_name, deadline, cancel)?;
    Ok(Stream::Tls { tls: Box::new(tls), deadline, cancel })
}

fn connect<'a>(
    endpoint: &Endpoint<'_>,
    deadline: Instant,
    cancel: &'a dyn Fn() -> bool,
) -> Result<Stream<'a>, ClientError> {
    let origin = endpoint.origin;
    if origin.scheme == Scheme::Http {
        let ip = plaintext_address(&origin.host).ok_or(ClientError::InsecureOrigin)?;
        let socket = Socket::connect(SocketAddr::new(ip, origin.port), deadline, cancel).map_err(
            |error| {
                if is_timeout(&error) {
                    ClientError::Deadline
                } else {
                    ClientError::Tls(TlsError::Connect(error))
                }
            },
        )?;
        return Ok(Stream::Plain(socket));
    }
    let connector = endpoint.connector.ok_or(ClientError::TlsRequired)?;
    if let Some(address) = endpoint.address {
        return Ok(connect_tls(connector, address, &origin.host, deadline, cancel)?);
    }
    let unresolved = || ClientError::Tls(TlsError::Unresolved(origin.host.clone()));
    let bare = origin.host.trim_start_matches('[').trim_end_matches(']');
    let addresses = (bare, origin.port).to_socket_addrs().map_err(|_| unresolved())?;
    let mut last = unresolved();
    for address in addresses.take(MAX_ADDRESSES) {
        match connect_tls(connector, address, &origin.host, deadline, cancel) {
            Ok(stream) => return Ok(stream),
            // A bad name or certificate stays bad on every address; a timeout means the
            // deadline has passed or the exchange was canceled.
            Err(error @ (TlsError::InvalidServerName(_) | TlsError::Certificate { .. })) => {
                return Err(error.into());
            }
            Err(error) => last = error.into(),
        }
        if matches!(last, ClientError::Deadline) {
            break;
        }
    }
    Err(last)
}

/// Reads the head, checks it, and reads the body it frames, at most `max_body` bytes.
fn read_response<R: Read>(stream: &mut R, max_body: usize) -> Result<Response, ClientError> {
    let (mut head, mut rest) = read_head(stream)?;
    let parsed = parse_response_head(&head, false);
    head.truncate(head.len().saturating_sub(4));
    let mut response = Response { status: 0, head, body: Vec::new() };
    let refused = match parsed {
        None => true,
        Some(parsed) => {
            response.status = parsed.status;
            let mut codings = response.headers("Content-Encoding");
            let coded =
                codings.next().is_some_and(|coding| !coding.eq_ignore_ascii_case("identity"));
            parsed.status / 100 == 1 || coded || codings.next().is_some()
        }
    };
    let framing = parsed.map(|parsed| parsed.framing);
    let body = match framing {
        _ if refused => Err(ClientError::InvalidResponse),
        None | Some(Framing::None) => Ok(Vec::new()),
        Some(Framing::Length(length)) => read_length(stream, &mut rest, length, max_body),
        Some(Framing::Chunked) => read_chunked(stream, &mut rest, max_body),
        Some(Framing::UntilClose) => read_to_close(stream, &mut rest, max_body),
    };
    ct::zeroize(&mut rest);
    response.body = body?;
    Ok(response)
}

/// Reads until the blank line that ends the head; returns the head (blank line included)
/// and the bytes read after it.
fn read_head<R: Read>(stream: &mut R) -> Result<(Vec<u8>, Vec<u8>), ClientError> {
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut searched: usize = 0;
    loop {
        let from = searched.saturating_sub(3);
        let found = buffer
            .get(from..)
            .and_then(|tail: &[u8]| tail.windows(4).position(|window| window == b"\r\n\r\n"));
        if let Some(at) = found {
            let rest = buffer.split_off(from + at + 4);
            return Ok((buffer, rest));
        }
        searched = buffer.len();
        if buffer.len() > MAX_RESPONSE_HEAD {
            ct::zeroize(&mut buffer);
            return Err(ClientError::TooLarge);
        }
        let read = match stream.read(&mut chunk) {
            Ok(0) => Err(ClientError::InvalidResponse),
            Ok(read) => Ok(read),
            Err(error) => Err(io_error(error)),
        };
        let read = read.inspect_err(|_| ct::zeroize(&mut buffer))?;
        buffer.extend_from_slice(chunk.get(..read).unwrap_or_default());
    }
}

/// Reads a body of `length` bytes, of which `start` already arrived with the head.
fn read_length<R: Read>(
    stream: &mut R,
    start: &mut Vec<u8>,
    length: u64,
    max_body: usize,
) -> Result<Vec<u8>, ClientError> {
    let length = usize::try_from(length).ok().filter(|&length| length <= max_body);
    let length = length.ok_or(ClientError::TooLarge)?;
    let mut body = std::mem::take(start);
    body.truncate(length);
    let filled = body.len();
    body.resize(length, 0);
    match stream.read_exact(body.get_mut(filled..).unwrap_or_default()) {
        Ok(()) => Ok(body),
        Err(error) => {
            ct::zeroize(&mut body);
            Err(io_error(error))
        }
    }
}

/// Reads a body that ends when the server closes the connection.
fn read_to_close<R: Read>(
    stream: &mut R,
    start: &mut Vec<u8>,
    max_body: usize,
) -> Result<Vec<u8>, ClientError> {
    let mut body = std::mem::take(start);
    let mut chunk = [0u8; 4096];
    let result = loop {
        if body.len() > max_body {
            break Err(ClientError::TooLarge);
        }
        match stream.read(&mut chunk) {
            Ok(0) => break Ok(()),
            Ok(read) => body.extend_from_slice(chunk.get(..read).unwrap_or_default()),
            Err(error) => break Err(io_error(error)),
        }
    };
    ct::zeroize(&mut chunk);
    match result {
        Ok(()) => Ok(body),
        Err(error) => {
            ct::zeroize(&mut body);
            Err(error)
        }
    }
}

/// Decodes a chunked body in place. The raw bytes read are bounded too, by twice the body
/// bound plus 64 KiB, so a server cannot keep the client busy with chunk extensions.
fn read_chunked<R: Read>(
    stream: &mut R,
    raw: &mut Vec<u8>,
    max_body: usize,
) -> Result<Vec<u8>, ClientError> {
    let raw_limit = max_body.saturating_mul(2).saturating_add(64 * 1024);
    let mut body = Vec::new();
    let mut decoder = Decoder::new();
    let mut received = raw.len();
    let mut chunk = [0u8; 4096];
    let result = loop {
        let Ok(step) = decoder.decode(raw) else { break Err(ClientError::InvalidResponse) };
        body.extend_from_slice(raw.get(..step.output).unwrap_or_default());
        let consumed = step.consumed.min(raw.len());
        ct::zeroize(raw.get_mut(..consumed).unwrap_or_default());
        raw.drain(..consumed);
        if body.len() > max_body || received > raw_limit {
            break Err(ClientError::TooLarge);
        }
        if decoder.is_done() {
            break Ok(());
        }
        match stream.read(&mut chunk) {
            Ok(0) => break Err(ClientError::InvalidResponse),
            Ok(read) => {
                raw.extend_from_slice(chunk.get(..read).unwrap_or_default());
                received = received.saturating_add(read);
            }
            Err(error) => break Err(io_error(error)),
        }
    };
    ct::zeroize(&mut chunk);
    match result {
        Ok(()) => Ok(body),
        Err(error) => {
            ct::zeroize(&mut body);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread::JoinHandle;
    use std::time::Duration;

    /// Serves one connection: reads a request (head and `Content-Length` body), writes
    /// `response`, closes, and returns the request bytes.
    fn serve(response: Vec<u8>) -> (Origin, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let thread = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = socket.read(&mut chunk).unwrap_or(0);
                request.extend_from_slice(&chunk[..read]);
                let text = String::from_utf8_lossy(&request).into_owned();
                if let Some(end) = text.find("\r\n\r\n") {
                    let length = text
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .map_or(0, |value| value.parse::<usize>().unwrap());
                    if request.len() >= end + 4 + length || read == 0 {
                        break;
                    }
                }
                if read == 0 {
                    break;
                }
            }
            let _ = socket.write_all(&response);
            request
        });
        (Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap(), thread)
    }

    fn limits(max_body: usize) -> Limits {
        Limits { deadline: Instant::now() + Duration::from_secs(5), max_body }
    }

    fn exchange(response: &[u8], max_body: usize) -> Result<Response, ClientError> {
        let (origin, server) = serve(response.to_vec());
        let endpoint = Endpoint { origin: &origin, address: None, connector: None };
        let result = get(&endpoint, "/x", &[], &limits(max_body));
        server.join().unwrap();
        result
    }

    // console_client.zig: "CLI origins forbid plaintext remote authorities, credentials,
    // redirects and encodings".
    #[test]
    fn origins_forbid_plaintext_remote_authorities_and_credentials() {
        for valid in ["http://127.0.0.1:9443", "http://[::1]:9443", "https://console.example:443"]
        {
            assert!(Origin::parse(valid).is_ok(), "{valid}");
        }
        for insecure in ["http://localhost:9443", "http://192.0.2.1:9443"] {
            assert!(matches!(Origin::parse(insecure), Err(ClientError::InsecureOrigin)));
        }
        for invalid in [
            "https://console.example/path",
            "https://user@console.example",
            "https://a%2eb",
            "https://console.example?x=1",
            "https://console.example#x",
            "https://a:0",
            "https://",
            "ftp://a",
            "https://a:65536",
            "https://a:b",
            "https://[::1",
            "https://::1",
        ] {
            assert!(
                matches!(Origin::parse(invalid), Err(ClientError::InvalidOrigin)),
                "{invalid}"
            );
        }
        let origin = Origin::parse("https://[2001:db8::1]:8443").unwrap();
        assert_eq!((origin.host(), origin.port()), ("[2001:db8::1]", 8443));
        assert_eq!(origin.authority(), "[2001:db8::1]:8443");
        assert_eq!(Origin::parse("https://a").unwrap().authority(), "a");
        assert!(Origin::parse(&format!("https://{}", "a".repeat(250))).is_err());
    }

    #[test]
    fn urls_split_into_origin_and_target() {
        let (origin, target) = split_url("https://download.example/a/b.csv?x=1").unwrap();
        assert_eq!((origin.as_str(), target), ("https://download.example", "/a/b.csv?x=1"));
        assert_eq!(split_url("https://a.example").unwrap().1, "/");
        assert!(split_url("https://a.example/#x").is_err());
        assert!(split_url("https://a.example?x").is_err());
        assert!(split_url("http://example.com/a").is_err());
        assert!(split_url("https://a.example/a b").is_err());
    }

    #[test]
    fn requests_carry_the_fields_and_refuse_injection() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: a=1\r\n\
            Set-Cookie: b=2\r\n\r\nok"
            .to_vec();
        let (origin, server) = serve(response);
        let endpoint = Endpoint { origin: &origin, address: None, connector: None };
        let fields = [("Origin", origin.as_str()), ("X-Console-CSRF", "abc")];
        let reply =
            post_json(&endpoint, "/console/api/login", &fields, b"{}", &limits(16)).unwrap();
        let request = String::from_utf8(server.join().unwrap()).unwrap();
        let port = origin.port();
        assert_eq!(
            request,
            format!(
                "POST /console/api/login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
                 Connection: close\r\nAccept-Encoding: identity\r\nOrigin: http://127.0.0.1:\
                 {port}\r\nX-Console-CSRF: abc\r\nContent-Type: application/json\r\n\
                 Content-Length: 2\r\n\r\n{{}}"
            )
        );
        assert_eq!((reply.status, reply.body.as_slice()), (200, b"ok".as_slice()));
        assert_eq!(reply.headers("set-cookie").collect::<Vec<_>>(), ["a=1", "b=2"]);
        assert_eq!(reply.header("Set-Cookie"), None);
        assert_eq!(reply.header("content-length"), Some("2"));
        for fields in [[("X", "a\r\nInjected: 1")], [("Bad Name", "a")]] {
            let request = Request { fields: &fields, ..Request::default() };
            let refused = send(&endpoint, &request, &limits(16));
            assert!(matches!(refused, Err(ClientError::InvalidRequest)));
        }
        let request = Request { target: "/a\r\n", ..Request::default() };
        assert!(matches!(
            send(&endpoint, &request, &limits(16)),
            Err(ClientError::InvalidRequest)
        ));
    }

    #[test]
    fn bodies_are_framed_and_bounded() {
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n\
            6\r\n world\r\n0\r\n\r\n";
        assert_eq!(exchange(chunked, 11).unwrap().body, b"hello world");
        assert!(matches!(exchange(chunked, 10), Err(ClientError::TooLarge)));
        let close = b"HTTP/1.1 200 OK\r\n\r\nuntil the end";
        assert_eq!(exchange(close, 13).unwrap().body, b"until the end");
        assert!(matches!(exchange(close, 12), Err(ClientError::TooLarge)));
        let oversize = b"HTTP/1.1 200 OK\r\nContent-Length: 16385\r\n\r\n{}";
        assert!(matches!(exchange(oversize, 16384), Err(ClientError::TooLarge)));
        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab";
        assert!(matches!(exchange(short, 16), Err(ClientError::Transport(_))));
        let empty = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert_eq!(exchange(empty, 0).unwrap().status, 204);
    }

    #[test]
    fn redirects_codings_and_bad_heads_are_not_followed() {
        let redirect =
            b"HTTP/1.1 302 Found\r\nLocation: /credential-trap\r\nContent-Length: 0\r\n\r\n";
        let reply = exchange(redirect, 16).unwrap();
        assert_eq!((reply.status, reply.header("Location")), (302, Some("/credential-trap")));
        let gzip = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(exchange(gzip, 16), Err(ClientError::InvalidResponse)));
        let identity =
            b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 0\r\n\r\n";
        assert!(exchange(identity, 16).is_ok());
        let interim = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n";
        assert!(matches!(exchange(interim, 16), Err(ClientError::InvalidResponse)));
        assert!(matches!(exchange(b"nonsense\r\n\r\n", 16), Err(ClientError::InvalidResponse)));
        assert!(matches!(exchange(b"HTTP/1.1 200 OK\r\n", 16), Err(ClientError::InvalidResponse)));
        let mut huge = b"HTTP/1.1 200 OK\r\n".to_vec();
        huge.extend(std::iter::repeat_n(b'a', MAX_RESPONSE_HEAD + 10));
        assert!(matches!(exchange(&huge, 16), Err(ClientError::TooLarge)));
    }

    #[test]
    fn the_deadline_bounds_a_silent_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let endpoint = Endpoint { origin: &origin, address: None, connector: None };
        let started = Instant::now();
        let deadline = started + Duration::from_millis(300);
        let result = get(&endpoint, "/", &[], &Limits { deadline, max_body: 16 });
        assert!(matches!(result, Err(ClientError::Deadline)), "{result:?}");
        assert!(started.elapsed() < Duration::from_secs(3));
        drop(listener);
        let https = Origin::parse("https://console.example").unwrap();
        let endpoint = Endpoint { origin: &https, address: None, connector: None };
        assert!(matches!(get(&endpoint, "/", &[], &limits(1)), Err(ClientError::TlsRequired)));
    }

    #[test]
    fn cancellation_ends_a_silent_exchange_long_before_its_deadline() {
        // The backlog completes each TCP connection; nothing ever answers.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let plain = Origin::parse(&format!("http://{address}")).unwrap();
        let https = Origin::parse("https://localhost").unwrap();
        let ca = concat!(env!("CARGO_MANIFEST_DIR"), "/../tls/tests/data/ca.pem");
        let connector = Connector::load(&sibuna_tls::Trust::from_ca_file(ca)).unwrap();
        let endpoints = [
            Endpoint { origin: &plain, address: None, connector: None },
            Endpoint { origin: &https, address: Some(address), connector: Some(&connector) },
        ];
        for endpoint in endpoints {
            let started = Instant::now();
            let limits = Limits { deadline: started + Duration::from_secs(30), max_body: 16 };
            let cancel = || started.elapsed() >= Duration::from_millis(300);
            let request = Request::default();
            let result = send_cancellable(&endpoint, &request, &limits, &cancel);
            assert!(matches!(result, Err(ClientError::Deadline)), "{result:?}");
            let elapsed = started.elapsed();
            assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
            assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        }
        drop(listener);
    }

    /// A deterministic xorshift generator for the fuzz test.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound as u64) as usize
        }
    }

    /// A reader that returns its input in pieces of random size.
    struct Pieces<'a> {
        input: &'a [u8],
        rng: Rng,
    }

    impl Read for Pieces<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.input.len().min(buffer.len()).min(1 + self.rng.below(64));
            let (head, rest) = self.input.split_at(count);
            buffer[..count].copy_from_slice(head);
            self.input = rest;
            Ok(count)
        }
    }

    #[test]
    fn mutated_responses_never_panic_and_stay_bounded() {
        let seeds: [&[u8]; 4] = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              5;a=b\r\nhello\r\n0\r\nX: y\r\n\r\n",
            b"HTTP/1.0 404 Not Found\r\nConnection: close\r\n\r\nmissing",
            b"HTTP/1.1 302 Found\r\nLocation: https://a.example/\r\nContent-Length: 0\r\n\r\n",
        ];
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        for round in 0..100_000 {
            let mut input = seeds[round % seeds.len()].to_vec();
            for _ in 0..1 + rng.below(4) {
                match rng.below(4) {
                    0 if !input.is_empty() => {
                        let at = rng.below(input.len());
                        input[at] ^= 1 << rng.below(8);
                    }
                    1 => input.truncate(rng.below(input.len() + 1)),
                    2 if !input.is_empty() => {
                        let at = rng.below(input.len());
                        let piece = input[at..].to_vec();
                        input.extend_from_slice(&piece[..piece.len().min(32)]);
                    }
                    _ => {
                        let other = seeds[rng.below(seeds.len())];
                        let at = rng.below(input.len() + 1);
                        input.splice(at..at, other[..rng.below(other.len())].iter().copied());
                    }
                }
            }
            let mut reader = Pieces { input: &input, rng: Rng(rng.next() | 1) };
            if let Ok(response) = read_response(&mut reader, 8) {
                assert!(response.body.len() <= 8);
                assert!((100..1000).contains(&response.status));
            }
        }
    }
}
