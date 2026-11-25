//! The view: what a hook sees of a flow or a request, and its wire form (SID 0030).
//!
//! Every tier reads the same record. The native tier borrows a [`View`]. The Wasm tier
//! and the agent tier receive [`encode`]d bytes. [`Edits`] holds the request fields that
//! a hook adds, after the checks that keep a hook from forging framing or our own
//! statements.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::verdict::{Failure, Stage};

/// The version byte of the wire form.
pub const WIRE_VERSION: u8 = 1;
/// The bytes of the wire form before its texts.
pub const WIRE_FIXED: usize = 48;

/// The protocol of the traffic a view describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// A TCP connection, also the connection of an HTTP frontend before its first request.
    Tcp,
    /// A UDP mapping.
    Udp,
    /// A request over HTTP/1.1.
    Http1,
    /// A request over HTTP/2.
    Http2,
    /// A request over HTTP/3.
    Http3,
}

impl Protocol {
    /// The byte of the protocol in the wire form.
    pub fn wire(self) -> u8 {
        match self {
            Protocol::Tcp => 1,
            Protocol::Udp => 2,
            Protocol::Http1 => 3,
            Protocol::Http2 => 4,
            Protocol::Http3 => 5,
        }
    }
}

/// One field of a request head. Both slices borrow the head.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Field<'a> {
    /// The name as the client wrote it.
    pub name: &'a [u8],
    /// The value, without surrounding blanks.
    pub value: &'a [u8],
}

/// What a hook sees. Every slice borrows the caller's buffers for the invocation.
#[derive(Clone, Copy, Debug)]
pub struct View<'a> {
    /// The stage of the invocation.
    pub stage: Stage,
    /// The protocol of the flow or request.
    pub protocol: Protocol,
    /// The client reached us over TLS or QUIC.
    pub secure: bool,
    /// The client. At the request stage it is the address the firewall judges by.
    pub client: SocketAddr,
    /// Our listener.
    pub local: SocketAddr,
    /// The name of the frontend.
    pub frontend: &'a str,
    /// The server name of an inspected ClientHello, else empty.
    pub server_name: &'a [u8],
    /// The JA4 fingerprint of an inspected ClientHello, else empty.
    pub ja4: &'a [u8],
    /// The request method, empty at the connection stage.
    pub method: &'a [u8],
    /// The `Host` of the request.
    pub host: &'a [u8],
    /// The path in normal form.
    pub path: &'a [u8],
    /// The query, without the question mark.
    pub query: &'a [u8],
    /// The fields of the request head, in order.
    pub fields: &'a [Field<'a>],
    /// Telemetry: the status of the answer.
    pub status: u16,
    /// Telemetry: microseconds from the request to the end of its answer.
    pub duration_us: u32,
}

impl Default for View<'_> {
    fn default() -> Self {
        let nowhere = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        View {
            stage: Stage::Connection,
            protocol: Protocol::Tcp,
            secure: false,
            client: nowhere,
            local: nowhere,
            frontend: "",
            server_name: b"",
            ja4: b"",
            method: b"",
            host: b"",
            path: b"",
            query: b"",
            fields: &[],
            status: 0,
            duration_us: 0,
        }
    }
}

impl View<'_> {
    /// The value of the first field named `name`, compared without regard to case.
    pub fn field(&self, name: &[u8]) -> Option<&[u8]> {
        self.fields.iter().find(|field| field.name.eq_ignore_ascii_case(name)).map(|f| f.value)
    }
}

/// Writes the 16 address bytes of the wire form.
fn put_address(out: &mut Vec<u8>, address: IpAddr) {
    match address {
        IpAddr::V4(v4) => {
            out.extend_from_slice(&v4.octets());
            out.extend_from_slice(&[0; 12]);
        }
        IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
    }
}

/// Writes a text of the wire form. A text longer than a `u16` counts does not fit.
fn put_text(out: &mut Vec<u8>, text: &[u8]) -> Result<(), Failure> {
    let length = u16::try_from(text.len()).map_err(|_| Failure::Overload)?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(text);
    Ok(())
}

/// Writes the wire form of `view` into `out`, which is cleared first.
///
/// # Errors
///
/// [`Failure::Overload`] when the form would exceed `limit` bytes. A view is never cut:
/// a hook that judged a part would judge another request.
pub fn encode(view: &View<'_>, out: &mut Vec<u8>, limit: usize) -> Result<(), Failure> {
    out.clear();
    let count = u16::try_from(view.fields.len()).map_err(|_| Failure::Overload)?;
    let mut flags = u8::from(view.secure);
    flags |= u8::from(view.client.is_ipv6()) << 1;
    flags |= u8::from(view.local.is_ipv6()) << 2;
    out.extend_from_slice(&[WIRE_VERSION, view.stage.wire(), view.protocol.wire(), flags]);
    out.extend_from_slice(&view.client.port().to_le_bytes());
    out.extend_from_slice(&view.local.port().to_le_bytes());
    put_address(out, view.client.ip());
    put_address(out, view.local.ip());
    out.extend_from_slice(&view.status.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&view.duration_us.to_le_bytes());
    let texts = [
        view.frontend.as_bytes(),
        view.server_name,
        view.ja4,
        view.method,
        view.host,
        view.path,
        view.query,
    ];
    for text in texts {
        put_text(out, text)?;
        if out.len() > limit {
            return Err(Failure::Overload);
        }
    }
    for field in view.fields {
        put_text(out, field.name)?;
        put_text(out, field.value)?;
        if out.len() > limit {
            return Err(Failure::Overload);
        }
    }
    Ok(())
}

/// The most fields one invocation may add.
pub const MAX_ADDED_FIELDS: usize = 8;
/// The most bytes of field lines one invocation may add.
pub const MAX_ADDED_BYTES: usize = 1024;

/// Field names a hook may not add: they carry framing or a hop.
const FRAMING: [&str; 8] = [
    "content-length",
    "transfer-encoding",
    "connection",
    "host",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
];
/// Field names a hook may not add: a server reads them as Sibuna's statement.
const OWN: [&str; 2] = ["x-real-ip", "x-client-cert-sha256"];
/// Prefixes of such names.
const OWN_PREFIXES: [&str; 3] = ["x-sibuna-", "x-forwarded-", "proxy-"];

/// True for the bytes of an HTTP token.
fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// True when a hook may add a field of this name.
fn may_add(name: &[u8]) -> bool {
    let Ok(name) = std::str::from_utf8(name) else { return false };
    let lower = name.to_ascii_lowercase();
    !name.is_empty()
        && name.bytes().all(is_token)
        && !FRAMING.contains(&lower.as_str())
        && !OWN.contains(&lower.as_str())
        && !OWN_PREFIXES.iter().any(|prefix| lower.starts_with(prefix))
}

/// The request fields that the hooks of one request added, as complete lines.
#[derive(Debug, Default)]
pub struct Edits {
    lines: Vec<u8>,
    count: usize,
    refused: u32,
}

impl Edits {
    /// Forgets every line, keeping the buffer.
    pub fn clear(&mut self) {
        self.lines.clear();
        self.count = 0;
        self.refused = 0;
    }

    /// Adds the field `name` with `value`. Returns whether it was taken. A name that is
    /// no token, a name that carries framing or one of our statements, a value with a
    /// control character, and a field beyond the budget are refused and counted.
    pub fn add(&mut self, name: &[u8], value: &[u8]) -> bool {
        let value = value.trim_ascii();
        let clean = value.iter().all(|&byte| byte == b'\t' || (byte >= 0x20 && byte != 0x7f));
        let size = name.len() + value.len() + 4;
        let fits = self.count < MAX_ADDED_FIELDS && self.lines.len() + size <= MAX_ADDED_BYTES;
        if !(clean && fits && may_add(name)) {
            self.refused = self.refused.saturating_add(1);
            return false;
        }
        self.lines.extend_from_slice(name);
        self.lines.extend_from_slice(b": ");
        self.lines.extend_from_slice(value);
        self.lines.extend_from_slice(b"\r\n");
        self.count += 1;
        true
    }

    /// Adds the line `Name: value`, with or without a line end. See [`Edits::add`].
    pub fn add_line(&mut self, line: &[u8]) -> bool {
        let line = line.strip_suffix(b"\r\n").unwrap_or(line);
        match line.iter().position(|&byte| byte == b':') {
            Some(colon) => self.add(&line[..colon], &line[colon + 1..]),
            None => {
                self.refused = self.refused.saturating_add(1);
                false
            }
        }
    }

    /// Adds every line of `block`, whose lines end in CRLF. Refused lines are counted.
    pub fn add_block(&mut self, block: &[u8]) {
        for line in block.split(|&byte| byte == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if !line.is_empty() {
                self.add_line(line);
            }
        }
    }

    /// The accepted lines, each ending in CRLF.
    pub fn lines(&self) -> &[u8] {
        &self.lines
    }

    /// How many lines were refused since the last [`Edits::clear`].
    pub fn refused(&self) -> u32 {
        self.refused
    }

    /// Cuts the lines back to `length` bytes and `count` fields: an invocation that
    /// failed adds nothing.
    pub(crate) fn rewind(&mut self, length: usize, count: usize) {
        self.lines.truncate(length);
        self.count = count;
    }

    /// The length and the count to [`Edits::rewind`] to.
    pub(crate) fn mark(&self) -> (usize, usize) {
        (self.lines.len(), self.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample<'a>(fields: &'a [Field<'a>]) -> View<'a> {
        View {
            stage: Stage::Request,
            protocol: Protocol::Http2,
            secure: true,
            client: "192.0.2.7:4242".parse().unwrap(),
            local: "[2001:db8::1]:443".parse().unwrap(),
            frontend: "web",
            method: b"GET",
            host: b"example.test",
            path: b"/a",
            query: b"x=1",
            fields,
            ..View::default()
        }
    }

    #[test]
    fn the_wire_form_has_the_documented_layout() {
        let fields = [Field { name: b"Accept", value: b"*/*" }];
        let mut out = Vec::new();
        encode(&sample(&fields), &mut out, 4096).unwrap();
        assert_eq!(&out[..4], &[1, 2, 4, 0b101]);
        assert_eq!(u16::from_le_bytes([out[4], out[5]]), 4242);
        assert_eq!(u16::from_le_bytes([out[6], out[7]]), 443);
        assert_eq!(&out[8..12], &[192, 0, 2, 7]);
        assert_eq!(&out[12..24], &[0; 12]);
        assert_eq!(&out[24..26], &[0x20, 0x01]);
        assert_eq!(u16::from_le_bytes([out[42], out[43]]), 1);
        let texts = &out[WIRE_FIXED..];
        assert_eq!(&texts[..5], b"\x03\0web");
        let tail = b"\x06\0Accept\x03\0*/*";
        assert_eq!(&out[out.len() - tail.len()..], tail);
    }

    #[test]
    fn a_view_that_does_not_fit_is_refused_and_never_cut() {
        let fields = [Field { name: b"Cookie", value: &[b'a'; 600] }];
        let mut out = Vec::new();
        assert_eq!(encode(&sample(&fields), &mut out, 256), Err(Failure::Overload));
        let long = vec![b'p'; 70_000];
        let view = View { path: &long, ..sample(&[]) };
        assert_eq!(encode(&view, &mut out, usize::MAX), Err(Failure::Overload));
    }

    #[test]
    fn edits_refuse_framing_our_statements_and_broken_lines() {
        let mut edits = Edits::default();
        assert!(edits.add(b"X-Tenant", b" acme "));
        for name in ["Content-Length", "host", "X-Sibuna-Status", "x-forwarded-for", "TE"] {
            assert!(!edits.add(name.as_bytes(), b"1"), "{name}");
        }
        assert!(!edits.add(b"X-A", b"a\r\nX-Injected: 1"));
        assert!(!edits.add(b"X A", b"1"));
        assert!(!edits.add(b"", b"1"));
        assert!(!edits.add_line(b"no colon"));
        assert_eq!(edits.lines(), b"X-Tenant: acme\r\n");
        assert_eq!(edits.refused(), 9);
    }

    #[test]
    fn edits_hold_at_most_eight_fields_and_a_kilobyte() {
        let mut edits = Edits::default();
        for index in 0..MAX_ADDED_FIELDS {
            assert!(edits.add(format!("X-{index}").as_bytes(), b"v"));
        }
        assert!(!edits.add(b"X-More", b"v"));
        edits.clear();
        assert!(!edits.add(b"X-Big", &[b'v'; MAX_ADDED_BYTES]));
        assert!(edits.add(b"X-Fits", &[b'v'; MAX_ADDED_BYTES - 10]));
        assert_eq!(edits.lines().len(), MAX_ADDED_BYTES);
    }

    #[test]
    fn a_block_of_lines_is_added_line_by_line() {
        let mut edits = Edits::default();
        edits.add_block(b"X-A: 1\r\nHost: evil\r\nX-B: 2\r\n");
        assert_eq!(edits.lines(), b"X-A: 1\r\nX-B: 2\r\n");
        assert_eq!(edits.refused(), 1);
    }
}
