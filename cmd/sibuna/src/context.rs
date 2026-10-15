//! One request in flight: the parsed request, the identity it is judged by, and the parts of
//! its connection it may use.
//!
//! # The client identity
//!
//! Without trusted forwarding the client is the socket peer. With it (`--trust-forwarded`,
//! or forward-auth mode), each proxy in front of the daemon appends the address it received
//! the request from to `X-Forwarded-For`, so the entries a client cannot forge are the last
//! ones. The client is the entry `--trusted-hops` positions from the right (1 by default:
//! the address the nearest proxy appended); every entry further left was written by the
//! client and is ignored. `X-Real-IP` is read only when no `X-Forwarded-For` field is
//! present. A chosen entry that is not an IP address (only a misbehaving trusted proxy can
//! produce one) is not trusted: the request is judged by the socket peer and counted in
//! `sibuna_forwarded_invalid_total`. The Zig daemon took the leftmost entry, which
//! appending proxies pass through from the client.
//!
//! The address is parsed once per request. Policy reads the parsed address; the rate
//! limiters and the ban table read a [`ClientKey`], its canonical bytes, so `1.2.3.4`,
//! `::ffff:1.2.3.4` and `001.2.3.4` are one client. IPv6 clients are aggregated to their
//! `--ipv6-prefix` network (a /64 by default) for limits and bans, because one subscriber
//! commonly holds a whole /64 and would otherwise multiply its budget. The text stays for
//! incidents, logs and the token fingerprint, a format shared with Zig nodes.

use std::io::Write;
use std::net::{IpAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

use sibuna_http::Request;
use sibuna_net::{Activity, Upload, Workspace};

use crate::connection::Link;
use crate::server::Server;
use crate::slot::EngineCache;

/// A request and the connection parts it borrows. Every slice borrows the connection's
/// read buffer or the peer text, so a context cannot outlive the bytes it describes.
pub(crate) struct Ctx<'c, W> {
    pub server: &'c Server,
    pub stream: &'c TcpStream,
    pub writer: &'c mut W,
    pub workspace: &'c mut Workspace,
    pub cache: &'c mut EngineCache,
    pub activity: &'c Activity,
    pub request: Request<'c>,
    /// Bytes read after the buffered body: a pipelined request, or the start of a streamed
    /// upload or upgraded connection.
    pub pending: &'c [u8],
    /// How an admitted body reaches the origin.
    pub upload: Upload,
    /// The body length the request declared ([`crate::connection::UNKNOWN_LENGTH`] while a
    /// chunked body continues past the buffer).
    pub declared_body: usize,
    /// The address the request is judged by, as text: the trusted forwarded entry or the
    /// peer. It feeds incidents, logs, the audit fields and the token fingerprint.
    pub client_ip: &'c [u8],
    /// `client_ip` parsed; `None` only when the peer text itself is not an address.
    pub client_address: Option<IpAddr>,
    /// The bytes the rate limiters and the ban table know the client by.
    pub client_key: ClientKey<'c>,
    pub user_agent: &'c [u8],
    /// Unix seconds and milliseconds when the request was dispatched.
    pub now: u64,
    pub now_ms: u64,
    pub keep_alive: bool,
    /// The route identity, taken before any trusted authorization-target rewrite.
    pub internal: bool,
}

impl<'c, W: Write> Ctx<'c, W> {
    /// Builds the context of `request` on `link`, whose peer address is `peer`.
    pub(crate) fn new<'l: 'c>(
        link: &'c mut Link<'l, W>,
        request: Request<'c>,
        peer: &'c [u8],
        declared_body: usize,
    ) -> Ctx<'c, W> {
        let now_ms = unix_ms();
        let server = link.server;
        let (client_ip, client_address) = resolve_client(server, &request, peer);
        let client_key = ClientKey::new(client_ip, client_address, server.config.ipv6_prefix);
        let user_agent = request.header(b"user-agent").unwrap_or_default();
        let keep_alive =
            request.wants_keep_alive() && declared_body <= request.body.len() && !link.last;
        let internal = request.path.starts_with(b"/__sibuna/");
        Ctx {
            server,
            stream: link.stream,
            writer: &mut link.writer,
            workspace: &mut link.workspace,
            cache: &mut link.cache,
            activity: link.activity,
            request,
            pending: &[],
            upload: Upload::None,
            declared_body,
            client_ip,
            client_address,
            client_key,
            user_agent,
            now: now_ms / 1000,
            now_ms,
            keep_alive,
            internal,
        }
    }
}

/// Returns the client address text and its parse (see the module documentation): the
/// trusted forwarded entry when forwarding is trusted and the entry is an address, else the
/// peer. Counts an untrusted entry in `forwarded_invalid`.
fn resolve_client<'c>(
    server: &Server,
    request: &Request<'c>,
    peer: &'c [u8],
) -> (&'c [u8], Option<IpAddr>) {
    if server.config.trusts_forwarded() {
        let hops = usize::from(server.config.trusted_hops);
        if let Some(forwarded) = forwarded_entry(request, hops) {
            if let Ok(address) = sibuna_cidr::parse_ip(forwarded) {
                return (forwarded, Some(address));
            }
            server.metrics.forwarded_invalid.bump();
        }
    }
    (peer, sibuna_cidr::parse_ip(peer).ok())
}

/// Returns the `X-Forwarded-For` entry `hops` positions from the right (1 is the last),
/// reading every `X-Forwarded-For` field in order as one list, trimmed of spaces and tabs.
/// Without any such field it returns `X-Real-IP`. Returns `None` when neither field is
/// present; `Some` of empty text when the chain is shorter than `hops`, which no address
/// parses from.
fn forwarded_entry<'c>(request: &Request<'c>, hops: usize) -> Option<&'c [u8]> {
    let mut fields = request
        .headers()
        .iter()
        .rev()
        .filter(|header| header.name.eq_ignore_ascii_case(b"x-forwarded-for"))
        .peekable();
    if fields.peek().is_none() {
        return request.header(b"x-real-ip").map(trim_whitespace);
    }
    let mut entries = fields.flat_map(|header| header.value.rsplit(|&byte| byte == b','));
    Some(entries.nth(hops.saturating_sub(1)).map_or(&[][..], trim_whitespace))
}

/// Trims spaces and tabs (the optional whitespace around list elements).
fn trim_whitespace(bytes: &[u8]) -> &[u8] {
    bytes.trim_ascii_start().trim_ascii_end()
}

/// The bytes the rate limiters and the ban table know a client by.
///
/// An address is a zero byte followed by its 16-byte IPv4-mapped form (IPv6 addresses cut
/// to the configured prefix), so every spelling of one address is one key. Text that is not
/// an address (possible only for a peer text that does not parse) keys on itself. Header
/// values and peer texts never hold a zero byte, so no text key equals an address key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientKey<'c> {
    /// The canonical bytes of an address.
    Address([u8; 17]),
    /// Text that did not parse as an address.
    Text(&'c [u8]),
}

impl<'c> ClientKey<'c> {
    /// Returns the key of a client whose text is `text` and whose parse is `address`;
    /// IPv6 addresses (not IPv4-mapped ones) keep their first `ipv6_prefix` bits.
    pub(crate) fn new(text: &'c [u8], address: Option<IpAddr>, ipv6_prefix: u8) -> Self {
        let Some(address) = address else { return ClientKey::Text(text) };
        let mut key = sibuna_cidr::mapped_key(address);
        let ipv4_mapped = key >> 32 == sibuna_cidr::IPV4_MAPPED_PREFIX >> 32;
        if !ipv4_mapped {
            key &= u128::MAX.checked_shl(128 - u32::from(ipv6_prefix.min(128))).unwrap_or(0);
        }
        let mut bytes = [0u8; 17];
        bytes[1..].copy_from_slice(&key.to_be_bytes());
        ClientKey::Address(bytes)
    }

    /// Returns the key bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            ClientKey::Address(bytes) => bytes,
            ClientKey::Text(text) => text,
        }
    }
}

/// The wall clock in Unix milliseconds; zero before 1970.
pub(crate) fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(text: &str, prefix: u8) -> Vec<u8> {
        let address = sibuna_cidr::parse_ip(text.as_bytes()).ok();
        ClientKey::new(text.as_bytes(), address, prefix).as_bytes().to_vec()
    }

    #[test]
    fn every_spelling_of_an_address_is_one_key() {
        let canonical = key("1.2.3.4", 64);
        assert_eq!(canonical.len(), 17);
        for spelling in ["::ffff:1.2.3.4", "001.2.3.4", "::FFFF:1.2.3.4", "1.2.3.04"] {
            assert_eq!(key(spelling, 64), canonical, "{spelling}");
        }
        assert_ne!(key("1.2.3.5", 64), canonical);
        assert_eq!(key("not an address", 64), b"not an address");
    }

    #[test]
    fn ipv6_clients_are_aggregated_to_their_prefix_and_ipv4_never_is() {
        assert_eq!(key("2001:db8:1:2::1", 64), key("2001:db8:1:2:ffff::9", 64));
        assert_ne!(key("2001:db8:1:2::1", 64), key("2001:db8:1:3::1", 64));
        assert_eq!(key("2001:db8:1:2::1", 48), key("2001:db8:1:3::1", 48));
        assert_ne!(key("2001:db8::1", 128), key("2001:db8::2", 128));
        assert_ne!(key("1.2.3.4", 32), key("1.2.3.5", 32));
    }

    fn entry(head: &str, hops: usize) -> Option<String> {
        let raw = format!("GET / HTTP/1.1\r\nHost: t\r\n{head}\r\n");
        let request = sibuna_http::parse_request(raw.as_bytes()).unwrap();
        forwarded_entry(&request, hops).map(|text| String::from_utf8(text.to_vec()).unwrap())
    }

    #[test]
    fn the_client_is_counted_from_the_right_of_the_forwarded_chain() {
        let chain = "X-Forwarded-For: 203.0.113.7, 192.0.2.66\r\n";
        assert_eq!(entry(chain, 1).as_deref(), Some("192.0.2.66"));
        assert_eq!(entry(chain, 2).as_deref(), Some("203.0.113.7"));
        assert_eq!(entry(chain, 3).as_deref(), Some(""), "a short chain names nobody");
        // Several fields are one list in field order; whitespace around entries goes.
        let split = "X-Forwarded-For: 10.0.0.1 ,\t10.0.0.2\r\nX-Forwarded-For:  10.0.0.3 \r\n";
        assert_eq!(entry(split, 1).as_deref(), Some("10.0.0.3"));
        assert_eq!(entry(split, 2).as_deref(), Some("10.0.0.2"));
        // X-Real-IP is read only without X-Forwarded-For.
        let both = "X-Real-IP: 198.51.100.9\r\nX-Forwarded-For: 192.0.2.1\r\n";
        assert_eq!(entry(both, 1).as_deref(), Some("192.0.2.1"));
        assert_eq!(entry("X-Real-IP:  198.51.100.9 \r\n", 1).as_deref(), Some("198.51.100.9"));
        assert_eq!(entry("", 1), None);
    }
}
