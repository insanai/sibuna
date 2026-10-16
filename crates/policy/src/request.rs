//! The borrowed request that policy evaluation and both inspection paths read.

use std::net::IpAddr;

use crate::rule::Header;

/// Everything the engine looks at for one request. Every slice borrows the connection
/// buffer (or the caller's storage), so a view cannot outlive the request it describes.
///
/// ```
/// use sibuna_policy::RequestView;
///
/// let base = RequestView::new(b"/a", b"192.0.2.1", b"curl/8");
/// let view = RequestView { query: b"page=2", ..base };
/// assert_eq!(view.path, b"/a");
/// assert!(view.headers.is_empty() && view.body.is_empty());
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestView<'a> {
    /// The request path, before any `?`.
    pub path: &'a [u8],
    /// The query string without the `?`.
    pub query: &'a [u8],
    /// The client address as text (IPv4 or IPv6), as received. Policy reads
    /// `client_address`; the text serves incidents and logs.
    pub client_ip: &'a [u8],
    /// The client address, parsed once by whoever built the view (`RequestView::new` parses
    /// `client_ip`). Reputation and CIDR criteria read it; `None` matches no address
    /// criterion. When it is `None` while `client_ip` holds text, the engine parses the text
    /// itself, so a view built field by field without it is still judged by its address.
    pub client_address: Option<IpAddr>,
    /// The User-Agent header value.
    pub user_agent: &'a [u8],
    /// The JA4 TLS fingerprint a trusted ingress forwarded, if any (SID 0014).
    pub ja4: Option<crate::ja4::Fingerprint<'a>>,
    /// The request headers in order.
    pub headers: &'a [Header<'a>],
    /// The request body received so far; inspection reads at most its first 8 KiB.
    pub body: &'a [u8],
}

impl<'a> RequestView<'a> {
    /// Returns a view of a request with a path, a client address (parsed here) and a
    /// User-Agent, and no query, headers or body.
    pub fn new(path: &'a [u8], client_ip: &'a [u8], user_agent: &'a [u8]) -> RequestView<'a> {
        let client_address = sibuna_cidr::parse_ip(client_ip).ok();
        RequestView { path, client_ip, client_address, user_agent, ..RequestView::default() }
    }

    /// Returns the client address policy judges: `client_address`, or else `client_ip`
    /// parsed now (`None` when it is not an address).
    #[inline]
    pub fn address(&self) -> Option<IpAddr> {
        if self.client_address.is_some() || self.client_ip.is_empty() {
            return self.client_address;
        }
        sibuna_cidr::parse_ip(self.client_ip).ok()
    }
}
