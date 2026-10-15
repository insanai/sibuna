//! The borrowed request that policy evaluation and both inspection paths read.

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
    /// The client address as text (IPv4 or IPv6); text that is not an address matches no
    /// address criterion.
    pub client_ip: &'a [u8],
    /// The User-Agent header value.
    pub user_agent: &'a [u8],
    /// The request headers in order.
    pub headers: &'a [Header<'a>],
    /// The request body received so far; inspection reads at most its first 8 KiB.
    pub body: &'a [u8],
}

impl<'a> RequestView<'a> {
    /// Returns a view of a request with a path, a client address and a User-Agent, and no
    /// query, headers or body.
    pub fn new(path: &'a [u8], client_ip: &'a [u8], user_agent: &'a [u8]) -> RequestView<'a> {
        RequestView { path, client_ip, user_agent, ..RequestView::default() }
    }
}
