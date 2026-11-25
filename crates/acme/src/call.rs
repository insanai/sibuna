//! A plain HTTP request for the caller to send: the question to an OCSP responder and
//! the calls of the Cloudflare API. The crate builds it and reads the answer. The caller
//! owns the socket.

use std::fmt;

/// One HTTP request. The answer comes back as a [`crate::Response`].
#[derive(Clone, PartialEq, Eq)]
pub struct Call {
    /// The method: `GET`, `POST` or `DELETE`.
    pub method: &'static str,
    /// The absolute URL.
    pub url: String,
    /// The header fields beside `Host`. A value may be a secret.
    pub headers: Vec<(&'static str, String)>,
    /// The body, empty for a request without one.
    pub body: Vec<u8>,
}

impl fmt::Debug for Call {
    /// Shows the method, the URL and the names of the header fields. A header value may
    /// be a token, so no value is shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<_> = self.headers.iter().map(|(name, _)| *name).collect();
        f.debug_struct("Call")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_has_no_header_value() {
        let call = Call {
            method: "GET",
            url: "http://127.0.0.1/x".to_owned(),
            headers: vec![("authorization", "Bearer secret-token".to_owned())],
            body: Vec::new(),
        };
        let shown = format!("{call:?}");
        assert!(shown.contains("authorization") && !shown.contains("secret-token"), "{shown}");
    }
}
