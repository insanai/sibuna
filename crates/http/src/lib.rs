//! Zero-copy HTTP/1.1 for an edge server.
//!
//! - [`parse_request`] parses a request head into a [`Request`] whose slices borrow the
//!   connection buffer, without allocating.
//! - [`chunked`] decodes the chunked transfer coding in place under the strict grammar of
//!   SID 0009, and re-frames a body canonically for the origin.
//! - [`response`] writes complete length-delimited responses into any `io::Write`.
//! - [`forwarded`] reads authorization metadata from a trusted ingress.
//! - [`websocket`] encodes and decodes RFC 6455 frames and checks the opening handshake.
//!
//! ```
//! let head = b"GET /a?b=1 HTTP/1.1\r\nHost: example.com\r\nCookie: t=xyz\r\n\r\n";
//! let request = sibuna_http::parse_request(head).unwrap();
//! assert_eq!(request.path, b"/a");
//! assert_eq!(request.cookie(b"t"), Some(&b"xyz"[..]));
//! ```
//!
//! # Changes from the Zig version
//!
//! `libs/net/src/{http,chunked,response,forwarded}.zig` and
//! `libs/serve/src/websocket{,_io,_upgrade}.zig` are the specification. The accepted and
//! refused inputs and every byte written are unchanged; the port differs as follows.
//!
//! - Names follow Rust conventions: `getHeader` is [`Request::header`], `getCookie` is
//!   [`Request::cookie`], `validToken` is [`is_valid_token`], `Decoder.done` is
//!   [`chunked::Decoder::is_done`], and `response.write` is [`response::write_response`].
//! - `Request::version` is an enum ([`Version`]) instead of text: only two versions parse.
//! - A query that is absent is an empty slice at the end of the target, not a static empty
//!   string, so every slice of a parsed request lies inside the parsed bytes.
//! - [`Request::content_length`] parses digits only. Zig's `parseInt` would also have read
//!   `+5` or `1_0`, but the parser never accepts such a field, so this changes nothing for a
//!   parsed request.
//! - The re-chunking helper of the proxy lives here as [`chunked::write_chunk`] and
//!   [`chunked::LAST_CHUNK`].
//! - The WebSocket decoder returns `Ok(None)` for an incomplete frame instead of the error
//!   `NeedMore`, the FIN flag is called `fin`, and a text message arrives as `&str`.
//! - [`websocket::FrameReader`] replaces the peek-and-toss use of Zig's buffered reader, and
//!   [`websocket::upgrade_key`] takes a parsed [`Request`] instead of the console's context.
//! - [`response::write_302`] writes its `Location` and cookie fields directly instead of
//!   formatting them into 512- and 768-byte stack buffers, so a long location no longer
//!   fails.
//! - Writers take any `std::io::Write` and flush it at the end, as Zig did.
//!
//! # Performance
//!
//! The Zig benchmark `http_parser/zero_copy_request_and_cookie` (a 400-byte browser request,
//! then a cookie lookup) measured 1,119 to 1,145 ns per operation; this parser takes about
//! 135 to 170 ns on the same machine (`tests/timing.rs`). Parsing is deterministic, so a
//! daemon that moves a head inside its buffer re-parses it for the same cost and gets the
//! same verdict.

#![warn(missing_docs)]

mod bytes;
pub mod chunked;
pub mod forwarded;
mod request;
pub mod response;
#[cfg(test)]
mod test_util;
pub mod websocket;

pub use request::{
    Header, MAX_HEADERS, Method, ParseError, Request, Target, Version, is_token_char,
    is_valid_token, parse_request, split_target,
};
