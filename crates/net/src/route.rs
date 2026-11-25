//! Where a balanced exchange goes, and what to do when its server fails (SID 0019).
//!
//! A caller that balances over several servers lends the proxy a [`Route`]. The proxy
//! asks it for the server and its bounds, and asks it for another server when the
//! current one cannot have acted on the request. The rule that decides this is
//! [`recover`]. The blocking proxy and the event-driven workers both use it, so a
//! request moves under the same conditions on both paths.

use std::net::SocketAddr;
use std::time::Duration;

use crate::HeadEdit;

/// The bounds of one exchange with a server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    /// The longest wait for the connection.
    pub connect: Duration,
    /// The longest silence of the server while it owes bytes. `None` leaves the bound
    /// to the idle timeout of the client connection.
    pub response: Option<Duration>,
    /// The most body bytes a request without a declared length may carry.
    pub max_body: Option<u64>,
    /// The largest body that is kept so that the request can be sent again.
    pub retry_body: u64,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            connect: crate::CONNECT_TIMEOUT,
            response: None,
            max_body: None,
            retry_body: u64::MAX,
        }
    }
}

/// The servers of one request, one at a time.
pub trait Route {
    /// The server the request goes to now.
    fn address(&self) -> SocketAddr;

    /// The bounds of an exchange with that server.
    fn bounds(&self) -> Bounds;

    /// The fields to drop from and to append to the response of that server.
    fn response_edit(&self) -> HeadEdit<'_>;

    /// The server could not be reached, or a fresh connection to it failed before it
    /// answered. Later requests should avoid it for a while.
    fn unreachable(&mut self);

    /// Reserves another server for the request. Returns false when none may be tried.
    /// The proxy calls this only when the current server cannot have acted on the
    /// request.
    fn advance(&mut self) -> bool;

    /// The server sent a final response head with `status`.
    fn responded(&mut self, status: u16);
}

/// How an exchange lost its server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lost {
    /// The server sent no response byte.
    pub unanswered: bool,
    /// The connection came from the pool of idle connections.
    pub pooled: bool,
    /// The request is still held whole: its body, if it has one, was buffered and is
    /// within the `retry_body` of its pool.
    pub kept: bool,
    /// The method is idempotent: carrying the request out twice has the effect of
    /// carrying it out once.
    pub idempotent: bool,
    /// The server said that it did not act on the request: the connection handed the
    /// request back unsent, or an HTTP/2 server refused the stream or sent `GOAWAY`
    /// below it. A lost HTTP/1.1 connection never proves this.
    pub refused: bool,
    /// The request was already sent again on a fresh connection to this server.
    pub retried: bool,
}

/// True for the methods whose requests may be sent twice (RFC 9110, section 9.2.2).
/// `TRACE` is idempotent too. It carries no body and is rare, and it is left out so
/// that every path reads one list.
pub fn is_idempotent(method: sibuna_http::Method) -> bool {
    use sibuna_http::Method::{Delete, Get, Head, Options, Put};
    matches!(method, Get | Head | Options | Put | Delete)
}

/// What follows the loss of a server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// Send the request again on a fresh connection to the same server. An idle
    /// connection that the server closed says nothing about the server.
    Reconnect,
    /// Ask for another server. The caller fails the exchange when there is none.
    Move,
    /// Fail the exchange.
    Fail,
}

/// Decides what follows the loss of a server after the connection was made.
///
/// A missing reply is no evidence that a server did not act on a request. So a request
/// is sent twice only while no response byte arrived, only when it is still held whole,
/// and only when it is idempotent or the server refused it. A failed connect is not
/// decided here: nothing was sent, and any request may move.
pub fn recover(lost: Lost) -> Recovery {
    if !(lost.unanswered && lost.kept && (lost.idempotent || lost.refused)) {
        Recovery::Fail
    } else if lost.pooled && !lost.retried {
        Recovery::Reconnect
    } else {
        Recovery::Move
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_kept_unanswered_request_that_is_idempotent_or_refused_is_sent_again() {
        let lost = Lost {
            unanswered: true,
            pooled: true,
            kept: true,
            idempotent: true,
            refused: false,
            retried: false,
        };
        assert_eq!(recover(lost), Recovery::Reconnect);
        assert_eq!(recover(Lost { retried: true, ..lost }), Recovery::Move);
        assert_eq!(recover(Lost { pooled: false, ..lost }), Recovery::Move);
        assert_eq!(recover(Lost { kept: false, ..lost }), Recovery::Fail);
        assert_eq!(recover(Lost { unanswered: false, ..lost }), Recovery::Fail);
        // A request that is not idempotent needs the word of the server.
        let post = Lost { idempotent: false, ..lost };
        assert_eq!(recover(post), Recovery::Fail);
        assert_eq!(recover(Lost { refused: true, ..post }), Recovery::Reconnect);
        assert_eq!(recover(Lost { refused: true, kept: false, ..post }), Recovery::Fail);
        // All the cases agree with the rule as the record states it.
        for bits in 0..64u8 {
            let bit = |at: u8| bits & (1 << at) != 0;
            let lost = Lost {
                unanswered: bit(0),
                pooled: bit(1),
                kept: bit(2),
                idempotent: bit(3),
                refused: bit(4),
                retried: bit(5),
            };
            let again = lost.unanswered && lost.kept && (lost.idempotent || lost.refused);
            assert_eq!(recover(lost) != Recovery::Fail, again, "{lost:?}");
        }
    }

    #[test]
    fn the_idempotent_methods_are_those_of_the_record() {
        use sibuna_http::Method;
        for method in [Method::Get, Method::Head, Method::Options, Method::Put, Method::Delete] {
            assert!(is_idempotent(method));
        }
        assert!(!is_idempotent(Method::Post) && !is_idempotent(Method::Patch));
    }
}
