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
}

impl Default for Bounds {
    fn default() -> Self {
        Self { connect: crate::CONNECT_TIMEOUT, response: None, max_body: None }
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
    /// The request is safe (`GET`, `HEAD`, `OPTIONS`) and still held whole.
    pub retryable: bool,
    /// The request was already sent again on a fresh connection to this server.
    pub retried: bool,
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
/// A missing reply is no evidence that a server did not act on a request. So only a
/// request that is safe and held whole is ever sent twice, and only while no response
/// byte arrived. A failed connect is not decided here: nothing was sent, and any request
/// may move.
pub fn recover(lost: Lost) -> Recovery {
    if !(lost.unanswered && lost.retryable) {
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
    fn only_a_safe_unanswered_request_is_sent_again() {
        let lost = Lost { unanswered: true, pooled: true, retryable: true, retried: false };
        assert_eq!(recover(lost), Recovery::Reconnect);
        assert_eq!(recover(Lost { retried: true, ..lost }), Recovery::Move);
        assert_eq!(recover(Lost { pooled: false, ..lost }), Recovery::Move);
        assert_eq!(recover(Lost { retryable: false, ..lost }), Recovery::Fail);
        assert_eq!(recover(Lost { unanswered: false, ..lost }), Recovery::Fail);
    }
}
