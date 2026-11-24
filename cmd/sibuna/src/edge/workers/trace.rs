//! What a worker tells the access log about an exchange (SID 0020).
//!
//! An admitted request moves its entry from the decision to its connection record. The
//! functions here fill it as the response passes and settle it when the exchange ends.

use std::time::Instant;

use crate::access::Entry;
use crate::client_writer::{Tally, status_of};
use crate::server::Server;

/// Interim heads looked past to find the final status in one piece of a response.
const INTERIM_HEADS: usize = 4;

/// Notes server bytes that arrived at `now`. `output` holds what the relay wrote for the
/// client from `before` on.
pub(super) fn received(trace: &mut Option<Entry>, output: &[u8], before: usize, now: Instant) {
    let Some(entry) = trace.as_mut() else { return };
    if entry.first_byte.is_none() {
        entry.first_byte = Some(now.saturating_duration_since(entry.started));
    }
    let added = output.get(before..).unwrap_or_default();
    entry.bytes_out += added.len() as u64;
    if entry.status == 0 {
        entry.status = final_status(added);
    }
}

/// Counts `count` bytes relayed to the client inside a tunnel.
pub(super) fn count(trace: &mut Option<Entry>, count: usize) {
    if let Some(entry) = trace.as_mut() {
        entry.bytes_out += count as u64;
    }
}

/// Settles an exchange that Sibuna answered itself for a failed server.
pub(super) fn answered(server: &Server, trace: &mut Option<Entry>, tally: Tally, now: Instant) {
    let Some(mut entry) = trace.take() else { return };
    entry.status = tally.status;
    entry.bytes_out += tally.bytes;
    // The server sent no usable response, whatever bytes it sent.
    entry.first_byte = None;
    if let Some(observe) = &server.observe {
        observe.settle(entry, now);
    }
}

/// Settles the entry of an exchange that ended at `now`, complete or not.
pub(super) fn settle(server: &Server, trace: &mut Option<Entry>, now: Instant) {
    let Some(entry) = trace.take() else { return };
    if let Some(observe) = &server.observe {
        observe.settle(entry, now);
    }
}

/// The status of the final head at the start of `bytes`, after any interim heads, or
/// zero when `bytes` holds none.
fn final_status(mut bytes: &[u8]) -> u16 {
    for _ in 0..INTERIM_HEADS {
        let status = status_of(bytes);
        if !(100..200).contains(&status) || status == 101 {
            return status;
        }
        let Some(end) = crate::connection::find_blank_line(bytes) else { return 0 };
        bytes = bytes.get(end + 4..).unwrap_or_default();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_final_status_follows_interim_heads() {
        assert_eq!(final_status(b"HTTP/1.1 200 OK\r\n\r\n"), 200);
        assert_eq!(final_status(b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 404 No\r\n\r\n"), 404);
        assert_eq!(final_status(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"), 101);
        assert_eq!(final_status(b"HTTP/1.1 100 Continue\r\n\r\n"), 0);
        assert_eq!(final_status(b"a chunk of a body"), 0);
        assert_eq!(final_status(b""), 0);
    }
}
