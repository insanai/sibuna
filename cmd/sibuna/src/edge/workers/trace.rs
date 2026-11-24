//! What a worker tells the access log about an exchange (SID 0020).
//!
//! An admitted request moves its entry from the decision to its connection record. The
//! functions here fill it as the response passes and settle it when the exchange ends.

use std::time::Instant;

use crate::access::Entry;
use crate::client_writer::Tally;
use crate::server::Server;

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
        entry.status = entry.scan.feed(added);
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
