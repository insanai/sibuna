//! Flows that wait for the judges (SID 0030, "Parking a connection"). The worker
//! holds what a parked flow owns and goes on with it when the ruling arrives.

use std::time::Instant;

use crate::gate::Parked;
use crate::stats::Refusal;
use crate::{Edge, flowlog, forward};

/// The first datagram of a UDP client: its size in the buffer of the worker and the
/// peer that forwarded it.
pub(crate) type First = (usize, Option<forward::Via>);

impl Edge {
    /// Keeps `flow` until the ruling of `ticket` arrives.
    pub(crate) fn park(&mut self, ticket: u64, flow: Parked) {
        if let Some(gate) = &mut self.gate {
            gate.hold(ticket, flow);
        }
    }

    /// Goes on with every parked flow that has its ruling. An admitted flow starts
    /// where it would have started. A denied one is closed and counted.
    pub(crate) fn finish_rulings(&mut self, now: Instant) {
        // One batch, so that a burst of rulings does not keep the sockets waiting.
        for _ in 0..256 {
            let Some((flow, admitted)) = self.gate.as_mut().and_then(|gate| gate.next(now)) else {
                return;
            };
            if !self.resume(flow, admitted, now) {
                self.drops = self.drops.saturating_add(1);
            }
        }
    }

    /// Returns false when the flow was dropped.
    fn resume(&mut self, flow: Parked, admitted: bool, now: Instant) -> bool {
        match flow {
            Parked::Stream { listener, client, peer, reached, permit, named } => {
                if !admitted {
                    return self.refuse(listener, peer, Refusal::Hook);
                }
                self.start_flow(listener, client, peer, reached, permit, named)
            }
            Parked::Hello { id, mut flow, end } => {
                if !admitted {
                    self.stats.refuse(Refusal::Hook);
                    flowlog::mark(&mut flow.opening.line, Refusal::Hook.end());
                    return false;
                }
                self.settle_inspection(id, *flow, end)
            }
            Parked::Datagram { key, permit, bytes, via } => {
                if !admitted {
                    self.stats.refuse(Refusal::Hook);
                    return false;
                }
                if !self.map(key, permit, now) {
                    return false;
                }
                let size = bytes.len().min(self.buffer.len());
                self.buffer[..size].copy_from_slice(&bytes[..size]);
                self.relay(key, size, via, now)
            }
        }
    }
}
