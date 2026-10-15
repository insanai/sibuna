//! The console's capacity budget (Zig's `budget.zig`, SID 0007 Invariant I4): slot and
//! stream quotas, and the memory the console may reserve, printed in the startup banner.
//!
//! The reservation is an estimate of what the console's bounded owners may hold at once,
//! recomputed for the Rust layout: connection workers keep their 16 KiB receive buffer on
//! their stack, each WebSocket has a scoped reader thread, topic rings and outboxes are
//! allocated on demand up to the same bounds, and the Argon2 workspace is allocated once.
//! Database and allocator overheads are not included; the impact harness measures them.

use std::fmt;
use std::mem::size_of;

use sibuna_console_protocol::rankings_archive;
use sibuna_console_protocol::subscriptions::{
    QUEUE_CAPACITY, RECORD_BYTES, RING_CAPACITY, SNAPSHOT_BYTES, TOPIC_COUNT,
};
use sibuna_serve::{Capacity, stack};
use sibuna_store::{incidents, telemetry};

use super::peers::MAX_PEERS;
use crate::limits::{BUDGET_SLOTS, LIMITER_SLOTS};

/// The largest request body any route reads (SID 0007, "The Serve Kernel").
pub const BODY_BYTES: u64 = 1024 * 1024;
/// One 32 MiB source buffer for an uncompressed GeoIP provider, plus download scratch.
pub const IMPORT_BYTES: u64 = 32 * 1024 * 1024 + 40 * 1024;
/// The Argon2id workspace: m = 19,456 KiB, allocated once at start (decision 9).
pub const AUTH_BYTES: u64 = 19_456 * 1024;
/// What one outbound management peer may hold: frame reassembly, a JSON document and the
/// TLS record buffers.
pub const PEER_BYTES: u64 = 192 * 1024;
/// Service threads with the default stack: acceptor, watchdog, collector, hub feeder,
/// probe and GeoIP importer.
pub const SERVICE_THREADS: u64 = 6;
/// The notifier's larger stack: it formats and signs deliveries on its own thread.
pub const NOTIFIER_STACK: usize = 512 * 1024;
/// The bytes of one GeoIP range in a loaded generation: first and last addresses and a
/// two-byte country code, in three arrays (SID 0007, Rust port note).
pub const GEOIP_RANGE_BYTES: u64 = 34;

/// Slot and stream quotas and the per-thread stack; the defaults are SID 0007's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Budget {
    /// Connection slots of every class together; 16 to 256.
    pub slots: u16,
    /// Slots that browser and peer streams can never take; at least 16.
    pub http_reserved: u16,
    /// Browser subscriptions; at most 64.
    pub subscribers: u16,
    /// Inbound management peer streams; at most 64.
    pub peers: u16,
    /// The usable stack of every service thread; 64 KiB to 8 MiB.
    pub stack_bytes: u32,
    /// Concurrent password verifications; exactly 1 (one workspace).
    pub auth_verifiers: u8,
    /// The memory of one loaded GeoIP generation; two may be live during a swap.
    pub geoip_generation_bytes: u64,
}

impl Default for Budget {
    fn default() -> Budget {
        let ranges = u64::try_from(sibuna_geoip::MAX_RANGES).unwrap_or(u64::MAX);
        Budget {
            slots: 96,
            http_reserved: 16,
            subscribers: 64,
            peers: 16,
            stack_bytes: 256 * 1024,
            auth_verifiers: 1,
            geoip_generation_bytes: ranges.saturating_mul(GEOIP_RANGE_BYTES),
        }
    }
}

/// Why a budget was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BudgetError;

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid console budget")
    }
}

impl std::error::Error for BudgetError {}

impl Budget {
    /// Returns the listener capacity these quotas describe.
    pub fn capacity(&self) -> Capacity {
        Capacity {
            max_slots: self.slots,
            http_reserved: self.http_reserved,
            max_browsers: self.subscribers,
            max_peers: self.peers,
        }
    }

    /// Checks the quotas: the listener's rules ([`Capacity::validate`]: 16 to 256 slots, a
    /// reserve of at least 16, at most 64 browsers and 64 peers within the unreserved
    /// slots), exactly one verifier, and a stack of 64 KiB to 8 MiB.
    ///
    /// Fails with [`BudgetError`] when any rule fails.
    pub fn validate(&self) -> Result<(), BudgetError> {
        self.capacity().validate().map_err(|_| BudgetError)?;
        if self.auth_verifiers != 1 {
            return Err(BudgetError);
        }
        if !(64 * 1024..=8 * 1024 * 1024).contains(&self.stack_bytes) {
            return Err(BudgetError);
        }
        Ok(())
    }

    /// Returns the bytes the console may reserve at once under these quotas: thread stacks,
    /// request bodies, the GeoIP import buffer and two generations, the Argon2 workspace,
    /// topic rings, subscriber outboxes and snapshots, peer buffers, the telemetry rings,
    /// the limiter tables and retained ranking archives. Saturates instead of overflowing.
    ///
    /// Fails with [`BudgetError`] when [`Budget::validate`] does.
    pub fn reserved_bytes(&self) -> Result<u64, BudgetError> {
        self.validate()?;
        let slots = u64::from(self.slots);
        let streams = u64::from(self.subscribers) + u64::from(self.peers);
        let outbound = MAX_PEERS as u64;
        let usable = usize::try_from(self.stack_bytes).unwrap_or(usize::MAX);
        let per_thread = as_u64(stack::bytes(usable));
        let threads = slots + streams + outbound + SERVICE_THREADS;
        let parts = [
            threads.saturating_mul(per_thread),
            as_u64(stack::bytes(NOTIFIER_STACK)),
            slots.saturating_mul(BODY_BYTES),
            IMPORT_BYTES,
            AUTH_BYTES,
            topic_bytes(),
            streams.saturating_mul(outbox_bytes()),
            outbound.saturating_mul(PEER_BYTES),
            traffic_bytes(),
            limiter_bytes(),
            self.geoip_generation_bytes.saturating_mul(2),
            (sibuna_storage::JOB_QUEUE as u64 + slots)
                .saturating_mul(as_u64(rankings_archive::MAX_BYTES)),
        ];
        Ok(parts.into_iter().fold(0u64, u64::saturating_add))
    }
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// One ring per topic plus the browser-statistics trigger ring, each of 1,024 entries of
/// at most 2 KiB (SID 0007: 14 MiB of payload).
fn topic_bytes() -> u64 {
    as_u64((TOPIC_COUNT + 1) * RING_CAPACITY * RECORD_BYTES)
}

/// One subscriber's outbox of 64 frames and its 64 KiB snapshot.
fn outbox_bytes() -> u64 {
    as_u64(QUEUE_CAPACITY * RECORD_BYTES + SNAPSHOT_BYTES)
}

/// The data plane's console rings: samples, challenge events and committed incidents, each
/// slot with its sequence word.
fn traffic_bytes() -> u64 {
    let samples = telemetry::QUEUE_CAPACITY * (size_of::<telemetry::Record>() + 8);
    let challenges = telemetry::QUEUE_CAPACITY * (size_of::<telemetry::ChallengeRecord>() + 8);
    let incidents = incidents::QUEUE_CAPACITY * (size_of::<incidents::Record>() + 8);
    as_u64(size_of::<telemetry::ConsoleTelemetry>() + samples + challenges + incidents)
}

/// The login limiter and the query budget tables.
fn limiter_bytes() -> u64 {
    as_u64(LIMITER_SLOTS * (32 + 8 + 8) + BUDGET_SLOTS * (32 + 8 + 8))
}

#[cfg(test)]
mod tests {
    use super::*;

    // budget.zig: "budget preserves HTTP headroom and accounts for both GeoIP generations".
    #[test]
    fn the_budget_keeps_http_headroom_and_counts_both_generations() {
        assert_eq!(Budget { slots: 79, ..Budget::default() }.validate(), Err(BudgetError));
        assert_eq!(Budget { auth_verifiers: 2, ..Budget::default() }.validate(), Err(BudgetError));
        let base = Budget { geoip_generation_bytes: 0, ..Budget::default() };
        let loaded = Budget { geoip_generation_bytes: 1000, ..Budget::default() };
        assert_eq!(base.reserved_bytes().unwrap() + 2000, loaded.reserved_bytes().unwrap());
        assert_eq!(Budget::default().validate(), Ok(()));
        assert_eq!(Budget { stack_bytes: 1024, ..Budget::default() }.validate(), Err(BudgetError));
    }

    #[test]
    fn the_default_reservation_is_in_the_expected_range() {
        let bytes = Budget::default().reserved_bytes().unwrap();
        // Bodies alone are 96 MiB, two full GeoIP generations about 68 MiB.
        assert!(bytes > 200 * 1024 * 1024, "{bytes}");
        assert!(bytes < 2 * 1024 * 1024 * 1024, "{bytes}");
        assert_eq!(topic_bytes(), 14 * 1024 * 1024);
    }
}
