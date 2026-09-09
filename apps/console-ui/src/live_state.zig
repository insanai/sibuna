//! Small published indicators; the transport owns JSON reassembly separately.
const p = @import("console_protocol");
pub const Observation = struct {
    received_at: u64 = 0,
    observed_at: u64 = 0,
    missing_ids: u64 = 0,
    newer: u8 = 0,
    available: bool = false,
    stale: bool = true,
};
pub const Model = struct {
    topics: [p.subscriptions.topic_count]Observation = @splat(.{}),
    committed: u64 = 0,
    applied: u64 = 0,
};
