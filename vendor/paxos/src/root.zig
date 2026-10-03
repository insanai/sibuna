//! A deterministic, bounded implementation of classic and Multi-Paxos.
//!
//! The library performs no I/O and owns no threads or clocks. A `Node` consumes
//! messages and emits `Effects`. Persist `Effects.writes` before transmitting
//! `Effects.messages`; this ordering is part of the safety contract. After
//! syncing a batch, call `Effects.confirmWritesDurable`. Every build mode
//! checks the ordering and stops hosts that send before persisting; the
//! `host_managed` namespace is the only audited exception.

const protocol = @import("protocol.zig");
const replicated_log = @import("replicated_log.zig");
const learner = @import("learner.zig");

/// Human-readable library version.
pub const version = "0.7.0";
/// Stable identity of one voting member.
pub const NodeId = protocol.NodeId;
/// One-based log position.
pub const Slot = protocol.Slot;
/// Totally ordered Paxos proposal ballot.
pub const Ballot = protocol.Ballot;
/// Compile-time configuration of the minimal protocol core.
pub const Options = protocol.Options;
/// Bounded classic and Multi-Paxos effect machine.
pub const Protocol = protocol.Protocol;
/// Compile-time configuration of the sealed replicated-log layer.
pub const ReplicatedLogOptions = replicated_log.Options;
/// Reconfigurable command log with stop signs and snapshot epochs.
pub const ReplicatedLog = replicated_log.ReplicatedLog;
/// Compile-time bounds for a non-voting chosen-value learner.
pub const LearnerOptions = learner.Options;
/// Bounded non-voting learner that releases only contiguous chosen values.
pub const Learner = learner.Learner;
/// Returns a human-friendly Elm-style explanation of any error.
pub const explainError = @import("errors.zig").explainError;
/// Protocol factory for hosts that own the durability boundary themselves.
/// Read the namespace warning before using it; every use is audited.
pub const host_managed = @import("host_managed.zig");

test {
    _ = @import("bit_set.zig");
    _ = @import("protocol.zig");
    _ = @import("replicated_log.zig");
    _ = @import("learner.zig");
    _ = @import("errors.zig");
    _ = @import("host_managed.zig");
}
