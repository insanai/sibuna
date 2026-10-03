//! The audited exception to the effect-order guard.
//!
//! `host_managed.Protocol` produces the same protocol as `paxos.Protocol`
//! but without the runtime check that `confirmWritesDurable` ran before
//! `messagesSlice` or `reset`. Selecting this namespace transfers ownership
//! of a load-bearing safety rule to the host: a promise or vote message
//! released before its write is durable can retract that claim after a
//! crash and break agreement.
//!
//! A host that declares its protocol here must meet four obligations:
//!
//! 1. Copy writes and messages out of `Effects` before the next transition
//!    resets the batch.
//! 2. Keep every pending message private from the network until the shared
//!    write barrier completes.
//! 3. Release no message and report no client success after a failed append
//!    or barrier.
//! 4. Rebuild the same durable state from the written prefix after restart,
//!    and prove it with a crash-recovery test.
//!
//! Every use of this namespace needs written ownership notes and appears in
//! the release audit. The `ReplicatedLog` layer has no host-managed variant
//! by design; it always builds on the enforced protocol.

const std = @import("std");
const protocol = @import("protocol.zig");

/// Same compile-time options as the enforced factory.
pub const Options = protocol.Options;

/// Bounded Paxos effect machine whose durability boundary the host owns.
pub fn Protocol(comptime Value: type, comptime options: Options) type {
    return protocol.ProtocolGated(Value, options, .host_managed);
}

test "host-managed hosts may batch messages before confirming durability" {
    const P = Protocol(u64, .{ .max_members = 3, .window_slots = 16 });
    var membership: P.Membership = undefined;
    try membership.init(&.{ 1, 2, 3 });
    var node: P.Node = undefined;
    try node.init(2, &membership);
    var effects = P.Effects{};

    try node.step(.{
        .from = 1,
        .to = 2,
        .message = .{ .prepare = .{
            .ballot = .{ .round = 1, .node = 1 },
            .first = 1,
        } },
    }, &effects);
    try std.testing.expect(effects.writes_count > 0);
    try std.testing.expect(!effects.writes_confirmed);

    // The host copies messages into its private batch before its shared
    // barrier; the library does not stop it, so the obligation is the
    // host's alone.
    try std.testing.expect(effects.messagesSlice().len > 0);
    effects.reset();
    try std.testing.expectEqual(@as(usize, 0), effects.writes_count);
}
