//! Stack-owned operation waiters, registered only while the host mutex is held.
const std = @import("std");
const paxos = @import("paxos");
const types = @import("types.zig");
const Node = @import("node.zig").Node;

pub const WriteOutcome = enum { pending, committed, conflict };

pub const WriteWaiter = struct {
    slot: paxos.Slot,
    batch_id: u128,
    outcome: WriteOutcome = .pending,
    cond: std.Io.Condition = .init,

    /// Caller owns registration and holds the server mutex throughout.
    pub fn awaitOutcome(self: *WriteWaiter, server: anytype, start: u64, timeout: u64) !void {
        while (self.outcome == .pending) {
            if (server.failed or server.shutdown_flag.load(.acquire)) return error.Ambiguous;
            if ((server.tick_count -| start) * server.options.tick_ms > timeout) {
                return error.OpTimeout;
            }
            self.cond.waitUncancelable(server.io, &server.mutex);
        }
        if (self.outcome != .committed) return error.Ambiguous;
    }
};

pub const FenceWaiter = struct {
    id: u64,
    ballot: paxos.Ballot,
    fence_slot: paxos.Slot,
    acked: [types.log_options.max_members]paxos.NodeId =
        @as([types.log_options.max_members]paxos.NodeId, @splat(0)),
    ack_count: usize = 0,
    needed: usize,
    failed: bool = false,
    done: bool = false,
    cond: std.Io.Condition = .init,

    pub fn awaitQuorum(self: *FenceWaiter, server: anytype, start: u64, timeout: u64) !void {
        while (!self.done) {
            if (server.failed or server.shutdown_flag.load(.acquire)) return error.Unavailable;
            if ((server.tick_count -| start) * server.options.tick_ms > timeout) {
                return error.ReadFenceTimeout;
            }
            self.cond.waitUncancelable(server.io, &server.mutex);
        }
        if (server.failed or server.shutdown_flag.load(.acquire)) return error.Unavailable;
        if (self.failed) return error.ReadFenceLeadershipChanged;
    }

    pub fn noteAck(self: *FenceWaiter, member: paxos.NodeId) void {
        for (self.acked[0..self.ack_count]) |seen| {
            if (seen == member) return;
        }
        if (self.ack_count >= self.acked.len) return;
        self.acked[self.ack_count] = member;
        self.ack_count += 1;
    }
};

pub const HistoryProbeWaiter = struct {
    nonce: u64,
    slot: paxos.Slot,
    hash: [32]u8,
    /// Voters whose vouch counts toward the read quorum. Only distinct
    /// IDs drawn from this set count; the transfer sender is one of them.
    voters: [types.log_options.max_members]paxos.NodeId =
        @as([types.log_options.max_members]paxos.NodeId, @splat(0)),
    voter_count: u16 = 0,
    acked: [types.log_options.max_members]paxos.NodeId =
        @as([types.log_options.max_members]paxos.NodeId, @splat(0)),
    ack_count: usize = 0,
    needed: usize,

    pub fn isVoter(self: *const HistoryProbeWaiter, member: paxos.NodeId) bool {
        for (self.voters[0..self.voter_count]) |voter| {
            if (voter == member) return true;
        }
        return false;
    }

    pub fn noteAck(self: *HistoryProbeWaiter, member: paxos.NodeId) void {
        if (!self.isVoter(member)) return;
        for (self.acked[0..self.ack_count]) |seen| {
            if (seen == member) return;
        }
        if (self.ack_count >= self.acked.len) return;
        self.acked[self.ack_count] = member;
        self.ack_count += 1;
    }
};

pub const WaitWaiter = struct {
    min_applied: paxos.Slot,
    need_leader: bool,
    done: bool = false,
    cond: std.Io.Condition = .init,

    pub fn satisfied(self: *const WaitWaiter, node: *Node) bool {
        if (node.applied_slot < self.min_applied) return false;
        if (self.need_leader and node.currentLeader() == null) return false;
        return true;
    }
};

test "a committed write retains its result when shutdown races its wake" {
    const Host = struct {
        io: std.Io = std.testing.io,
        mutex: std.Io.Mutex = .init,
        failed: bool = true,
        shutdown_flag: std.atomic.Value(bool) = .init(true),
        tick_count: u64 = 0,
        options: struct { tick_ms: u64 = 25 } = .{},
    };
    var host = Host{};
    var write = WriteWaiter{ .slot = 1, .batch_id = 1, .outcome = .committed };
    try write.awaitOutcome(&host, 0, 10_000);
    var fence = FenceWaiter{
        .id = 1,
        .ballot = .{ .round = 1, .priority = 1, .node = 1 },
        .fence_slot = 1,
        .needed = 1,
        .done = true,
    };
    try std.testing.expectError(error.Unavailable, fence.awaitQuorum(&host, 0, 10_000));
}
