//! Storage-owned consensus snapshot of the local member: role, leader, ballot round and
//! log frontiers. A single node reads its own status; a cluster member asks its own
//! Zaxonlite endpoint over the local RPC. Failures keep the last observation and clear
//! `quorum`; nothing here invents progress. Runs only on the owner thread, at most 1/s.
const std = @import("std");
const build_options = @import("build_options");
const zx = @import("zaxonlite");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const Rpc = struct {
    node_id: u32,
    role: []const u8,
    leader: ?u32 = null,
    quorum_available: bool = false,
    ballot: struct { round: u64 = 0 } = .{},
    decided_slot: u64 = 0,
    applied_slot: u64 = 0,
    durable_state_slot: u64 = 0,
};

pub fn refresh(owner: *Persistent, now: u64) void {
    const state = &owner.console_node;
    if (now == state.storage.observed_at) return;
    switch (owner.db) {
        .node => |node| {
            // A single Zaxonlite node leads itself; report it as the one-member case.
            const status = node.status();
            state.storage = .{
                .role = .single,
                .leader = status.leader,
                .term = status.ballot.round,
                .decided = status.decided_slot,
                .applied = status.applied_slot,
                .durable = status.durable_state_slot,
                .quorum = true,
                .observed_at = now,
            };
        },
        .embedded => |embedded| {
            if (!build_options.cluster) unreachable;
            remote(owner, embedded, now) catch |err| {
                if (state.storage.quorum) std.log.warn("storage status unavailable: {t}", .{err});
                state.storage.role = .unknown;
                state.storage.quorum = false;
                state.storage.observed_at = now;
            };
        },
    }
}

fn remote(owner: *Persistent, embedded: *zx.Embedded, now: u64) !void {
    if (!build_options.cluster) unreachable;
    if (embedded.finished.load(.acquire)) return error.Finished;
    const link = owner.status_link orelse blk: {
        const opened = try zx.client.Connection.openWithTransport(
            owner.gpa,
            owner.io,
            embedded.self_endpoint,
            .{
                .secret = embedded.auth_secret,
                .tls = if (embedded.tls_client) |*context| context else null,
            },
        );
        owner.status_link = opened;
        break :blk opened;
    };
    errdefer {
        link.close();
        owner.status_link = null;
    }
    const reply = try link.call("{\"op\":\"status\"}");
    defer owner.gpa.free(reply);
    const parsed = try std.json.parseFromSlice(Rpc, owner.gpa, reply, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const status = parsed.value;
    if (status.node_id != owner.node_id) return error.WrongMember;
    owner.console_node.storage = .{
        .role = parseRole(status.role),
        .leader = status.leader,
        .term = status.ballot.round,
        .decided = status.decided_slot,
        .applied = status.applied_slot,
        .durable = status.durable_state_slot,
        .quorum = status.quorum_available,
        .observed_at = now,
    };
}

fn parseRole(text: []const u8) p.nodes.Role {
    if (std.mem.eql(u8, text, "leader")) return .leader;
    if (std.mem.eql(u8, text, "follower")) return .follower;
    if (std.mem.eql(u8, text, "candidate")) return .candidate;
    return .unknown;
}

/// Closes the status link before storage shuts down.
pub fn close(owner: *Persistent) void {
    if (!build_options.cluster) return;
    if (owner.status_link) |link| link.close();
    owner.status_link = null;
}

test "unknown role strings never claim leadership" {
    try std.testing.expectEqual(p.nodes.Role.unknown, parseRole("observer"));
    try std.testing.expectEqual(p.nodes.Role.leader, parseRole("leader"));
}
