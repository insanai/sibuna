//! Shared native fixtures for arithmetic and subscriber ownership tests.
const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const peers = @import("peer_store.zig");

pub fn fixture() !peers.Store {
    var options: @import("peer_config.zig").Config = .{ .count = 2 };
    for (options.targets[0..2], 2..) |*target, node| target.* = .{
        .node = @intCast(node),
        .origin = try p.Bytes(255).init("https://peer.test"),
    };
    return peers.Store.init(t.io, options, 1, null);
}

pub fn sample(node: u32, requests: u64) p.StatsSnapshot {
    var result = std.mem.zeroes(p.StatsSnapshot);
    result.node = node;
    result.boot = @splat(@intCast(node));
    result.outcomes_version = 1;
    result.uptime_ms = 1000;
    result.timestamp = 100;
    result.sample_probability = "1/64";
    result.requests = requests;
    result.admitted = requests;
    return result;
}

pub fn publish(store: *peers.Store, value: *const p.StatsSnapshot, now: u64) !void {
    const handle = try store.activate(@intCast(value.node - 2), value.boot);
    try t.expect(try store.publish(handle, .{
        .value = value,
        .watermark = value.uptime_ms,
        .sequence = 1,
        .received_at = now,
    }));
}
