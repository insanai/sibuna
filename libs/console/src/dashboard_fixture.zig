//! Shared native fixtures for arithmetic and subscriber ownership tests.
const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const peers = @import("peer_store.zig");

pub fn fixture() !peers.Store {
    return configured(2);
}

pub fn configured(count: u8) !peers.Store {
    std.debug.assert(count <= 8);
    var options: @import("peer_config.zig").Config = .{ .count = count };
    for (options.targets[0..count], 2..) |*target, node| target.* = .{
        .node = @intCast(node),
        .origin = try p.Bytes(255).init("https://peer.test"),
    };
    return peers.Store.init(t.io, options, 1, null);
}

/// Fill every source and ranking slot with exact counters above JavaScript's integer range.
pub fn maximum(store: *peers.Store) !p.StatsSnapshot {
    var local = sample(1, 9007199254740993);
    local.server_location = .{ .lat = -89.12345678901234, .lon = 179.12345678901234 };
    local.incident_geo = .{};
    var codes: [32]u16 = undefined;
    var count: usize = 0;
    for (0..676) |index| {
        const code = [2]u8{ @intCast(index / 26 + 'A'), @intCast(index % 26 + 'A') };
        if (!@import("geoip").country.valid(&code)) continue;
        codes[count] = @as(u16, code[0]) << 8 | code[1];
        count += 1;
        if (count == codes.len) break;
    }
    try t.expectEqual(codes.len, count);
    for (0..9) |index| {
        var value = local;
        value.node = @intCast(index + 1);
        value.boot = @splat(@intCast(index + 1));
        for (codes, 0..) |code, i| {
            value.countries[i] = .{ .code = code, .samples = 9007199254740993 };
            value.incident_geo.?.countries[i] = value.countries[i];
        }
        if (index == 0) local = value else try publish(store, &value, 100);
    }
    return local;
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
