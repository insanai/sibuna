const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const Hub = @import("subscription_hub.zig").Hub;
const Handle = @import("subscription_hub.zig").Handle;

fn state(hub: *Hub, count: u64) !void {
    var buffer: [128]u8 = undefined;
    var scratch: [256]u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    try hub.stores[@intFromEnum(p.Topic.stats)].state(
        t.io,
        arena.allocator(),
        try std.fmt.bufPrint(&buffer, "{{\"count\":{d},\"unchanged\":true}}", .{count}),
        &scratch,
    );
}

fn message(hub: *Hub, handle: Handle, op: []const u8, sequence: u64) !void {
    const item = hub.take(handle) orelse return error.MissingFrame;
    try t.expect(item == .frame);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        item.frame.bytes.slice(),
        .{},
    );
    defer parsed.deinit();
    try t.expectEqualStrings(op, parsed.value.object.get("op").?.string);
    try t.expectEqual(sequence, @as(u64, @intCast(parsed.value.object.get("seq").?.integer)));
}

test "hub snapshots precede deltas and overflow pauses until a fresh epoch" {
    const hub = try Hub.init(t.allocator, t.io, @splat(1));
    defer hub.deinit();
    const handle = try hub.attach();
    defer hub.detach(handle);
    try state(hub, 1);
    try hub.command(handle, .{ .op = .sub, .topic = .stats });
    hub.fanout();
    try message(hub, handle, "snapshot_begin", 0);
    try message(hub, handle, "snapshot_chunk", 1);
    try message(hub, handle, "snapshot_end", 2);
    try state(hub, 2);
    hub.fanout();
    const update = hub.take(handle).?.frame;
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        update.bytes.slice(),
        .{},
    );
    defer parsed.deinit();
    const delta = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        parsed.value.object.get("data").?.string,
        .{},
    );
    defer delta.deinit();
    try t.expectEqual(@as(i64, 2), delta.value.object.get("set").?.object.get("count").?.integer);
    try t.expect(!delta.value.object.get("set").?.object.contains("unchanged"));
    for (3..80) |count| {
        try state(hub, count);
        hub.fanout();
    }
    try t.expect(hub.take(handle).? == .gap);
    try t.expectEqual(null, hub.take(handle));
    try state(hub, 90);
    hub.fanout();
    try t.expectEqual(null, hub.take(handle));
    try hub.command(handle, .{ .op = .sub, .topic = .stats });
    hub.fanout();
    try message(hub, handle, "snapshot_begin", 0);
    try message(hub, handle, "snapshot_chunk", 1);
    try message(hub, handle, "snapshot_end", 2);
}

test "hub filters retained summaries and recycled handles cannot change another stream" {
    const hub = try Hub.init(t.allocator, t.io, @splat(2));
    defer hub.deinit();
    const stale = try hub.attach();
    hub.detach(stale);
    const handle = try hub.attach();
    defer hub.detach(handle);
    try t.expectEqual(stale.index, handle.index);
    try t.expectError(error.StaleHandle, hub.command(stale, .{ .op = .sub, .topic = .stats }));
    const store = hub.stores[@intFromEnum(p.Topic.events)];
    for ([_]u32{ 1, 2 }) |node| try store.row(t.io, .{ .events = .{
        .node = node,
        .id = @as(u64, node) << 40 | 1,
        .category = try p.Bytes(32).init("honeypot"),
    } });
    try hub.command(handle, .{ .op = .sub, .topic = .events, .args = .{ .node = 2 } });
    hub.fanout();
    try message(hub, handle, "snapshot_begin", 0);
    const item = hub.take(handle).?.frame;
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        item.bytes.slice(),
        .{},
    );
    defer parsed.deinit();
    const data = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        parsed.value.object.get("data").?.string,
        .{},
    );
    defer data.deinit();
    const rows = data.value.object.get("rows").?.array.items;
    try t.expectEqual(@as(usize, 1), rows.len);
    try t.expectEqual(@as(i64, 2), rows[0].object.get("node").?.integer);
    try message(hub, handle, "snapshot_end", 2);
}

test "peer and browser hub partitions cannot consume each other's quota" {
    const hub = try Hub.init(t.allocator, t.io, @splat(3));
    defer hub.deinit();
    var browsers: [64]Handle = undefined;
    var peers: [16]Handle = undefined;
    for (&browsers) |*handle| handle.* = try hub.attach();
    defer for (browsers) |handle| hub.detach(handle);
    try t.expectError(error.Full, hub.attach());
    for (&peers) |*handle| handle.* = try hub.attachPeer();
    defer for (peers) |handle| hub.detach(handle);
    try t.expectError(error.Full, hub.attachPeer());
    for (browsers) |handle| try t.expect(handle.index < 64);
    for (peers) |handle| try t.expect(handle.index >= 64);
}

test {
    _ = @import("dashboard_hub_test.zig");
}
