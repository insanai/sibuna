const std = @import("std");
const t = std.testing;
const p = @import("console_protocol");
const fixture = @import("dashboard_fixture.zig").fixture;
const sample = @import("dashboard_fixture.zig").sample;
const publish = @import("dashboard_fixture.zig").publish;

fn hubState(hub: *@import("subscription_hub.zig").Hub, value: p.StatsSnapshot) !void {
    var bytes: [16384]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(value, .{}, &writer);
    var arena = std.heap.FixedBufferAllocator.init(hub.arena_bytes);
    try hub.stores[@backingInt(p.Topic.stats)].state(
        t.io,
        arena.allocator(),
        writer.buffered(),
        hub.scratch,
    );
    arena.reset();
    writer.end = 0;
    try writer.print("{{\"tick\":{d}}}", .{value.uptime_ms});
    try hub.dashboard_store.state(t.io, arena.allocator(), writer.buffered(), hub.scratch);
}

fn drain(
    hub: *@import("subscription_hub.zig").Hub,
    handle: @import("subscription_hub.zig").Handle,
    client: *p.subscription_client.Client,
) !void {
    const scratch = try t.allocator.alloc(u8, 512 * 1024);
    defer t.allocator.free(scratch);
    while (hub.take(handle)) |item| {
        try t.expect(item == .frame);
        var arena = std.heap.FixedBufferAllocator.init(scratch);
        const parsed = try std.json.parseFromSlice(
            std.json.Value,
            arena.allocator(),
            item.frame.bytes.slice(),
            .{},
        );
        _ = try client.receive(parsed.value, arena.allocator());
    }
}

fn requestCount(client: *p.subscription_client.Client, expected: u64, browser: bool) !void {
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        client.view(.stats),
        .{},
    );
    defer parsed.deinit();
    const value = parsed.value.object.get("requests").?;
    const actual = if (value == .string)
        try std.fmt.parseInt(u64, value.string, 10)
    else
        @as(u64, @intCast(value.integer));
    try t.expectEqual(expected, actual);
    try t.expectEqual(browser, parsed.value.object.contains("scope"));
}

test "full nine-source snapshots and deltas fit hub and browser scratch budgets" {
    var store = try @import("dashboard_fixture.zig").configured(8);
    defer store.deinit();
    var local = try @import("dashboard_fixture.zig").maximum(&store);
    const hub = try @import("subscription_hub.zig").Hub.init(t.allocator, t.io, @splat(1));
    defer hub.deinit();
    const browser = try hub.attach();
    defer hub.detach(browser);
    const peer = try hub.attachPeer();
    defer hub.detach(peer);
    const clients = try t.allocator.alloc(p.subscription_client.Client, 2);
    defer t.allocator.free(clients);
    for (clients) |*client| client.reset();
    try hub.command(browser, .{ .op = .sub, .topic = .stats });
    try hub.command(peer, .{ .op = .sub, .topic = .stats });
    for (0..2) |step| {
        hub.dashboard.collect(&local, &store, 100 + step);
        try hubState(hub, local);
        // The bounded per-tick send allowance may split a full snapshot across ticks.
        for (0..16) |_| {
            hub.fanout();
            try drain(hub, browser, &clients[0]);
            try drain(hub, peer, &clients[1]);
        }
        try t.expect(clients[0].position(.stats) != null);
        try t.expect(clients[1].position(.stats) != null);
        try requestCount(&clients[0], 81064793292668937 + step, true);
        try requestCount(&clients[1], 9007199254740993 + step, false);
        local.requests += 1;
        local.admitted += 1;
        local.uptime_ms += 1000;
    }
}

test "hub isolates peer totals from browser aggregation and filtered state epochs" {
    var store = try fixture();
    defer store.deinit();
    const hub = try @import("subscription_hub.zig").Hub.init(t.allocator, t.io, @splat(1));
    defer hub.deinit();
    const browser = try hub.attach();
    defer hub.detach(browser);
    const peer = try hub.attachPeer();
    defer hub.detach(peer);
    const clients = try t.allocator.alloc(p.subscription_client.Client, 2);
    defer t.allocator.free(clients);
    for (clients) |*client| client.reset();
    var local = sample(1, 10);
    const remote = sample(2, 20);
    try publish(&store, &remote, 100);
    hub.dashboard.collect(&local, &store, 100);
    try hubState(hub, local);
    try hub.command(browser, .{ .op = .sub, .topic = .stats });
    try hub.command(peer, .{ .op = .sub, .topic = .stats });
    hub.fanout();
    try drain(hub, browser, &clients[0]);
    try drain(hub, peer, &clients[1]);
    try requestCount(&clients[0], 30, true);
    try requestCount(&clients[1], 10, false);
    local.requests += 1;
    local.uptime_ms += 1000;
    hub.dashboard.collect(&local, &store, 101);
    try hubState(hub, local);
    hub.fanout();
    try drain(hub, browser, &clients[0]);
    try drain(hub, peer, &clients[1]);
    try requestCount(&clients[0], 31, true);
    try requestCount(&clients[1], 11, false);
    const selection: p.subscriptions.Command = .{
        .op = .filter,
        .topic = .stats,
        .args = .{ .node = 2 },
    };
    try t.expectError(error.InvalidCommand, hub.command(peer, selection));
    try hub.command(browser, selection);
    hub.fanout();
    try drain(hub, browser, &clients[0]);
    try requestCount(&clients[0], 20, true);
    local.uptime_ms += 1000;
    hub.dashboard.collect(&local, &store, 110);
    try hubState(hub, local);
    hub.fanout();
    try drain(hub, browser, &clients[0]);
    const stale = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        clients[0].view(.stats),
        .{},
    );
    defer stale.deinit();
    try t.expect(stale.value.object.get("scope").?.object.get("stale").?.bool);
}
