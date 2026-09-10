const std = @import("std");
const t = std.testing;
const q = @import("peer_query.zig");
const p = @import("console_protocol");
const peers = @import("peer_store.zig");

fn fixture() !peers.Store {
    var options: @import("peer_config.zig").Config = .{ .count = 1 };
    options.targets[0] = .{ .node = 2, .origin = try p.Bytes(255).init("https://peer.test") };
    var store = peers.Store.init(t.io, options, 1, @splat(7));
    try store.startQueries(t.allocator);
    return store;
}

test "peer queries own cursors and fence reconnects without recycling abandoned work" {
    var store = try fixture();
    defer store.deinit();
    const handle = try store.activate(0, @splat(1));
    const box = store.queries[0].?;
    var boot = [_]u8{'a'} ** 32;
    const cursor = try q.Cursor.from(.{ .before = 100, .epoch = 1, .boot = &boot });
    const ticket = try box.submit(t.io, .{
        .generation = handle.generation,
        .boot = handle.boot,
        .kind = .timeline,
        .cursor = cursor,
    }, .background);
    @memset(&boot, 'b');
    var session: @import("peer_query_client.zig").Session = .{ .store = &store, .handle = handle };
    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try t.expect(try session.next(&writer));
    try t.expectEqual(@as(u8, 'a'), session.pending.?.request.cursor.boot.?[0]);
    session.sent_at -= 6 * std.time.ns_per_s;
    try t.expectError(error.PeerQueryTimeout, session.next(&writer));
    try box.abandon(t.io, ticket);
    session.deinit();
    try t.expectError(error.StaleTicket, box.poll(t.io, ticket));
    const old = try box.submit(t.io, .{
        .generation = handle.generation,
        .boot = handle.boot,
        .kind = .rankings,
    }, .background);
    session.handle = try store.activate(0, @splat(2));
    try t.expect(!try session.next(&writer));
    try t.expectEqual(q.Status.unavailable, (try box.poll(t.io, old)).?.failed);
    store.stop();
    try t.expectError(error.Stopping, box.submit(t.io, .{
        .generation = handle.generation,
        .boot = handle.boot,
        .kind = .rankings,
    }, .background));
}

test "peer reader handoff is bounded and preserves FIFO ownership" {
    var queue: @import("peer_query_queue.zig").Queue = .{};
    try t.expect(!try queue.accept(t.io, "{\"op\":\"sub\",\"topic\":\"stats\"}"));
    var bytes: [256]u8 = undefined;
    for (0..8) |index| {
        var writer: std.Io.Writer = .fixed(&bytes);
        try std.json.Stringify.value(q.Wire{
            .op = .peer_query,
            .id = index + 1,
            .kind = .rankings,
        }, .{}, &writer);
        try t.expect(try queue.accept(t.io, writer.buffered()));
    }
    const full = "{\"op\":\"peer_query\",\"id\":9,\"kind\":\"rankings\"}";
    try t.expectError(error.Full, queue.accept(t.io, full));
    for (0..8) |index| try t.expectEqual(index + 1, queue.take(t.io).?.id);
    try t.expect(queue.take(t.io) == null);
    const invalid = "{\"op\":\"peer_query\",\"id\":1,\"kind\":\"timeline\"," ++
        "\"cursor\":{\"limit\":9}}";
    try t.expectError(error.InvalidRequest, queue.accept(t.io, invalid));
}

test "eight escaped ranking rows and maximum counters fit the peer reply body" {
    const label = [_]u8{1} ** 128;
    const row: p.rankings.Row = .{
        .key = &label,
        .encoding = .utf8,
        .estimate = std.math.maxInt(u64),
        .error_bound = std.math.maxInt(u64),
    };
    const rows = [_]p.rankings.Row{row} ** 8;
    var bytes: [q.max_body]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(p.rankings.Page{
        .node = std.math.maxInt(u32),
        .boot = @splat(255),
        .minute_start = std.math.maxInt(u64),
        .snapshot_at = std.math.maxInt(u64),
        .first_sample = std.math.maxInt(u64),
        .last_sample = std.math.maxInt(u64),
        .retained_samples = std.math.maxInt(u64),
        .truncated_records = std.math.maxInt(u64),
        .rejected_records = std.math.maxInt(u64),
        .queue_loss_since_boot = std.math.maxInt(u64),
        .missing_key_bound = std.math.maxInt(u64),
        .rows = &rows,
    }, .{}, &writer);
    try t.expect(writer.buffered().len < q.max_body);
}

test "peer reply identity cannot substitute another node or boot" {
    var store = try fixture();
    defer store.deinit();
    const handle = try store.activate(0, @splat(1));
    const box = store.queries[0].?;
    const ticket = try box.submit(t.io, .{
        .generation = handle.generation,
        .boot = handle.boot,
        .kind = .rankings,
    }, .background);
    var session: @import("peer_query_client.zig").Session = .{ .store = &store, .handle = handle };
    defer session.deinit();
    var output: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&output);
    try t.expect(try session.next(&writer));
    for (0..2) |i| {
        const body = try std.json.Stringify.valueAlloc(t.allocator, .{
            .op = "peer_result",
            .id = ticket.id,
            .node = @as(u32, if (i == 0) 3 else 2),
            .boot = @as([16]u8, @splat(if (i == 0) 1 else 2)),
            .status = "unavailable",
            .data = @as(?u8, null),
        }, .{});
        defer t.allocator.free(body);
        const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, body, .{});
        defer parsed.deinit();
        try t.expectError(error.InvalidPeerReply, session.receive(parsed.value, t.allocator));
        try t.expect(try box.poll(t.io, ticket) == null);
    }
}
