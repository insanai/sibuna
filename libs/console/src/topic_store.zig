//! Hub-owned topic state and journals. Network threads consume copied outbox frames only.
const std = @import("std");
const p = @import("console_protocol");
const s = p.subscriptions;
const feed = p.subscription_feed;
pub const Metadata = struct {
    kind: enum { patch, row, gap } = .patch,
    update: u64 = 0,
    part: u16 = 0,
    parts: u16 = 1,
    node: u32 = 0,
    actor: u64 = 0,
    category: p.Bytes(32) = .{},
    ip: p.Bytes(48) = .{},
    path: p.Bytes(128) = .{},
    action: p.Bytes(48) = .{},

    pub fn matches(self: *const Metadata, args: *const s.Args) bool {
        return (args.node == null or args.node.? == self.node) and
            (args.actor == null or args.actor.? == self.actor) and
            match(args.category.slice(), self.category.slice()) and
            match(args.ip.slice(), self.ip.slice()) and
            match(args.action.slice(), self.action.slice()) and
            std.mem.startsWith(u8, self.path.slice(), args.path_prefix.slice());
    }

    fn match(filter: []const u8, value: []const u8) bool {
        return filter.len == 0 or std.mem.eql(u8, filter, value);
    }
};
pub const Journal = @import("topic_ring.zig").Ring(s.ring_capacity, s.record_bytes, Metadata);
pub const Watermark = struct {
    node: u32 = 0,
    id: p.Counter = .{ .value = 0 },
    observed_at: p.Counter = .{ .value = 0 },
    producer_dropped: ?p.Counter = null,
    producer_boot: ?[32]u8 = null,
    replica_observed_at: p.Counter = .{ .value = 0 },
    replica_quorum: bool = false,
};
const Coverage = struct {
    available: bool,
    observed_at: p.Counter,
    missing_ids: p.Counter,
    retained_summaries: usize,
    summary_limit: usize = 64,
    expected_sources: u8,
    sources: []const Watermark,
};
pub const Store = struct {
    ring: Journal = .{},
    current: p.Bytes(s.snapshot_bytes) = .{},
    recent: [64]Journal.Record = undefined,
    recent_head: usize = 0,
    recent_count: usize = 0,
    update: u64 = 0,
    available: bool = false,
    observed_at: u64 = 0,
    missing_ids: u64 = 0,
    sources: [p.nodes.max_members]Watermark = @splat(.{}),
    source_count: u8 = 0,
    expected_sources: u8 = 1,

    /// The caller's fixed scratch arena is reset between publications. Neither the ring
    /// publisher nor its readers allocate; state serialization runs only on the hub thread.
    pub fn state(
        self: *Store,
        io: std.Io,
        arena: std.mem.Allocator,
        bytes: []const u8,
        scratch: []u8,
    ) !void {
        if (bytes.len > s.snapshot_bytes) return error.TooLarge;
        var output: std.Io.Writer = .fixed(scratch);
        const previous = if (self.available) self.current.slice() else "{\"available\":false}";
        if (try p.json_delta.write(arena, previous, bytes, &output))
            try self.publish(io, .{}, output.buffered());
        try self.current.set(bytes);
        self.available = true;
    }

    pub fn row(self: *Store, io: std.Io, value: feed.Row) !void {
        var record: Journal.Record = .{
            .metadata = .{ .kind = .row },
            .len = 0,
            .bytes = undefined,
        };
        var output: std.Io.Writer = .fixed(&record.bytes);
        switch (value) {
            .events => |event| {
                record.metadata.node = event.node;
                record.metadata.ip = event.ip;
                record.metadata.path = event.path;
                record.metadata.category = event.category;
                try std.json.Stringify.value(event, .{}, &output);
            },
            .audit => |audit| {
                record.metadata.actor = audit.actor;
                record.metadata.action = audit.action;
                try std.json.Stringify.value(audit, .{}, &output);
            },
        }
        record.len = @intCast(output.buffered().len);
        try self.publish(io, record.metadata, record.payload());
        self.recent[self.recent_head] = record;
        self.recent_head = (self.recent_head + 1) % self.recent.len;
        self.recent_count = @min(self.recent.len, self.recent_count + 1);
    }

    fn publish(self: *Store, io: std.Io, input: Metadata, bytes: []const u8) !void {
        if (self.update == std.math.maxInt(u64)) return error.SequenceExhausted;
        self.update += 1;
        var metadata = input;
        metadata.update = self.update;
        var count: u16 = 0;
        var offset: usize = 0;
        while (offset < bytes.len) : (count += 1)
            offset += s.fragmentLength(bytes[offset..]);
        metadata.parts = count;
        offset = 0;
        while (offset < bytes.len) : (metadata.part += 1) {
            const length = s.fragmentLength(bytes[offset..]);
            _ = try self.ring.publish(io, metadata, bytes[offset..][0..length]);
            offset += length;
        }
    }

    pub fn advance(self: *Store, io: std.Io, page: *const feed.Page) !void {
        if (page.missing_ids != 0) {
            self.missing_ids +|= page.missing_ids;
            try self.publish(io, .{ .kind = .gap }, "{}");
        }
        var index: usize = 0;
        while (index < self.source_count) : (index += 1) {
            if (self.sources[index].node == page.node) break;
        }
        if (index == self.source_count) {
            if (index == self.sources.len) return error.TooManySources;
            self.source_count += 1;
        }
        self.sources[index] = .{
            .node = page.node,
            .id = .{ .value = page.next },
            .observed_at = .{ .value = page.observed_at },
            .producer_dropped = if (page.producer_dropped) |count| .{ .value = count } else null,
            .producer_boot = if (page.producer_dropped != null) page.producer_boot.data else null,
            .replica_observed_at = .{ .value = page.replica_observed_at },
            .replica_quorum = page.replica_quorum,
        };
        self.observed_at = page.observed_at;
        self.available = true;
        var bytes: [4096]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&bytes);
        try std.json.Stringify.value(.{
            .set = .{ .coverage = self.coverage() },
            .remove = @as([]const []const u8, &.{}),
        }, .{}, &writer);
        try self.publish(io, .{}, writer.buffered());
    }

    pub fn snapshot(
        self: *const Store,
        topic: p.Topic,
        args: *const s.Args,
        arena: std.mem.Allocator,
        output: *std.Io.Writer,
    ) !void {
        if (topic == .events or topic == .audit) return self.rows(args, output);
        if (!self.available) return output.writeAll("{\"available\":false}");
        if (topic != .nodes or args.node == null) return output.writeAll(self.current.slice());
        const parsed = try std.json.parseFromSlice(
            std.json.Value,
            arena,
            self.current.slice(),
            .{},
        );
        defer parsed.deinit();
        var value = parsed.value;
        const page = value.object.getPtr("page") orelse return error.InvalidState;
        const members = page.object.getPtr("members") orelse return error.InvalidState;
        filterNodes(members, args.node.?);
        if (value.object.getPtr("probes")) |probes| filterNodes(probes, args.node.?);
        try std.json.Stringify.value(value, .{}, output);
    }

    fn coverage(self: *const Store) Coverage {
        return .{
            .available = self.available,
            .observed_at = .{ .value = self.observed_at },
            .missing_ids = .{ .value = self.missing_ids },
            .retained_summaries = self.recent_count,
            .expected_sources = self.expected_sources,
            .sources = self.sources[0..self.source_count],
        };
    }

    fn rows(self: *const Store, args: *const s.Args, output: *std.Io.Writer) !void {
        try output.writeAll("{\"rows\":[");
        var count: usize = 0;
        for (0..self.recent_count) |offset| {
            const index = (self.recent_head + self.recent.len - offset - 1) % self.recent.len;
            const item = &self.recent[index];
            if (!item.metadata.matches(args)) continue;
            if (output.buffered().len + item.len + 2048 > s.snapshot_bytes) break;
            if (count != 0) try output.writeByte(',');
            try output.writeAll(item.payload());
            count += 1;
        }
        try output.writeAll("],\"coverage\":");
        try std.json.Stringify.value(self.coverage(), .{}, output);
        try output.writeByte('}');
    }
};

fn filterNodes(value: *std.json.Value, node: u32) void {
    var count: usize = 0;
    for (value.array.items) |member| {
        const id = member.object.get("node") orelse continue;
        if (id != .integer or id.integer != node) continue;
        value.array.items[count] = member;
        count += 1;
    }
    value.array.items.len = count;
}

test "topic snapshots bound escaped summaries and keep filtered node probes consistent" {
    const t = std.testing;
    const store = try t.allocator.create(Store);
    defer t.allocator.destroy(store);
    store.* = .{};
    const buffer = try t.allocator.alloc(u8, s.snapshot_bytes);
    defer t.allocator.free(buffer);
    var allocator = std.heap.ArenaAllocator.init(t.allocator);
    defer allocator.deinit();
    for (0..64) |id| try store.row(t.io, .{ .audit = .{
        .id = id + 1,
        .action = try p.Bytes(48).init("\x01" ** 48),
        .target = try p.Bytes(128).init("\x01" ** 128),
    } });
    var writer: std.Io.Writer = .fixed(buffer);
    try store.snapshot(.audit, &.{}, allocator.allocator(), &writer);
    const rows = try std.json.parseFromSlice(
        std.json.Value,
        allocator.allocator(),
        writer.buffered(),
        .{},
    );
    defer rows.deinit();
    const items = rows.value.object.get("rows").?.array.items;
    try t.expect(items.len > 0 and items.len < 64);
    try t.expectEqual(@as(i64, 64), items[0].object.get("id").?.integer);
    store.available = true;
    try store.current.set("{\"page\":{\"members\":[{\"node\":1},{\"node\":2}]}," ++
        "\"probes\":[{\"node\":1},{\"node\":2}]}");
    writer.end = 0;
    try store.snapshot(.nodes, &.{ .node = 2 }, allocator.allocator(), &writer);
    const nodes = try std.json.parseFromSlice(
        std.json.Value,
        allocator.allocator(),
        writer.buffered(),
        .{},
    );
    defer nodes.deinit();
    try t.expectEqual(@as(usize, 1), nodes.value.object.get("probes").?.array.items.len);
    try t.expectEqual(@as(i64, 2), nodes.value.object.get("probes").?.array.items[0]
        .object.get("node").?.integer);
}
