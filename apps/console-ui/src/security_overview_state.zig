//! Owned views survive event-arena resets. A frozen range belongs to one query generation.
const std = @import("std");
const p = @import("console_protocol");
const decode = @import("json_value.zig").decode;
pub const FeedRow = struct {
    id: u64,
    node: u32,
    time: u64,
    ip: p.Bytes(48),
    path: p.Bytes(128),
    category: p.Bytes(32),
    display_truncated: bool = false,
};
pub const Model = struct {
    hours: u16 = 24,
    request: p.security.Request = .{ .from = 0, .until = 1 },
    tickets: [3]u64 = @splat(0),
    busy: [3]bool = @splat(false),
    loaded: [3]bool = @splat(false),
    failed: [3]bool = @splat(false),
    observed_at: [3]u64 = @splat(0),
    modules: [3]p.security.Findings = @splat(.{}),
    categories: [5]?p.security.Rank = @splat(null),
    paths: [5]?p.security.Rank = @splat(null),
    category_total: u64 = 0,
    feed: [8]?FeedRow = @splat(null),

    pub fn clear(self: *Model) void {
        @memset(std.mem.asBytes(self), 0);
        self.hours = 24;
        self.request.until = 1;
        for (&self.modules) |*module| {
            for (&module.sources) |*source| source.* = null;
        }
        for (&self.categories) |*row| row.* = null;
        for (&self.paths) |*row| row.* = null;
        for (&self.feed) |*row| row.* = null;
    }

    pub fn accept(self: *Model, page: *const p.security.Page) !void {
        if (page.version != 2 or page.request.node != self.request.node or
            page.request.from != self.request.from or
            page.request.until != self.request.until) return error.InvalidResponse;
        switch (page.request.view) {
            .modules => self.modules = page.modules,
            .categories => {
                self.categories = page.rows;
                self.category_total = page.total;
            },
            .paths => self.paths = page.rows,
        }
        const index = @intFromEnum(page.request.view);
        self.observed_at[index] = page.observed_at;
        self.loaded[index] = true;
        self.failed[index] = false;
    }

    pub fn live(self: *Model, value: std.json.Value, alloc: std.mem.Allocator) !void {
        const rows = @import("events_state.zig").field(value, "rows") orelse
            return error.InvalidResponse;
        if (rows != .array or rows.array.items.len > 64) return error.InvalidResponse;
        var candidate: [8]?FeedRow = @splat(null);
        for (rows.array.items) |item| {
            var next: ?FeedRow = try decode(FeedRow, item, alloc);
            if (self.request.node != 0 and next.?.node != self.request.node)
                return error.InvalidResponse;
            for (&candidate) |*row| {
                if (row.* == null or newer(next.?, row.*.?))
                    std.mem.swap(?FeedRow, row, &next);
                if (next == null) break;
            }
        }
        self.feed = candidate;
    }
};

fn newer(a: FeedRow, b: FeedRow) bool {
    return a.time > b.time or (a.time == b.time and a.id > b.id);
}

test "security reset erases retained addresses and restores optional defaults" {
    var model: Model = .{ .loaded = @splat(true) };
    model.categories[0] = .{ .label = try p.Bytes(96).init("private") };
    model.clear();
    try std.testing.expectEqualDeep(Model{}, model);
}

test "live security rows own text, retain newest summaries and reject mismatched nodes" {
    const t = std.testing;
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"rows\":[{\"id\":\"9007199254740993\",\"node\":2,\"time\":100," ++
            "\"ip\":\"8.8.8.8\",\"path\":\"/test\",\"category\":\"audit:xss\"}]}",
        .{},
    );
    var model: Model = .{};
    try model.live(parsed.value, t.allocator);
    model.request.node = 1;
    try t.expectError(error.InvalidResponse, model.live(parsed.value, t.allocator));
    parsed.deinit();
    try t.expectEqualStrings("8.8.8.8", model.feed[0].?.ip.slice());
    try t.expectEqual(@as(u64, 9007199254740993), model.feed[0].?.id);
}
