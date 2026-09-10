const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const Writer = std.Io.Writer;
pub const Model = struct {
    const Row = struct {
        key: p.Bytes(256) = .{},
        encoding: p.rankings.Encoding = .utf8,
        estimate: u64 = 0,
        error_bound: u64 = 0,
    };
    rows: [p.rankings.max_rows]Row = @splat(.{}),
    count: usize = 0,
    node: u32 = 0,
    generation: u32 = 0,
    busy: bool = false,
    loaded: bool = false,
    stale: bool = true,
    requested_at: u64 = 0,
    received_at: u64 = 0,
    minute_start: u64 = 0,
    retained: u64 = 0,
    truncated: u64 = 0,
    rejected: u64 = 0,
    queue_loss: u64 = 0,

    pub fn clear(self: *Model) void {
        // All fields have a zero representation except stale. Erase owned keys at reset
        // without embedding a second full row buffer in the WebAssembly data segment.
        @memset(std.mem.asBytes(self), 0);
        self.stale = true;
    }

    /// Copy every retained key before the shared browser event arena is erased.
    pub fn decode(self: *Model, value: std.json.Value, _: std.mem.Allocator) !void {
        const data = @import("events_state.zig");
        const source = data.field(value, "rows") orelse return error.InvalidResponse;
        if (source != .array or source.array.items.len > self.rows.len or
            try unsigned(value, "counter_capacity") != 256 or
            !std.mem.eql(u8, data.string(value, "kind"), "path_prefix") or
            !std.mem.eql(u8, data.string(value, "sampling_probability"), "1/64"))
            return error.InvalidResponse;
        var replacement: Model = undefined;
        replacement.clear();
        replacement.generation = self.generation;
        replacement.busy = self.busy;
        replacement.requested_at = self.requested_at;
        replacement.retained = try unsigned(value, "retained_samples");
        for (source.array.items, 0..) |row, i| {
            const encoding = data.string(row, "encoding");
            const encoded = std.mem.eql(u8, encoding, "hex");
            if (!encoded and !std.mem.eql(u8, encoding, "utf8")) return error.InvalidResponse;
            const key = data.field(row, "key") orelse return error.InvalidResponse;
            const limit: usize = if (encoded) 256 else 128;
            if (key != .string or key.string.len > limit) return error.InvalidResponse;
            const estimate = try unsigned(row, "estimate");
            const bound = try unsigned(row, "error_bound");
            if (bound > estimate or bound > replacement.retained / 256)
                return error.InvalidResponse;
            replacement.rows[i] = .{
                .key = try p.Bytes(256).init(key.string),
                .encoding = if (encoded) .hex else .utf8,
                .estimate = estimate,
                .error_bound = bound,
            };
        }
        replacement.count = source.array.items.len;
        if (data.field(value, "node") != null) {
            const node = try unsigned(value, "node");
            if (node > std.math.maxInt(u32)) return error.InvalidResponse;
            replacement.node = @intCast(node);
        }
        replacement.minute_start = try unsigned(value, "minute_start");
        replacement.truncated = try unsigned(value, "truncated_records");
        replacement.rejected = try unsigned(value, "rejected_records");
        replacement.queue_loss = try unsigned(value, "queue_loss_since_boot");
        replacement.loaded = true;
        replacement.stale = false;
        self.* = replacement;
    }
};

fn unsigned(value: std.json.Value, key: []const u8) !u64 {
    const item = @import("events_state.zig").field(value, key) orelse return error.InvalidResponse;
    if (item == .integer and item.integer >= 0) return @intCast(item.integer);
    if (item == .number_string) return std.fmt.parseInt(u64, item.number_string, 10);
    return error.InvalidResponse;
}

pub fn render(model: *const Model, w: *Writer, now: u64, paused: bool) Writer.Error!void {
    try html.render(w, "<section class=\"sb-panel mt-6\" aria-labelledby=\"ranking-heading\">" ++
        "<h2 id=\"ranking-heading\">Sampled request paths</h2>" ++
        "<p class=\"sb-note\">Selected node · partial UTC minute · " ++
        "updates every 10 seconds. " ++
        "Counts show samples at 1/64 probability. " ++
        "128-byte path prefixes. " ++
        "Sample counts lie between the bounds.</p>", .{});
    if (model.loaded) try html.render(w, "<p class=\"sb-note\">Node {{ node }}</p>", .{
        .node = model.node,
    });
    if (!model.loaded) {
        try html.render(w, "<p role=\"status\">", .{});
        try w.writeAll(if (model.generation != 0 and !model.busy)
            "Rankings unavailable. Retrying."
        else
            "Waiting for live path samples.");
        try html.render(w, "</p></section>", .{});
        return;
    }
    const stale = model.stale or paused or now -| model.received_at > 20;
    const hour: u8 = @intCast(model.minute_start / 3600 % 24);
    const minute: u8 = @intCast(model.minute_start / 60 % 60);
    const time = [_]u8{
        '0' + hour / 10,
        '0' + hour % 10,
        ':',
        '0' + minute / 10,
        '0' + minute % 10,
    };
    try html.render(w, "<p class=\"sb-note\">Minute {{ v0 }} UTC · " ++
        "Up to 12 of 256 tracked prefixes.</p>", .{
        .v0 = time,
    });
    try html.render(
        w,
        "<p class=\"sb-note\">{{ v0 }} · Updated {{ v1 }} seconds ago · " ++
            "{{ v2 }} retained samples · {{ v3 }} truncated sample records · " ++
            "{{ v4 }} rejected samples · " ++
            "{{ v5 }} lost queue samples since boot.</p>",
        .{
            .v0 = if (stale) "Stale or paused" else "Live",
            .v1 = now -| model.received_at,
            .v2 = model.retained,
            .v3 = model.truncated,
            .v4 = model.rejected,
            .v5 = model.queue_loss,
        },
    );
    try html.render(w, "<div class=\"overflow-x-auto\"><table class=\"table\">" ++
        "<caption class=\"sb-note\">Sample count bounds</caption>" ++
        "<thead><tr><th>Path prefix</th><th>Estimate</th><th>Lower bound</th></tr></thead>" ++
        "<tbody>", .{});
    for (model.rows[0..model.count]) |*row| try html.render(
        w,
        @embedFile("snippets/ranking-row.html"),
        .{
            .key = row.key.slice(),
            .encoding = if (row.encoding == .hex) " (hex bytes)" else "",
            .estimate = row.estimate,
            .lower = row.estimate - row.error_bound,
        },
    );
    if (model.count == 0) try w.writeAll(
        "<tr><td colspan=\"3\">No path samples this minute.</td></tr>",
    );
    try html.render(w, "</tbody></table></div></section>", .{});
}

test "ranking decoder owns keys, rejects excess rows atomically and escapes rendered paths" {
    const t = std.testing;
    const source =
        \\{"kind":"path_prefix","counter_capacity":256,"sampling_probability":"1/64",
        \\ "minute_start":120,"retained_samples":5,"truncated_records":0,
        \\ "rejected_records":0,"queue_loss_since_boot":0,
        \\ "rows":[{"key":"/<script>","encoding":"utf8","estimate":5,"error_bound":0}]}
    ;
    var input: [source.len]u8 = undefined;
    @memcpy(&input, source);
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), &input, .{});
    var model: Model = .{};
    try model.decode(value, arena.allocator());
    @memset(&input, 0);
    try t.expectEqualStrings("/<script>", model.rows[0].key.slice());
    const old = model;
    const rows = value.object.getPtr("rows").?;
    for (0..12) |_| try rows.array.append(rows.array.items[0]);
    try t.expectError(error.InvalidResponse, model.decode(value, arena.allocator()));
    try t.expectEqualDeep(old, model);
    var output: [8192]u8 = undefined;
    var writer: Writer = .fixed(&output);
    try render(&model, &writer, 0, false);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "&lt;script&gt;") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "<script>") == null);
    model.clear();
    try t.expect(std.mem.allEqual(u8, &model.rows[0].key.data, 0));
}
