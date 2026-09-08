const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");

pub fn query(app: *App, context: *http.Context) !void {
    const digest = try http.session(context);
    if (!app.query_budget.allow(app.io, digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLEQUERY");
    var body: [1024]u8 = undefined;
    var memory: [4096]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct {
        source: []const u8,
        generation: u32,
        from: u64 = 0,
        until: u64,
        before: ?struct { time: u64, id: []const u8 } = null,
    }, context, &body, fixed.allocator());
    defer parsed.deinit();
    const input = parsed.value;
    var request: p.similarity.Query = .{
        .session_digest = digest,
        .require_totp = app.config.behind_proxy,
        .source = std.fmt.parseInt(u64, input.source, 10) catch return error.InvalidRequest,
        .from = input.from,
        .until = input.until,
    };
    if (input.before) |cursor| request.before = .{
        .time = cursor.time,
        .id = std.fmt.parseInt(u64, cursor.id, 10) catch return error.InvalidRequest,
    };
    const result = try app.background(.{ .events_similar = request });
    if (result != .similarity) {
        const status: std.http.Status = switch (result.failed) {
            .unauthorized => .unauthorized,
            .forbidden => .forbidden,
            else => .service_unavailable,
        };
        return http.fail(context, status, "CONSOLESIMILAR");
    }
    var output: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&output);
    try write(result.similarity, input.generation, &writer);
    return context.respond(.ok, "application/json", writer.buffered(), &.{});
}

fn write(part: p.similarity.Part, generation: u32, w: *std.Io.Writer) !void {
    try w.print("{{\"generation\":{d},\"source_available\":{s}," ++
        "\"scanned\":{d},\"invalid\":{d},\"rows\":[", .{
        generation, if (part.source_available) "true" else "false", part.scanned, part.invalid,
    });
    for (part.best.rows[0..part.best.count], 0..) |row, i| {
        if (i != 0) try w.writeByte(',');
        var id: [20]u8 = undefined;
        try std.json.Stringify.value(.{
            .id = try std.fmt.bufPrint(&id, "{d}", .{row.id}),
            .node = row.node,
            .time = row.time,
            .distance = row.distance,
        }, .{}, w);
    }
    try w.writeAll("],\"next\":");
    if (part.next) |cursor| {
        try w.print("{{\"time\":{d},\"id\":\"{d}\"}}", .{ cursor.time, cursor.id });
    } else try w.writeAll("null");
    try w.writeByte('}');
}

test "largest similarity response fits the bounded transport with exact IDs" {
    var part: p.similarity.Part = .{ .source_available = true, .scanned = 64, .invalid = 64 };
    for (0..10) |i| part.best.add(.{
        .id = std.math.maxInt(u64) - i,
        .node = std.math.maxInt(u32),
        .time = std.math.maxInt(u64),
        .distance = 1.234567890123456,
    });
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try write(part, std.math.maxInt(u32), &writer);
    const exact = std.mem.indexOf(u8, writer.buffered(), "\"18446744073709551615\"");
    try std.testing.expect(exact != null);
}
