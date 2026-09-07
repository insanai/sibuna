const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");

pub fn query(app: *App, context: *http.Context) !void {
    const digest = try http.session(context);
    var body: [2048]u8 = undefined;
    var arena: [8192]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const input = try http.parse(struct {
        before: ?struct { time: u64, id: []const u8 } = null,
        limit: u16 = 10,
        from: u64 = 0,
        until: ?u64 = null,
        node: u32 = 0,
        category: []const u8 = "",
        ip: []const u8 = "",
        path_prefix: []const u8 = "",
    }, context, &body, fixed.allocator());
    defer input.deinit();
    const fields = input.value;
    var request: p.events.Query = .{
        .session_digest = digest,
        .now = app.now(),
        .limit = fields.limit,
        .from = fields.from,
        .until = fields.until orelse std.math.maxInt(i64),
        .node = fields.node,
        .category = try p.Bytes(32).init(fields.category),
        .ip = try p.Bytes(48).init(fields.ip),
        .path_prefix = try p.Bytes(256).init(fields.path_prefix),
    };
    if (fields.before) |cursor| request.before = .{
        .time = cursor.time,
        .id = std.fmt.parseInt(u64, cursor.id, 10) catch return error.InvalidRequest,
    };
    const result = try app.request(.{ .events_query = request });
    if (result == .page)
        return context.respond(.ok, "application/json", result.page.slice(), &.{});
    const status: std.http.Status = switch (result.failed) {
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .invalid_input => .bad_request,
        else => .service_unavailable,
    };
    return http.fail(context, status, "CONSOLEEVENTS");
}
