//! Explicit retained queries use background priority; control/auth work retains precedence.
const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
pub const response_bytes = p.ranking_history.response_bytes;

pub fn handle(app: *App, context: *http.Context) !void {
    const session = try http.session(context);
    const now = app.now();
    if (!app.query_budget.allow(app.io, session, now, .query))
        return http.fail(context, .too_many_requests, "CONSOLE429");
    var body: [1024]u8 = undefined;
    var arena: [2048]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const parsed = try http.parse(p.ranking_history.Form, context, &body, fixed.allocator());
    defer parsed.deinit();
    const form = parsed.value;
    const query: p.ranking_history.Query = .{
        .session_digest = session,
        .require_totp = app.config.behind_proxy,
        .observed_at = now,
        .request = .{
            .from_minute = form.from_minute,
            .until_minute = form.until_minute,
            .node = form.node,
            .before = if (form.before) |cursor| .{
                .minute = cursor.minute,
                .digest = p.Bytes(64).init(cursor.digest) catch
                    return http.fail(context, .bad_request, "RANKHISTORY"),
            } else null,
        },
    };
    p.ranking_history.validate(query) catch
        return http.fail(context, .bad_request, "RANKHISTORY");
    const result = try app.background(.{ .rankings_query = query });
    defer p.releaseResult(result, app.gpa);
    if (result == .failed) return http.fail(context, switch (result.failed) {
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .invalid_input => .bad_request,
        .conflict => .conflict,
        else => .service_unavailable,
    }, "RANKHISTORY");
    if (result != .ranking_history) return error.StorageUnavailable;
    const buffer = try app.gpa.alloc(u8, response_bytes);
    defer app.gpa.free(buffer);
    var writer: std.Io.Writer = .fixed(buffer);
    try write(&writer, result.ranking_history);
    return context.respond(.ok, "application/json", writer.buffered(), &.{});
}

fn write(w: *std.Io.Writer, page: p.ranking_history.Page) !void {
    try w.writeAll("{\"version\":1,\"metadata\":");
    try std.json.Stringify.value(.{
        .from_minute = page.from_minute,
        .until_minute = page.until_minute,
        .retention_days = page.retention_days,
        .observed_at = page.observed_at,
        .cursor = page.cursor,
        .next = page.next,
    }, .{}, w);
    try w.writeAll(",\"archive\":\"");
    const alphabet = "0123456789abcdef";
    for (page.payload.slice()) |byte| {
        try w.writeAll(&.{ alphabet[byte >> 4], alphabet[byte & 15] });
    }
    try w.writeAll("\"}");
}
