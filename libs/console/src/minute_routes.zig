//! The HTTP reader owns its decoded request and returned page; Persistent owns database access.
const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");

pub fn handle(app: *App, context: *http.Context, summarized: bool) !void {
    const digest = try http.session(context);
    const now = app.now();
    if (!app.query_budget.allow(app.io, digest, now, .query))
        return http.fail(context, .too_many_requests, "CONSOLE429");
    var body: [1024]u8 = undefined;
    var arena: [2048]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const request = try http.parse(p.minutes.Request, context, &body, fixed.allocator());
    defer request.deinit();
    const until = request.value.until_minute orelse (now / 60 -| @intFromBool(summarized));
    const query: p.minutes.Query = .{
        .session_digest = digest,
        .observed_at = now,
        .require_totp = app.config.behind_proxy,
        .from_minute = request.value.from_minute orelse (until -| 60),
        .until_minute = until,
        .node = request.value.node,
        .before = request.value.before,
        .limit = request.value.limit,
    };
    const operation: p.StorageRequest = if (summarized)
        .{ .minutes_summary = query }
    else
        .{ .minutes_query = query };
    const result = try app.request(operation);
    if (result == .minute_summary) return http.json(context, result.minute_summary, &.{});
    if (result == .failed and result.failed == .unauthorized)
        return http.fail(context, .unauthorized, "CONSOLE401");
    if (result == .failed and result.failed == .forbidden)
        return http.fail(context, .forbidden, "CONSOLE403");
    if (result == .failed and result.failed == .invalid_input)
        return http.fail(context, .bad_request, "CONSOLE400");
    if (result != .minute_page) return context.respond(
        .service_unavailable,
        "application/json",
        "{\"error\":\"MINUTES001\",\"hint\":\"Minute history unavailable. Retry after " ++
            "storage recovers.\"}",
        &.{},
    );
    const page = &result.minute_page;
    return http.json(context, p.minutes.Reply{
        .retention_days = page.retention_days,
        .from_minute = @min(until, @max(
            query.from_minute,
            now / 60 -| (@as(u64, page.retention_days) * 1440),
        )),
        .until_minute = until,
        .observed_at = now,
        .rows = page.rows[0..page.count],
        .next = page.next,
    }, &.{});
}
