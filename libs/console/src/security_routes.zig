const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");

pub fn query(app: *App, context: *http.Context) !void {
    const digest = try http.session(context);
    if (!app.query_budget.allow(app.io, digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLEQUERY");
    var body: [256]u8 = undefined;
    var arena: [1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const input = try http.parse(p.security.Request, context, &body, fixed.allocator());
    defer input.deinit();
    const result = try app.request(.{ .security_query = .{
        .session_digest = digest,
        .require_totp = app.config.behind_proxy,
        .request = input.value,
    } });
    if (result == .page)
        return context.respond(.ok, "application/json", result.page.slice(), &.{});
    const status: std.http.Status = switch (result.failed) {
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .invalid_input => .bad_request,
        else => .service_unavailable,
    };
    return http.fail(context, status, "CONSOLESECURITY");
}
