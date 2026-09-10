//! Full policy authorization precedes a bounded owner query and is checked again on completion.
const std = @import("std");
const p = @import("console_protocol");
const wire = p.rule_hit_history;
const App = @import("app.zig").App;
const http = @import("http.zig");
const Form = struct {
    key: []const u8,
    node: u32,
    from_minute: u64,
    until_minute: u64,
    revision: ?u64 = null,
    before: ?wire.Cursor = null,
};

pub fn handle(app: *App, context: *http.Context) !void {
    const digest = try http.session(context);
    const now = app.now();
    if (!app.query_budget.allow(app.io, digest, now, .query))
        return http.fail(context, .too_many_requests, "CONSOLE429");
    var body: [2048]u8 = undefined;
    var arena: [8192]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const request = try http.parse(Form, context, &body, fixed.allocator());
    defer request.deinit();
    const form = request.value;
    const key = p.rule_hits.Key.init(form.key) catch
        return http.fail(context, .bad_request, "CONSOLE400");
    const query: wire.Query = .{
        .session_digest = digest,
        .require_totp = app.config.behind_proxy,
        .observed_at = now,
        .request = .{
            .key = key,
            .node = form.node,
            .from_minute = form.from_minute,
            .until_minute = form.until_minute,
            .revision = form.revision,
            .before = form.before,
        },
    };
    wire.validate(query) catch return http.fail(context, .bad_request, "CONSOLE400");
    const result = try app.request(.{ .rule_hit_history = query });
    if (result == .rule_hit_history) return http.json(context, result.rule_hit_history, &.{});
    if (result == .failed) switch (result.failed) {
        .unauthorized => return http.fail(context, .unauthorized, "CONSOLE401"),
        .forbidden => return http.fail(context, .forbidden, "CONSOLE403"),
        .conflict => return http.fail(context, .conflict, "CONSOLE409"),
        .invalid_input => return http.fail(context, .bad_request, "CONSOLE400"),
        else => {},
    };
    return context.respond(
        .service_unavailable,
        "application/json",
        "{\"error\":\"RULEHITS001\",\"hint\":\"Rule history is unavailable. " ++
            "Check storage and access, then retry.\"}",
        &.{},
    );
}
