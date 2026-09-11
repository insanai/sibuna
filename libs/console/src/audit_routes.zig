const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const origin = @import("origin.zig");
const Handler = @import("routes.zig").Handler;

pub fn handle(app: *App, context: *http.Context, principal: p.Principal, kind: Handler) !void {
    const digest = try http.session(context);
    const budget_kind: @import("query_budget.zig").Kind =
        if (kind == .audit_export) .export_page else .query;
    if (!app.query_budget.allow(app.io, digest, app.now(), budget_kind))
        return http.fail(context, .too_many_requests, "CONSOLEQUERY");
    const auth = try origin.authority(app, context, principal);
    var body: [1024]u8 = undefined;
    var memory: [4096]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    if (kind == .audit_read) {
        const Id = struct { id: []const u8 };
        const parsed = try http.parse(Id, context, &body, arena.allocator());
        defer parsed.deinit();
        const result = try app.request(.{ .audit_read = .{
            .auth = auth,
            .id = try number(parsed.value.id),
        } });
        if (result != .audit_detail) return fail(context, result.failed);
        return http.json(context, result.audit_detail, &.{});
    }
    const parsed = try http.parse(struct {
        before: ?[]const u8 = null,
        actor: ?[]const u8 = null,
        action: []const u8 = "",
        since: ?[]const u8 = null,
        until: ?[]const u8 = null,
    }, context, &body, arena.allocator());
    defer parsed.deinit();
    const value = parsed.value;
    const result = try app.request(.{ .audit_query = .{
        .auth = auth,
        .before = if (value.before) |v| try number(v) else p.audit.last_id,
        .actor = if (value.actor) |v| try number(v) else null,
        .action = try p.Bytes(48).init(value.action),
        .since = if (value.since) |v| try number(v) else 0,
        .until = if (value.until) |v| try number(v) else p.audit.last_id,
        .export_page = kind == .audit_export,
    } });
    if (result != .audit_page) return fail(context, result.failed);
    return http.json(context, result.audit_page, &.{});
}

fn number(value: []const u8) error{InvalidRequest}!u64 {
    if (value.len == 0 or value.len > 19) return error.InvalidRequest;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidRequest;
    const result = std.fmt.parseInt(u64, value, 10) catch return error.InvalidRequest;
    if (result > p.audit.last_id) return error.InvalidRequest;
    return result;
}

fn fail(context: *http.Context, reason: p.Failure) !void {
    const status: std.http.Status = switch (reason) {
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .conflict => .not_found,
        .invalid_input => .bad_request,
        else => .service_unavailable,
    };
    const code = if (reason == .conflict) "CONSOLEAUDIT404" else "CONSOLEAUDIT";
    return http.fail(context, status, code);
}
