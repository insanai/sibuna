const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");

pub fn read(app: *App, context: *http.Context) !void {
    const digest = try http.session(context);
    if (!app.query_budget.allow(app.io, digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLEQUERY");
    var body: [2048]u8 = undefined;
    var memory: [8192]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct {
        kind: enum { catalog, document, history } = .catalog,
        id: []const u8 = "",
        after: []const u8 = "",
        committed: ?[]const u8 = null,
        revision: ?[]const u8 = null,
        before: ?[]const u8 = null,
    }, context, &body, fixed.allocator());
    defer parsed.deinit();
    const input = parsed.value;
    const result = try app.request(.{ .policy_read = .{
        .session_digest = digest,
        .now = app.now(),
        .committed = try number(input.committed),
        .selection = switch (input.kind) {
            .catalog => .{ .catalog = try p.Bytes(128).init(input.after) },
            .document => .{ .document = .{
                .id = try p.Bytes(128).init(input.id),
                .revision = try number(input.revision),
            } },
            .history => .{ .history = .{
                .id = try p.Bytes(128).init(input.id),
                .before = try number(input.before),
            } },
        },
    } });
    if (result == .page)
        return context.respond(.ok, "application/json", result.page.slice(), &.{});
    if (result == .policy_document) {
        var revision: [20]u8 = undefined;
        return http.json(context, .{
            .committed = try std.fmt.bufPrint(
                &revision,
                "{d}",
                .{result.policy_document.revision},
            ),
            .document = result.policy_document.document.slice(),
        }, &.{});
    }
    return http.fail(context, switch (result.failed) {
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .conflict => .conflict,
        .invalid_input => .bad_request,
        else => .service_unavailable,
    }, "CONSOLEPOLICY");
}

fn number(value: ?[]const u8) error{InvalidRequest}!?u64 {
    return if (value) |text| std.fmt.parseInt(u64, text, 10) catch error.InvalidRequest else null;
}
