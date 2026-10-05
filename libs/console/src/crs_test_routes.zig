//! HTTP tasks transfer an owned bounded body, never compilation or evaluation.
const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const api = @import("crs_routes.zig");
const jobs = @import("crs_job.zig");
const Handler = @import("routes.zig").Handler;

pub fn handle(app: *App, context: *http.Context, auth: p.users.Auth, route: Handler) !void {
    const kind: p.crs_tasks.Kind = switch (route) {
        .crs_test, .crs_test_read => .sample,
        .crs_review, .crs_review_read => .review,
        else => unreachable,
    };
    if (route == .crs_test or route == .crs_review) return submit(app, context, auth, kind);
    return read(app, context, auth, kind);
}

pub fn submit(
    app: *App,
    context: *http.Context,
    auth: p.users.Auth,
    kind: p.crs_tasks.Kind,
) !void {
    _ = try api.administrator(app, auth);
    const content_type = try context.header("Content-Type") orelse return error.InvalidRequest;
    if (!std.mem.eql(u8, content_type, "application/json")) return error.InvalidRequest;
    var input: @import("crs_test_worker.zig").Input = .{
        .auth = auth,
        .kind = kind,
        .id = jobs.identifier(app.io),
        .body = try app.gpa.alloc(u8, if (kind == .sample)
            p.crs_tests.sample.sample_json_bytes
        else
            512),
        .length = 0,
    };
    var transferred = false;
    defer if (!transferred) input.deinit(app.gpa);
    input.length = (try context.body(input.body)).len;
    _ = try api.administrator(app, auth);
    try app.crs_job.enqueueTest(input);
    transferred = true;
    return http.json(context, .{ .accepted = true, .id = input.id.slice() }, &.{});
}

pub fn read(
    app: *App,
    context: *http.Context,
    auth: p.users.Auth,
    kind: p.crs_tasks.Kind,
) !void {
    _ = try api.administrator(app, auth);
    var body: [128]u8 = undefined;
    var memory: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &body);
    defer std.crypto.secureZero(u8, &memory);
    var arena: std.heap.FixedBufferAllocator = .init(&memory);
    const parsed = try http.parse(struct { id: []const u8 }, context, &body, arena.allocator());
    defer parsed.deinit();
    const id = try api.identifier(parsed.value.id);
    const result = try app.crs_job.testSnapshot(auth, id);
    if (result.kind != kind) return error.InvalidRequest;
    _ = try api.administrator(app, auth);
    return http.json(context, result, &.{});
}
