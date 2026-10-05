//! HTTP tasks transfer an owned bounded body, never compilation or evaluation.
const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const api = @import("crs_routes.zig");
const jobs = @import("crs_job.zig");

pub fn submit(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    _ = try api.administrator(app, auth);
    const content_type = try context.header("Content-Type") orelse return error.InvalidRequest;
    if (!std.mem.eql(u8, content_type, "application/json")) return error.InvalidRequest;
    var input: @import("crs_test_worker.zig").Input = .{
        .auth = auth,
        .id = jobs.identifier(app.io),
        .body = try app.gpa.alloc(u8, p.crs_tests.sample.sample_json_bytes),
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

pub fn read(app: *App, context: *http.Context, auth: p.users.Auth) !void {
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
    _ = try api.administrator(app, auth);
    return http.json(context, result, &.{});
}
