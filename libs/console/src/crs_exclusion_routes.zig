//! Pagination consumes immutable owned rows; compilation never runs on HTTP tasks.
const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const routes = @import("crs_routes.zig");

pub fn read(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    _ = try routes.administrator(app, auth);
    var body: [256]u8 = undefined;
    var memory: [1024]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&memory);
    const parsed = try http.parse(struct {
        id: []const u8,
        side: p.crs_tasks.review.exclusions.Side,
        offset: u32,
    }, context, &body, fixed.allocator());
    defer parsed.deinit();
    const id = try routes.identifier(parsed.value.id);
    const result = try app.crs_job.testSnapshot(auth, id);
    if (result.kind != .review or result.state != .complete) return error.InvalidRequest;
    try @import("crs_task_access.zig").recheck(app, auth, &result);
    const output = try app.gpa.create(p.crs_tasks.ExclusionPage);
    defer app.gpa.destroy(output);
    output.id = id;
    output.expected_revision = result.expected_revision;
    try app.crs_job.exclusionPage(auth, id, parsed.value.side, parsed.value.offset, &output.page);
    try @import("crs_task_access.zig").recheck(app, auth, &result);
    output.expires = try app.crs_job.renewReview(auth, id);
    try output.validate();
    return http.json(context, output.*, &.{});
}
