//! Safe template pages recheck the task's source, revision and authority around copying.
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
        offset: u8,
    }, context, &body, fixed.allocator());
    defer parsed.deinit();
    const id = try routes.identifier(parsed.value.id);
    const result = try app.crs_job.testSnapshot(auth, id);
    if (result.kind != .sample or result.state != .complete) return error.InvalidRequest;
    const report = result.report orelse return error.InvalidRequest;
    if (parsed.value.offset > report.event_count or
        parsed.value.offset % p.crs_tasks.sample_details.page_capacity != 0)
        return error.InvalidRequest;
    try @import("crs_task_access.zig").recheck(app, auth, &result);
    const output = try app.gpa.create(p.crs_tasks.DetailPage);
    defer app.gpa.destroy(output);
    defer std.crypto.secureZero(u8, std.mem.asBytes(output));
    output.id = id;
    output.expected_revision = result.expected_revision;
    try app.crs_job.detailPage(auth, id, parsed.value.offset, &output.page);
    try @import("crs_task_access.zig").recheck(app, auth, &result);
    output.expires = try app.crs_job.renewTask(auth, id);
    try output.validate();
    return http.json(context, output.*, &.{});
}
