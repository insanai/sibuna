//! Authentication and CSRF are checked by dispatch; history never opens a telemetry producer.
const std = @import("std");
const p = @import("console_protocol").timeline;
const App = @import("app.zig").App;
const http = @import("http.zig");

pub fn handle(app: *App, context: *http.Context) !void {
    const digest = try http.session(context);
    if (!app.query_budget.allow(app.io, digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLE429");
    var body: [256]u8 = undefined;
    var arena: [1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    const query = try http.parse(p.Query, context, &body, fixed.allocator());
    defer query.deinit();
    const boot = std.fmt.bytesToHex(app.stats.boot, .lower);
    var rows: [p.max_rows]p.Bucket = undefined;
    // Copy only this page under the collector mutex; a slow HTTP writer owns its output.
    app.stats.mutex.lockUncancelable(app.io);
    const page = app.stats.timeline.page(query.value, app.stats.node, &boot, &rows);
    app.stats.mutex.unlock(app.io);
    const result = page catch |err| switch (err) {
        error.Conflict => return context.respond(
            .conflict,
            "application/json",
            "{\"error\":\"TIMELINE001\",\"hint\":\"History changed. Reload the latest page.\"}",
            &.{},
        ),
        else => return err,
    };
    return http.json(context, result, &.{});
}
