//! Only the serialized peer writer calls this service. Snapshot copies release collector
//! locks before encoding or network writes; this route never relays another node's data.
const std = @import("std");
const p = @import("console_protocol");
const q = @import("peer_query.zig");
const App = @import("app.zig").App;

pub fn respond(app: *App, request: q.Wire, writer: *std.Io.Writer) !void {
    var output: [q.max_body]u8 = undefined;
    var body: std.Io.Writer = .fixed(&output);
    const status: q.Status = status: {
        (switch (request.kind) {
            .timeline => timeline(app, request.cursor, &body),
            .rankings => @import("ranking_routes.zig").write(app, &body, 8),
        }) catch |err| break :status switch (err) {
            error.Conflict => .conflict,
            error.InvalidRequest => .invalid,
            else => .unavailable,
        };
        break :status .ok;
    };
    var json: std.json.Stringify = .{ .writer = writer };
    try json.beginObject();
    try json.objectField("op");
    try json.write("peer_result");
    try json.objectField("id");
    try json.write(request.id);
    try json.objectField("node");
    try json.write(app.stats.node);
    try json.objectField("boot");
    try json.write(app.stats.boot);
    try json.objectField("status");
    try json.write(status);
    try json.objectField("data");
    if (status == .ok) try json.print("{s}", .{body.buffered()}) else try json.write(null);
    try json.endObject();
}

fn timeline(app: *App, cursor: q.Cursor, writer: *std.Io.Writer) !void {
    const boot = std.fmt.bytesToHex(app.stats.boot, .lower);
    var rows: [8]p.timeline.Bucket = undefined;
    app.stats.mutex.lockUncancelable(app.io);
    const result = app.stats.timeline.page(cursor.borrowed(), app.stats.node, &boot, &rows);
    app.stats.mutex.unlock(app.io);
    try std.json.Stringify.value(try result, .{}, writer);
}
