//! HTTP authority is checked again after waiting for a peer. A disconnected caller only
//! abandons its owned ticket; cancellation does not recycle work still on the wire.
const std = @import("std");
const p = @import("console_protocol");
const q = @import("peer_query.zig");
const App = @import("app.zig").App;
const http = @import("http.zig");

pub const Read = struct {
    credential: http.Credential,
    node: u32,
    kind: q.Kind,
    cursor: q.Cursor = .{},
};

pub fn handle(app: *App, context: *http.Context, read: Read) !void {
    context.extend(5 + App.storage_wait_seconds + 2);
    const result = request(app, read.node, read.kind, read.cursor) catch |err| switch (err) {
        error.Canceled => return err,
        else => q.Result{ .failed = .unavailable },
    };
    const actor = try app.reauthorize(context, read.credential) orelse return;
    if (app.restricted(actor) or !actor.role.allows(.read) or
        actor.scopes & p.tokens.Scope.stats_read.bit() == 0 or
        (actor.kiosk and read.kind != .timeline))
        return http.fail(context, .forbidden, "CONSOLE403");
    if (result == .page)
        return context.respond(.ok, "application/json", result.page.slice(), &.{});
    const status: std.http.Status = switch (result.failed) {
        .ok => unreachable,
        .conflict => .conflict,
        .invalid => .bad_request,
        .unavailable, .cancelled => .service_unavailable,
    };
    return http.fail(context, status, if (result.failed == .conflict)
        "TIMELINE001"
    else
        "CONSOLEPEERQUERY");
}

fn request(app: *App, node: u32, kind: q.Kind, cursor: q.Cursor) !q.Result {
    const pending = try app.peers.submit(node, kind, cursor, app.now());
    errdefer pending.box.abandon(app.io, pending.ticket) catch |err| {
        std.log.err("peer query cancellation: {t}", .{err});
    };
    try pending.box.waitFor(app.io, pending.ticket, .{ .duration = .{
        .clock = .awake,
        .raw = .fromSeconds(5),
    } });
    return try pending.box.poll(app.io, pending.ticket) orelse error.PeerUnavailable;
}
