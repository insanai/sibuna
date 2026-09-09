//! Local commands act only on the serving node. Membership combines replicated rows with
//! this console's own probes of explicitly configured peer listeners.
const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const Handler = @import("routes.zig").Handler;

pub fn dispatch(app: *App, context: *http.Context, actor: p.Principal, kind: Handler) !void {
    const auth: p.users.Auth = .{
        .session_digest = try http.session(context),
        .csrf_digest = actor.csrf_digest,
        .require_totp = app.config.behind_proxy,
    };
    if (kind != .node_command and !app.query_budget.allow(
        app.io,
        auth.session_digest,
        app.now(),
        .query,
    )) return http.fail(context, .too_many_requests, "CONSOLEQUERY");
    if (kind == .nodes_members) return members(app, context, auth);
    const result = try app.request(switch (kind) {
        .node_status => .{ .node_status = auth },
        .node_command => .{ .node_command = try command(context, auth, app.now()) },
        .node_command_read => .{ .node_command_read = try read(context, auth) },
        else => unreachable,
    });
    switch (result) {
        .node_status => |value| return http.json(context, value, &.{}),
        .node_receipt => |value| return http.json(context, value, &.{}),
        .failed => |reason| return http.fail(context, switch (reason) {
            .unauthorized => .unauthorized,
            .forbidden => .forbidden,
            .invalid_input => .bad_request,
            .conflict => .conflict,
            else => .service_unavailable,
        }, "CONSOLENODE"),
        else => return error.StorageUnavailable,
    }
}

fn members(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    const result = try app.request(.{ .nodes_query = auth });
    switch (result) {
        .nodes_page => |page| {
            var probes: [p.nodes.max_probes]p.nodes.Probe = undefined;
            const count = app.cluster.snapshot(&probes);
            var peers: [8]@import("peer_store.zig").Report = undefined;
            const peer_count = app.peers.reports(app.now(), &peers);
            return http.json(context, .{
                .page = page,
                .probes = probes[0..count],
                .peers = peers[0..peer_count],
                .observed_at = app.now(),
            }, &.{});
        },
        .failed => |reason| return http.fail(context, switch (reason) {
            .unauthorized => .unauthorized,
            .forbidden => .forbidden,
            else => .service_unavailable,
        }, "CONSOLENODE"),
        else => return error.StorageUnavailable,
    }
}

fn command(context: *http.Context, auth: p.users.Auth, now: u64) !p.nodes.Command {
    var body: [1024]u8 = undefined;
    var memory: [2048]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct {
        id: []const u8,
        boot: []const u8,
        node: u32,
        expected_revision: []const u8,
        kind: p.nodes.Kind,
    }, context, &body, arena.allocator());
    defer parsed.deinit();
    const input = parsed.value;
    return .{
        .auth = auth,
        .id = try identifier(input.id),
        .boot = try identifier(input.boot),
        .node = input.node,
        .expected_revision = std.fmt.parseInt(u64, input.expected_revision, 10) catch
            return error.InvalidRequest,
        .kind = input.kind,
        .expires = now + p.nodes.command_seconds,
    };
}

fn read(context: *http.Context, auth: p.users.Auth) !p.nodes.Read {
    var body: [128]u8 = undefined;
    var memory: [512]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct { id: []const u8 }, context, &body, arena.allocator());
    defer parsed.deinit();
    return .{ .auth = auth, .id = try identifier(parsed.value.id) };
}

fn identifier(value: []const u8) error{InvalidRequest}![16]u8 {
    if (value.len != 32) return error.InvalidRequest;
    var result: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidRequest;
    if (std.mem.allEqual(u8, &result, 0)) return error.InvalidRequest;
    return result;
}
