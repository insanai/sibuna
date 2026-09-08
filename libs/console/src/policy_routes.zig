const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");

pub fn query(app: *App, context: *http.Context, testing: bool) !void {
    const digest = try http.session(context);
    if (!app.query_budget.allow(app.io, digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLEQUERY");
    var body: [8192]u8 = undefined;
    var memory: [16384]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct {
        offset: u8 = 0,
        applied: ?[]const u8 = null,
        path: []const u8 = "",
        query: []const u8 = "",
        ip: []const u8 = "",
        user_agent: []const u8 = "",
        body: []const u8 = "",
        draft: ?[]const u8 = null,
        committed: ?[]const u8 = null,
        headers: []const struct { name: []const u8, value: []const u8 } = &.{},
    }, context, &body, fixed.allocator());
    defer parsed.deinit();
    const fields = parsed.value;
    const request: p.policies.Query = .{
        .session_digest = digest,
        .now = app.now(),
        .offset = fields.offset,
        .applied = if (fields.applied) |revision|
            std.fmt.parseInt(u64, revision, 10) catch return error.InvalidRequest
        else
            null,
    };
    var operation: p.StorageRequest = .{ .policies_query = request };
    if (testing) {
        var input: p.policies.Test = .{
            .query = request,
            .path = try p.Bytes(512).init(fields.path),
            .query_string = try p.Bytes(512).init(fields.query),
            .ip = try p.Bytes(48).init(fields.ip),
            .user_agent = try p.Bytes(256).init(fields.user_agent),
            .body = try p.Bytes(2048).init(fields.body),
            .draft = if (fields.draft) |draft| try p.Bytes(4096).init(draft) else null,
            .committed = if (fields.committed) |revision|
                std.fmt.parseInt(u64, revision, 10) catch return error.InvalidRequest
            else
                null,
        };
        if (fields.headers.len > input.headers.len) return error.InvalidRequest;
        for (fields.headers, 0..) |header, i| {
            input.headers[i] = .{
                .name = try p.Bytes(64).init(header.name),
                .value = try p.Bytes(256).init(header.value),
            };
        }
        input.header_count = @intCast(fields.headers.len);
        operation = .{ .policies_test = input };
    }
    const result = try app.request(operation);
    if (result == .page) {
        return context.respond(.ok, "application/json", result.page.slice(), &.{});
    }
    return fail(context, result.failed);
}

pub fn edit(app: *App, context: *http.Context, identity: p.Principal, inspection: bool) !void {
    const digest = try http.session(context);
    var body: [8192]u8 = undefined;
    var memory: [16384]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct {
        expected_revision: []const u8,
        document: []const u8,
    }, context, &body, fixed.allocator());
    defer parsed.deinit();
    const input: p.policies.Edit = .{
        .session_digest = digest,
        .csrf_digest = identity.csrf_digest,
        .now = app.now(),
        .expected_revision = std.fmt.parseInt(u64, parsed.value.expected_revision, 10) catch
            return error.InvalidRequest,
        .document = try p.Bytes(4096).init(parsed.value.document),
    };
    const result = try app.request(if (inspection)
        .{ .inspection_edit = input }
    else
        .{ .policy_edit = input });
    if (result != .revision) return fail(context, result.failed);
    var committed: [20]u8 = undefined;
    var applied: [20]u8 = undefined;
    return http.json(context, .{
        .committed = try std.fmt.bufPrint(&committed, "{d}", .{result.revision.committed}),
        .applied = try std.fmt.bufPrint(&applied, "{d}", .{result.revision.applied}),
    }, &.{});
}

fn fail(context: *http.Context, reason: p.Failure) !void {
    return http.fail(context, switch (reason) {
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .conflict => .conflict,
        .invalid_input => .bad_request,
        else => .service_unavailable,
    }, "CONSOLEPOLICY");
}
