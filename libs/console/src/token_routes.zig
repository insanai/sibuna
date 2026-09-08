//! Token values exist only in an issuance handler and its acknowledged response. The
//! mailbox receives an owned digest; catalog/revocation responses never include credentials.
const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const Handler = @import("routes.zig").Handler;

pub fn handle(app: *App, context: *http.Context, principal: p.Principal, kind: Handler) !void {
    std.debug.assert(principal.token_id == null and principal.role == .admin);
    const auth: p.users.Auth = .{
        .session_digest = try http.session(context),
        .csrf_digest = principal.csrf_digest,
        .require_totp = app.config.behind_proxy,
    };
    if (kind == .tokens_query and !app.query_budget.allow(
        app.io,
        auth.session_digest,
        app.now(),
        .query,
    )) return http.fail(context, .too_many_requests, "CONSOLEQUERY");
    var body: [2048]u8 = undefined;
    var memory: [8192]u8 = undefined;
    defer std.crypto.secureZero(u8, &body);
    defer std.crypto.secureZero(u8, &memory);
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    if (kind == .tokens_query) {
        const parsed = try http.parse(struct {
            after: ?[]const u8 = null,
            limit: u8 = p.tokens.page_rows,
        }, context, &body, fixed.allocator());
        defer parsed.deinit();
        const result = try app.request(.{ .tokens_query = .{
            .auth = auth,
            .after = if (parsed.value.after) |value| try number(value) else 0,
            .limit = parsed.value.limit,
        } });
        if (result != .tokens_page) return fail(context, result.failed);
        return http.json(context, result.tokens_page, &.{});
    }
    if (kind == .tokens_create) {
        const parsed = try http.parse(Create, context, &body, fixed.allocator());
        defer parsed.deinit();
        return mint(app, context, auth, parsed.value);
    }
    std.debug.assert(kind == .tokens_revoke);
    const parsed = try http.parse(struct {
        target: []const u8,
        expected_revision: []const u8,
        remove: bool = false,
    }, context, &body, fixed.allocator());
    defer parsed.deinit();
    const result = try app.request(.{ .tokens_revoke = .{
        .auth = auth,
        .target = try number(parsed.value.target),
        .expected_revision = try number(parsed.value.expected_revision),
        .remove = parsed.value.remove,
    } });
    if (result != .token_saved) return fail(context, result.failed);
    const saved = .{ .saved = true, .id = p.Counter{ .value = result.token_saved } };
    return http.json(context, saved, &.{});
}

const Create = struct {
    label: []const u8,
    role: p.Role = .viewer,
    scopes: []const p.tokens.Scope,
    expires: ?[]const u8 = null,
};

fn mint(app: *App, context: *http.Context, auth: p.users.Auth, input: Create) !void {
    var scopes: u32 = 0;
    if (input.scopes.len > @typeInfo(p.tokens.Scope).@"enum".fields.len)
        return error.InvalidRequest;
    for (input.scopes) |scope| {
        if (scopes & scope.bit() != 0) return error.InvalidRequest;
        scopes |= scope.bit();
    }
    if (!p.tokens.validLabel(input.label) or !p.tokens.validScopes(scopes, input.role))
        return error.InvalidRequest;
    const expires = if (input.expires) |value| try number(value) else null;
    var raw: [32]u8 = undefined;
    var encoded: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw);
    defer std.crypto.secureZero(u8, &encoded);
    app.io.random(&raw);
    encoded = std.fmt.bytesToHex(raw, .lower);
    var digest: [32]u8 = undefined;
    http.digest(&raw, &digest, .{});
    const result = try app.request(.{ .tokens_create = .{
        .auth = auth,
        .label = try p.Bytes(64).init(input.label),
        .role = input.role,
        .scopes = scopes,
        .expires = expires,
        .digest = digest,
    } });
    if (result != .token_saved) return fail(context, result.failed);
    try http.json(context, .{
        .saved = true,
        .id = p.Counter{ .value = result.token_saved },
        .token = @as([]const u8, &encoded),
        .expires = if (expires) |deadline| @as(?p.Counter, .{ .value = deadline }) else null,
    }, &.{});
}

fn number(value: []const u8) error{InvalidRequest}!u64 {
    if (value.len == 0 or value.len > 19) return error.InvalidRequest;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidRequest;
    const number_value = std.fmt.parseInt(u64, value, 10) catch return error.InvalidRequest;
    if (number_value > std.math.maxInt(i64)) return error.InvalidRequest;
    return number_value;
}

fn fail(context: *http.Context, reason: p.Failure) !void {
    const status: std.http.Status = switch (reason) {
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .conflict, .capacity => .conflict,
        .invalid_input => .bad_request,
        else => .service_unavailable,
    };
    const code = switch (reason) {
        .capacity => "CONSOLETOKENFULL",
        .conflict => "CONSOLETOKEN409",
        .forbidden => "CONSOLETOKEN403",
        .unauthorized => "CONSOLE401",
        else => "CONSOLETOKENS",
    };
    return http.fail(context, status, code);
}
