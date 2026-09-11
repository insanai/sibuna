const std = @import("std");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const http = @import("http.zig");
const origin = @import("origin.zig");
pub const Kind = enum { query, create, change };

pub fn dispatch(
    app: *App,
    context: *http.Context,
    principal: p.Principal,
    route: @import("routes.zig").Handler,
) !void {
    return handle(app, context, principal, switch (route) {
        .users_query => .query,
        .users_create => .create,
        .users_change => .change,
        else => unreachable,
    });
}

pub fn handle(app: *App, context: *http.Context, principal: p.Principal, kind: Kind) !void {
    const digest = try http.session(context);
    if (kind == .query and !app.query_budget.allow(app.io, digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLEQUERY");
    const auth = try origin.authority(app, context, principal);
    var body: [2048]u8 = undefined;
    var memory: [8192]u8 = undefined;
    defer std.crypto.secureZero(u8, &body);
    defer std.crypto.secureZero(u8, &memory);
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    if (kind == .query) {
        const parsed = try http.parse(struct {
            after: ?[]const u8 = null,
            limit: u8 = p.users.page_rows,
        }, context, &body, fixed.allocator());
        defer parsed.deinit();
        const result = try app.request(.{ .users_query = .{
            .auth = auth,
            .after = if (parsed.value.after) |value| try number(value) else 0,
            .limit = parsed.value.limit,
        } });
        if (result != .users_page) return fail(context, result.failed);
        return http.json(context, result.users_page, &.{});
    }
    var operation: p.StorageRequest = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&operation));
    if (kind == .create) {
        const parsed = try http.parse(struct {
            username: []const u8,
            role: p.Role = .viewer,
        }, context, &body, fixed.allocator());
        defer parsed.deinit();
        if (!p.validUsername(parsed.value.username)) return error.InvalidRequest;
        operation = .{ .users_create = .{
            .auth = auth,
            .username = try p.Bytes(64).init(parsed.value.username),
            .role = parsed.value.role,
            .password_hash = .{},
        } };
    } else {
        const parsed = try http.parse(Change, context, &body, fixed.allocator());
        defer parsed.deinit();
        operation = .{ .users_change = try change(auth, parsed.value) };
    }
    try submit(app, context, &operation);
}

const Change = struct {
    target: []const u8,
    expected_revision: []const u8,
    operation: enum { access, password, revoke },
    role: ?p.Role = null,
    disabled: ?bool = null,
};

fn change(auth: p.users.Auth, input: Change) !p.users.Change {
    if (input.operation != .access and (input.role != null or input.disabled != null))
        return error.InvalidRequest;
    return .{
        .auth = auth,
        .target = try number(input.target),
        .expected_revision = try number(input.expected_revision),
        .operation = switch (input.operation) {
            .access => .{ .access = .{
                .role = input.role orelse return error.InvalidRequest,
                .disabled = input.disabled orelse return error.InvalidRequest,
            } },
            .password => .{ .password = .{} },
            .revoke => .revoke,
        },
    };
}

fn submit(app: *App, context: *http.Context, operation: *p.StorageRequest) !void {
    const mint = operation.* == .users_create or operation.users_change.operation == .password;
    var password: [64]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &password);
    if (mint) {
        var random: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &random);
        app.io.random(&random);
        password = std.fmt.bytesToHex(random, .lower);
        const hash = try app.passwords.hash(app.io, &password);
        if (operation.* == .users_create)
            operation.users_create.password_hash = hash
        else
            operation.users_change.operation.password = hash;
    }
    const result = try app.request(operation.*);
    if (result != .users_saved) return fail(context, result.failed);
    var expires: [20]u8 = undefined;
    try http.json(context, .{
        .saved = true,
        .temporary_password = if (mint) @as(?[]const u8, &password) else null,
        .password_expires = try std.fmt.bufPrint(&expires, "{d}", .{result.users_saved}),
    }, &.{});
}

fn number(value: []const u8) error{InvalidRequest}!u64 {
    if (value.len == 0 or value.len > 19) return error.InvalidRequest;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidRequest;
    return std.fmt.parseInt(u64, value, 10) catch error.InvalidRequest;
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
        .capacity => "CONSOLEUSERFULL",
        .conflict => "CONSOLEUSER409",
        .forbidden => "CONSOLEUSER403",
        .unauthorized => "CONSOLE401",
        else => "CONSOLEUSERS",
    };
    return http.fail(context, status, code);
}
