//! Native account commands use an ephemeral authenticated session against the running
//! console. Expected revisions remain explicit; transport loss never implies rollback.
const std = @import("std");
const p = @import("console").protocol;
const arguments = @import("console_command_args.zig");
const client = @import("console_client.zig");
const Writer = std.Io.Writer;
const sessions = @import("console_session.zig");
pub const Error = sessions.Error || error{ImportFailed};

pub fn execute(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) u8 {
    const args = arguments.parse(argv) catch |err| {
        std.debug.print("CONSOLECLI002: invalid management command ({t}). " ++
            "Hint: use sibuna --help for management commands and required options.\n", .{err});
        return 1;
    };
    var buffer: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    var output = std.Io.File.stdout().writer(io, &buffer);
    run(allocator, io, args, &output.interface) catch |err| {
        diagnose(err);
        return 1;
    };
    output.interface.flush() catch {
        std.debug.print(
            "CONSOLECLIWRITE: output was not delivered. " ++
                "Hint: query current state; reset a temporary password " ++
                "or revoke an undisclosed token if needed.\n",
            .{},
        );
        return 1;
    };
    return 0;
}

fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    args: arguments.Args,
    writer: *Writer,
) Error!void {
    var session = try client.Session.init(allocator, io, args.origin);
    defer session.deinit();
    defer sessions.close(&session);
    if (args.token_file) |path| {
        try @import("console_command_token.zig").authenticate(&session, path);
    } else {
        const role = try sessions.login(&session, .{
            .username = args.actor,
            .password_file = args.password_file,
            .factor_file = args.factor_file,
        });
        try authorize(args.kind, role);
    }
    if (args.kind.managesTokens())
        return @import("console_command_token.zig").run(&session, args, writer);
    if (args.kind == .geo_status or args.kind == .geo_update)
        return @import("console_command_geo.zig").run(&session, args, writer);
    if (args.kind == .policies_export or args.kind == .policies_import)
        return @import("console_command_policies.zig").run(&session, args, writer);
    var payload: [2048]u8 = undefined;
    defer std.crypto.secureZero(u8, &payload);
    var body: Writer = .fixed(&payload);
    const endpoint = try operation(args, &body);
    var response: [client.max_response + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &response);
    const reply = try session.request(endpoint, body.buffer[0..body.end], &response);
    try requireOk(reply.status);
    const bytes = response[0..reply.length];
    try @import("console_command_reply.zig").validate(args, bytes);
    // Preserve the API's decimal strings for large counters instead of coercing them
    // through another JSON implementation. Validation permits only the known contract.
    try writer.writeAll(bytes);
    try writer.writeByte('\n');
}

fn authorize(kind: arguments.Kind, role: p.Role) Error!void {
    const read_only = kind == .users or kind == .geo_status or kind == .policies_export;
    const operator_ok = kind == .policies_import and role == .operator;
    if (!read_only and !operator_ok and role != .admin) return error.Forbidden;
}

fn operation(args: arguments.Args, writer: *Writer) Error!client.Endpoint {
    if (args.kind == .add) {
        try std.json.Stringify.value(.{
            .username = args.username,
            .role = args.role,
        }, .{}, writer);
        return .users_create;
    }
    var target: [20]u8 = undefined;
    const id = std.fmt.bufPrint(&target, "{d}", .{
        if (args.kind == .users) args.after else args.target,
    }) catch unreachable;
    if (args.kind == .users) {
        try std.json.Stringify.value(.{ .after = id }, .{}, writer);
        return .users_query;
    }
    var revision_buffer: [20]u8 = undefined;
    const revision = std.fmt.bufPrint(&revision_buffer, "{d}", .{args.revision}) catch unreachable;
    try std.json.Stringify.value(.{
        .target = id,
        .expected_revision = revision,
        .operation = @tagName(args.kind),
        .role = if (args.kind == .access) args.role else @as(?p.Role, null),
        .disabled = if (args.kind == .access) args.disabled else @as(?bool, null),
    }, .{}, writer);
    return .users_change;
}

pub const requireOk = sessions.requireOk;

fn diagnose(err: Error) void {
    const unknown = "Outcome unknown. Query the affected resource before retrying.";
    const hint = switch (err) {
        error.Transport, error.Deadline, error.Unavailable => unknown,
        error.InvalidResponse, error.ResponseTooLarge => unknown,
        error.Canceled, error.OutOfMemory => unknown,
        error.Conflict => "Refresh the resource: capacity or the expected revision conflicted.",
        error.ImportFailed => "Inspect GeoIP status and daemon diagnostics before retrying.",
        error.Forbidden => "Check role and scope; token management requires administrator login.",
        error.Unauthorized => "Check credential expiry, revocation, password and second factor.",
        error.PasswordChangeRequired => "Change the temporary password in the browser first.",
        error.FactorEnrollmentRequired => "Complete required two-factor enrollment in Account.",
        error.RateLimited => "Wait a minute before another login or management operation.",
        error.CredentialPermissions => "Restrict credential files to their owner " ++
            "(POSIX mode 600 or a private Windows ACL).",
        error.CredentialFile, error.InvalidCredential => "Use private regular credential files.",
        error.InvalidOrigin, error.InsecureOrigin => "Use HTTPS or literal loopback HTTP.",
        else => "Check origin, input bounds and server compatibility before retrying.",
    };
    std.debug.print("CONSOLECLI: management command failed ({t}). Hint: {s}\n", .{ err, hint });
}

test {
    _ = @import("console_command_args.zig");
    _ = @import("console_client.zig");
    _ = @import("console_command_reply.zig");
    _ = @import("console_command_geo.zig");
    _ = @import("console_command_token.zig");
}
