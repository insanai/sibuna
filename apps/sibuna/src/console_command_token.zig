//! Token commands require a browser-kind administrator login. Automation credentials can
//! call other commands, but cannot mint, catalog or revoke token authority.
const std = @import("std");
const p = @import("console").protocol;
const client = @import("console_client.zig");
const command = @import("console_command.zig");
const Args = @import("console_command_args.zig").Args;
const Writer = std.Io.Writer;

pub fn authenticate(session: *client.Session, path: []const u8) client.Error!void {
    var buffer: [67]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    const value = try client.readSecret(session.io, path, &buffer);
    if (value.len != 64) return error.InvalidCredential;
    for (value) |byte| if (!std.ascii.isHex(byte)) return error.InvalidCredential;
    std.debug.assert(session.cookie.len == 0 and session.csrf.len == 0);
    @memcpy(session.bearer.data[0..7], "Bearer ");
    @memcpy(session.bearer.data[7..71], value);
    session.bearer.len = 71;
}

pub fn run(session: *client.Session, args: Args, writer: *Writer) command.Error!void {
    std.debug.assert(args.kind.managesTokens() and session.bearer.len == 0);
    var payload: [2048]u8 = undefined;
    var response: [client.max_response + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &payload);
    defer std.crypto.secureZero(u8, &response);
    var body: Writer = .fixed(&payload);
    const endpoint = try operation(args, &body);
    const reply = try session.request(endpoint, body.buffer[0..body.end], &response);
    try command.requireOk(reply.status);
    const bytes = response[0..reply.length];
    try @import("console_command_token_reply.zig").validate(args, bytes);
    try writer.writeAll(bytes);
    try writer.writeByte('\n');
}

fn operation(args: Args, writer: *Writer) command.Error!client.Endpoint {
    var number_buffer: [20]u8 = undefined;
    if (args.kind == .mint_token) {
        var selected: [8]p.tokens.Scope = undefined;
        var count: usize = 0;
        inline for (@typeInfo(p.tokens.Scope).@"enum".field_names) |field_name| {
            const scope: p.tokens.Scope = @field(p.tokens.Scope, field_name);
            if (args.scopes & scope.bit() != 0) {
                selected[count] = scope;
                count += 1;
            }
        }
        const expires: ?[]const u8 = if (args.expires) |value|
            std.fmt.bufPrint(&number_buffer, "{d}", .{value}) catch unreachable
        else
            null;
        try std.json.Stringify.value(.{
            .label = args.username,
            .role = args.role,
            .scopes = selected[0..count],
            .expires = expires,
        }, .{}, writer);
        return .tokens_create;
    }
    if (args.kind == .tokens) {
        try std.json.Stringify.value(.{
            .after = std.fmt.bufPrint(&number_buffer, "{d}", .{args.after}) catch unreachable,
        }, .{}, writer);
        return .tokens_query;
    }
    var revision_buffer: [20]u8 = undefined;
    try std.json.Stringify.value(.{
        .target = std.fmt.bufPrint(&number_buffer, "{d}", .{args.target}) catch unreachable,
        .expected_revision = std.fmt.bufPrint(&revision_buffer, "{d}", .{args.revision}) catch
            unreachable,
        .remove = args.kind == .remove_token,
    }, .{}, writer);
    return .tokens_revoke;
}

test {
    _ = @import("console_command_token_reply.zig");
}
