//! Account authentication workflow; borrowed state and outbox live for one browser event.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const field = @import("events_state.zig").field;
const string = @import("events_state.zig").string;
const live = @import("live_controller.zig");

pub const Controller = struct {
    state: *State,
    out: Outbox,

    pub fn action(self: Controller, name: []const u8, fields: std.json.Value) !bool {
        const state = self.state;
        if (equal(name, "recovery-saved")) {
            state.totp_secret = .{};
            state.totp_uri = .{};
            state.recovery_codes = @splat(.{});
            state.recovery_count = 0;
            if (!state.recovery_sign_in) {
                state.recovery_sign_in = true;
                try self.refresh();
                return true;
            }
            state.csrf = .{};
            state.phase = .login;
            return true;
        }
        if (equal(name, "security") and state.csrf.len != 0) {
            state.phase = .security;
            state.message = .{};
            state.totp_secret = .{};
            state.totp_uri = .{};
            state.stats_busy = false;
            try self.refresh();
            return true;
        }
        if (state.phase != .security or state.busy) return false;
        if (equal(name, "totp-recovery") or equal(name, "totp-disable")) {
            state.busy = true;
            state.message = .{};
            const recovery = equal(name, "totp-recovery");
            if (!recovery) try live.signOut(self.out);
            const password = if (recovery) "totp-recovery-password" else "totp-disable-password";
            const code = if (recovery) "totp-recovery-code" else "totp-disable-code";
            try self.out.post(
                name,
                if (recovery) "/console/api/totp/recovery" else "/console/api/totp/disable",
                .{ .password = string(fields, password), .code = string(fields, code) },
            );
            return true;
        }
        if (!equal(name, "totp-enroll") and !equal(name, "totp-confirm")) return false;
        state.busy = true;
        state.message = .{};
        const enroll = equal(name, "totp-enroll");
        if (!enroll) try live.signOut(self.out);
        try self.out.post(
            name,
            if (enroll) "/console/api/totp/enroll" else "/console/api/totp/confirm",
            .{
                .password = string(fields, "password"),
                .code = string(fields, "code"),
                .revision = state.totp_revision,
            },
        );
        return true;
    }

    pub fn refresh(self: Controller) !void {
        const state = self.state;
        state.totp_available = null;
        state.busy = true;
        try self.out.emit(.{
            .op = "request",
            .id = "totp",
            .method = "GET",
            .path = "/console/api/totp",
        });
    }

    pub fn response(self: Controller, id: []const u8, status: i64, body: std.json.Value) !void {
        const state = self.state;
        state.busy = false;
        if (state.phase != .security) return;
        if (status != 200) {
            if (equal(id, "totp-confirm") or equal(id, "totp-disable")) live.authenticated();
            const key = equal(string(body, "error"), "CONSOLE2FAKEY");
            const message = switch (status) {
                429 => "Too many attempts. Wait a minute and try again.",
                409 => if (key)
                    "This node cannot read your authenticator. Use an unused recovery code, " ++
                        "or ask an administrator to reset two-factor."
                else
                    "Two-factor settings changed. Reload this page and try again.",
                else => p.diagnostics.responseHint(
                    std.math.cast(u16, status) orelse 0,
                    string(body, "error"),
                ),
            };
            state.message_success = false;
            try state.message.set(message);
            return;
        }
        if (equal(id, "totp")) {
            const available = field(body, "available") orelse .null;
            const enabled = field(body, "enabled") orelse .null;
            if (available != .bool or enabled != .bool) return error.InvalidResponse;
            state.totp_available = available.bool;
            state.totp_enabled = enabled.bool;
            state.totp_revision = @import("json_value.zig").unsignedOrZero(body, "revision");
        } else if (equal(id, "totp-enroll")) {
            state.totp_secret = try p.Bytes(32).init(string(body, "secret"));
            state.totp_uri = try p.Bytes(134).init(string(body, "uri"));
            state.totp_revision = @import("json_value.zig").unsignedOrZero(body, "revision");
        } else if (equal(id, "totp-disable")) {
            revoked(state, false);
            state.message_success = true;
            try state.message.set("Two-factor authentication is off. Sign in again.");
        } else if (equal(id, "totp-confirm") or equal(id, "totp-recovery")) {
            const codes = field(body, "recovery_codes") orelse return error.InvalidResponse;
            if (codes != .array or codes.array.items.len != 10) return error.InvalidResponse;
            for (codes.array.items, &state.recovery_codes) |code, *dest| {
                if (code != .string or code.string.len != 32) return error.InvalidResponse;
                dest.* = try p.Bytes(32).init(code.string);
            }
            state.recovery_count = 10;
            state.recovery_sign_in = equal(id, "totp-confirm");
            if (!state.recovery_sign_in) return;
            revoked(state, true);
        }
    }
};

/// An expected revocation retains only the confirmation's one-time codes and appearance.
/// No private page, pending observation or prior principal survives to a later sign-in.
fn revoked(state: *State, show_codes: bool) void {
    var codes = state.recovery_codes;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&codes));
    const appearance = state.appearance;
    const username = state.username;
    state.reset();
    state.appearance = appearance;
    state.username = username;
    state.phase = if (show_codes) .security else .login;
    if (show_codes) {
        state.recovery_codes = codes;
        state.recovery_count = 10;
    }
}

fn equal(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

test "confirmation fences revocation callbacks and retains only one-time recovery codes" {
    const t = std.testing;
    const Commands = @import("test_transport.zig").Commands;
    live.init();
    var state: State = .{ .phase = .security, .user_id = 7 };
    try state.csrf.set("prior principal");
    try state.username.set("alice");
    var commands: Commands = .{};
    try live.sync(&state, commands.out());
    const fields = std.json.Value{ .object = .empty };
    const controller: Controller = .{ .state = &state, .out = commands.out() };
    try t.expect(try controller.action("totp-confirm", fields));
    const emitted = commands.writer.buffered();
    const disconnect = std.mem.indexOf(u8, emitted, "disconnect") orelse
        return error.MissingDisconnect;
    try t.expect(disconnect < std.mem.indexOf(u8, emitted, "/totp/confirm").?);
    const rejection = "{\"state\":\"message\",\"body\":{\"error\":\"unauthorized\"}}";
    const revoked_frame = try std.json.parseFromSlice(std.json.Value, t.allocator, rejection, .{});
    defer revoked_frame.deinit();
    _ = try live.event(&state, revoked_frame.value, t.allocator, commands.out());
    try t.expectEqual(.security, state.phase);
    const code: [32]u8 = @splat('a');
    const bytes = try std.json.Stringify.valueAlloc(t.allocator, .{
        .recovery_codes = @as([10][]const u8, @splat(&code)),
    }, .{});
    defer t.allocator.free(bytes);
    const reply = try std.json.parseFromSlice(std.json.Value, t.allocator, bytes, .{});
    defer reply.deinit();
    try controller.response("totp-confirm", 200, reply.value);
    try t.expect(!state.fullAccess());
    try t.expectEqual(@as(u64, 0), state.user_id);
    try t.expectEqual(@as(usize, 10), state.recovery_count);
    try t.expectEqualStrings("alice", state.username.slice());
    try t.expect(try controller.action("recovery-saved", fields));
    try t.expectEqual(.login, state.phase);
    try t.expectEqual(@as(usize, 0), state.recovery_count);
}
