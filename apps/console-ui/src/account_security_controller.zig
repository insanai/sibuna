//! Account authentication workflow; borrowed state and outbox live for one browser event.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const field = @import("events_state.zig").field;
const string = @import("events_state.zig").string;

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
            const key = equal(string(body, "error"), "CONSOLE2FAKEY");
            const message = switch (status) {
                429 => "Too many attempts. Wait a minute and try again.",
                409 => if (key)
                    "This node cannot read your authenticator. Use an unused recovery code, " ++
                        "or ask an administrator to reset two-factor."
                else
                    "Two-factor settings changed. Reload this page and try again.",
                else => "Could not update authentication. Check your password, code and session.",
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
            state.totp_secret = .{};
            state.totp_uri = .{};
            state.csrf = .{};
            state.geometry = null;
            state.stats = null;
            state.phase = .login;
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
            state.totp_secret = .{};
            state.totp_uri = .{};
            state.csrf = .{};
            state.geometry = null;
            state.stats = null;
        }
    }
};

fn equal(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
