//! Operator page templates: bounded HTML with a fixed placeholder set. The owner validates
//! a template before staging it; the request path renders segments from the snapshot.
//! Template bytes travel in a heap block owned by whoever holds the envelope (the mailbox
//! between submission and completion), so the storage unions stay small.
const std = @import("std");
const p = @import("root.zig");
pub const Kind = enum { challenge, denied, rate_limited, banned, overloaded };
pub const max_bytes = 16 * 1024;
pub const Html = struct {
    bytes: [max_bytes]u8 = undefined,
    len: u16 = 0,

    pub fn slice(self: *const Html) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn set(self: *Html, text: []const u8) error{TooLarge}!void {
        if (text.len > max_bytes) return error.TooLarge;
        @memcpy(self.bytes[0..text.len], text);
        self.len = @intCast(text.len);
    }
};
pub const Read = struct { auth: p.users.Auth, kind: Kind };
/// `html` is present exactly when `reset` is false; ownership passes to the mailbox.
pub const Edit = struct {
    auth: p.users.Auth,
    kind: Kind,
    expected_revision: u64,
    reset: bool = false,
    html: ?*Html = null,
};
/// `html` is owned by the receiver of the result.
pub const Document = struct {
    kind: Kind,
    revision: u64,
    customized: bool,
    sha256: p.Bytes(64),
    html: *Html,
};

pub fn validateEdit(input: Edit) error{InvalidLimit}!void {
    if (input.expected_revision >= std.math.maxInt(i64)) return error.InvalidLimit;
    if (input.reset != (input.html == null)) return error.InvalidLimit;
    if (input.html) |html| if (html.len == 0 or html.len > max_bytes) return error.InvalidLimit;
}
