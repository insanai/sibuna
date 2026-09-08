//! Immutable terminal-rule configuration. Mutable GCRA cells remain node-local in store.
const std = @import("std");

pub const Limits = struct {
    rate: u32,
    window_seconds: u32,
    /// Zero returns 429 only; a positive duration additionally bans the address on this node.
    ban_seconds: u32 = 0,

    pub fn validate(self: Limits) error{InvalidRuleLimit}!void {
        if (self.rate == 0 or self.rate > 1_000_000 or self.window_seconds == 0 or
            self.window_seconds > 86400 or self.ban_seconds > 86400)
            return error.InvalidRuleLimit;
    }

    /// Settings changes create a new bucket scope; unrelated revisions do not. Fixed-width
    /// fields avoid ambiguous concatenation. The store uses the existing bounded hash table.
    pub fn scope(self: Limits, identity: u64) u64 {
        var bytes: [20]u8 = undefined;
        std.mem.writeInt(u64, bytes[0..8], identity, .little);
        std.mem.writeInt(u32, bytes[8..12], self.rate, .little);
        std.mem.writeInt(u32, bytes[12..16], self.window_seconds, .little);
        std.mem.writeInt(u32, bytes[16..20], self.ban_seconds, .little);
        return std.hash.Wyhash.hash(0x7275_6c65_2d67_6372, &bytes);
    }
};

pub fn managedIdentity(id: []const u8) u64 {
    const value = std.hash.Wyhash.hash(0x6d61_6e61_6765_642d, id);
    return if (value == 0) 1 else value;
}

pub fn fileIdentity(name: []const u8, index: usize) u64 {
    return std.hash.Wyhash.hash(0x6669_6c65_2d72_756c ^ index, name);
}

test "rule limit scopes separate identities and settings while remaining revision-independent" {
    const t = std.testing;
    const limits: Limits = .{ .rate = 2, .window_seconds = 60 };
    try limits.validate();
    try t.expect(limits.scope(managedIdentity("a")) != limits.scope(managedIdentity("b")));
    const changed: Limits = .{ .rate = 3, .window_seconds = 60 };
    try t.expect(limits.scope(7) != changed.scope(7));
    try t.expectError(
        error.InvalidRuleLimit,
        (Limits{ .rate = 0, .window_seconds = 1 }).validate(),
    );
    try t.expectError(
        error.InvalidRuleLimit,
        (Limits{ .rate = 1, .window_seconds = 0 }).validate(),
    );
}
