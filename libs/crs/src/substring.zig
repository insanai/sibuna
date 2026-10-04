//! Case-sensitive, length-aware KMP search for literal operators and dynamic macros.
//! Prefix storage is supplied by the caller; static programs prepare it off-path and
//! dynamic arguments reuse transaction scratch. No allocation occurs during matching.
const std = @import("std");
const work = @import("work.zig");

pub const Error = error{ScratchLimit} || work.Error;

pub const Pattern = struct {
    bytes: []const u8,
    prefixes: []const usize,

    /// On mismatch the prefix length strictly decreases. Successful comparisons
    /// increase it at most once per byte, bounding comparisons by twice input length.
    pub fn find(self: Pattern, input: []const u8, budget: *work.Budget) Error!?usize {
        std.debug.assert(self.bytes.len == self.prefixes.len);
        try budget.debit(1);
        if (self.bytes.len == 0) return 0;
        if (self.bytes.len > input.len) return null;
        var matched: usize = 0;
        for (input, 0..) |byte, position| {
            matched = try self.advance(matched, byte, budget);
            if (matched == self.bytes.len) return position + 1 - matched;
        }
        return null;
    }

    fn advance(self: Pattern, previous: usize, byte: u8, budget: *work.Budget) Error!usize {
        var matched = previous;
        std.debug.assert(matched < self.bytes.len);
        while (true) {
            try budget.debit(1);
            if (byte == self.bytes[matched]) return matched + 1;
            if (matched == 0) return 0;
            matched = self.prefixes[matched - 1];
        }
    }
};

/// The result borrows both the needle and prefix storage. A partially prepared table
/// cannot escape after work exhaustion, and subsequent prepares overwrite its entries.
pub fn prepare(bytes: []const u8, storage: []usize, budget: *work.Budget) Error!Pattern {
    if (storage.len < bytes.len) return error.ScratchLimit;
    try budget.debit(1);
    const prefixes = storage[0..bytes.len];
    if (bytes.len == 0) return .{ .bytes = bytes, .prefixes = prefixes };
    const pattern: Pattern = .{ .bytes = bytes, .prefixes = prefixes };
    prefixes[0] = 0;
    var matched: usize = 0;
    for (bytes[1..], 1..) |byte, position| {
        matched = try pattern.advance(matched, byte, budget);
        prefixes[position] = matched;
    }
    return pattern;
}

test "literal search agrees with independent byte search on overlapping and binary inputs" {
    var random: std.Random.DefaultPrng = .init(0xc450);
    const rng = random.random();
    var needle: [16]u8 = undefined;
    var input: [64]u8 = undefined;
    var prefixes: [16]usize = undefined;
    const alphabet = "aAbB\x00\xff";
    for (0..2000) |_| {
        const needle_len = rng.intRangeAtMost(usize, 0, needle.len);
        const input_len = rng.intRangeAtMost(usize, 0, input.len);
        for (needle[0..needle_len]) |*byte| byte.* = alphabet[
            rng.uintLessThan(usize, alphabet.len)
        ];
        for (input[0..input_len]) |*byte| byte.* = alphabet[
            rng.uintLessThan(usize, alphabet.len)
        ];
        var budget: work.Budget = .{ .remaining = 4096 };
        const pattern = try prepare(needle[0..needle_len], &prefixes, &budget);
        try std.testing.expectEqual(
            std.mem.indexOf(u8, input[0..input_len], needle[0..needle_len]),
            try pattern.find(input[0..input_len], &budget),
        );
    }
}

test "adversarial literal fallback consumes linear charged work" {
    var needle: [65]u8 = @splat('a');
    needle[needle.len - 1] = 'b';
    const input: [512]u8 = @splat('a');
    var prefixes: [65]usize = undefined;
    const limit = 2 * (needle.len + input.len) + 2;
    var budget: work.Budget = .{ .remaining = limit };
    const pattern = try prepare(&needle, &prefixes, &budget);
    try std.testing.expectEqual(@as(?usize, null), try pattern.find(&input, &budget));
    try std.testing.expect(budget.remaining > 0);
    budget.remaining = 0;
    try std.testing.expectError(error.WorkLimit, pattern.find(&input, &budget));
    try std.testing.expectError(error.WorkLimit, prepare(&needle, &prefixes, &budget));
    try std.testing.expectError(error.ScratchLimit, prepare(&needle, prefixes[0..1], &budget));
}
