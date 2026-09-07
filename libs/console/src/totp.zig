//! RFC 6238 / RFC 4226, HMAC-SHA1, six digits, 30-second steps. The storage owner must
//! atomically consume the returned step with session creation; checking alone is not login.
const std = @import("std");
pub const Seed = [20]u8;
pub const Code = [6]u8;
const Hmac = std.crypto.auth.hmac.HmacSha1;

fn truncated(seed: Seed, step: u64) u32 {
    var counter: [8]u8 = undefined;
    std.mem.writeInt(u64, &counter, step, .big);
    var mac: [20]u8 = undefined;
    defer std.crypto.secureZero(u8, &mac);
    Hmac.create(&mac, &counter, &seed);
    const offset: usize = mac[19] & 15;
    return std.mem.readInt(u32, mac[offset..][0..4], .big) & 0x7fffffff;
}

pub fn code(seed: Seed, step: u64) Code {
    var number = truncated(seed, step) % 1_000_000;
    var output: Code = undefined;
    for (0..output.len) |index| {
        output[output.len - 1 - index] = @as(u8, @intCast(number % 10)) + '0';
        number /= 10;
    }
    return output;
}

/// Accept one step of clock skew, never an already consumed or older step. Evaluate
/// all three candidates even after a match. A collision consumes the newest matching step.
pub fn verify(seed: Seed, input: []const u8, now: u64, last: ?u64) error{InvalidCode}!u64 {
    if (input.len != 6) return error.InvalidCode;
    for (input) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidCode;
    const current = now / 30;
    var accepted: ?u64 = null;
    for ([_]u64{ current -| 1, current, current + 1 }) |step| {
        const expected = code(seed, step);
        const matches = std.crypto.timing_safe.eql(Code, expected, input[0..6].*);
        if (matches and (last == null or step > last.?)) accepted = step;
    }
    return accepted orelse error.InvalidCode;
}

/// 160 bits encode to exactly 32 RFC 4648 characters, with no padding.
pub fn base32(seed: Seed) [32]u8 {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    var output: [32]u8 = undefined;
    for (&output, 0..) |*byte, index| {
        var value: u5 = 0;
        for (0..5) |bit| {
            const position = index * 5 + bit;
            value = (value << 1) | @as(u5, @intCast(
                (seed[position / 8] >> @as(u3, @intCast(7 - position % 8))) & 1,
            ));
        }
        byte.* = alphabet[value];
    }
    return output;
}

test "RFC 4226 counter vectors and RFC 6238 SHA1 time vectors" {
    const t = std.testing;
    const seed: Seed = "12345678901234567890".*;
    const values = [_][]const u8{
        "755224", "287082", "359152", "969429", "338314",
        "254676", "287922", "162583", "399871", "520489",
    };
    for (values, 0..) |expected, step| try t.expectEqualStrings(expected, &code(seed, step));
    const times = [_]u64{ 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000 };
    const expected = [_]u32{ 94287082, 7081804, 14050471, 89005924, 69279037, 65353130 };
    for (times, expected) |time, value| {
        try t.expectEqual(value, truncated(seed, time / 30) % 100_000_000);
    }
    try t.expectEqualStrings("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", &base32(seed));
}

test "verification bounds clock skew and refuses consumed steps and malformed codes" {
    const t = std.testing;
    const seed: Seed = "12345678901234567890".*;
    const current = code(seed, 100);
    try t.expectEqual(100, try verify(seed, &current, 3000, null));
    try t.expectEqual(100, try verify(seed, &current, 3030, 99));
    try t.expectEqual(100, try verify(seed, &current, 2970, 99));
    try t.expectError(error.InvalidCode, verify(seed, &current, 3060, null));
    try t.expectError(error.InvalidCode, verify(seed, &current, 3000, 100));
    try t.expectError(error.InvalidCode, verify(seed, "+12345", 3000, null));
    try t.expectError(error.InvalidCode, verify(seed, "1234567", 3000, null));
    try t.expectEqual(0, try verify(seed, &code(seed, 0), 0, null));
}
