//! Strict byte decoding shared by URI metadata and form acquisition. No Unicode
//! reinterpretation; decoded NULs remain ordinary length-delimited bytes.
const std = @import("std");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Error = work.Error || error{ InvalidPercentEscape, DecodedValueLimit };

/// Validate and size before writing. Malformed escapes are explicit errors rather
/// than a silently complete body; the connector applies its declared failure policy.
pub fn decode(
    input: []const u8,
    output: []u8,
    plus_as_space: bool,
    budget: *work.Budget,
) Error![]const u8 {
    const visits = std.math.mul(u64, input.len, 4) catch return error.WorkLimit;
    try budget.debit(std.math.add(u64, visits, 1) catch return error.WorkLimit);
    var length: usize = 0;
    var index: usize = 0;
    while (index < input.len) : (length += 1) {
        if (input[index] == '%') {
            if (input.len - index < 3 or hex(input[index + 1]) == null or
                hex(input[index + 2]) == null) return error.InvalidPercentEscape;
            index += 3;
        } else index += 1;
    }
    if (length > output.len) return error.DecodedValueLimit;
    buffers.assertDisjoint(input, output[0..length]);
    index = 0;
    for (output[0..length]) |*byte| {
        const first = input[index];
        if (first == '%') {
            byte.* = hex(input[index + 1]).? * 16 + hex(input[index + 2]).?;
            index += 3;
        } else {
            byte.* = if (plus_as_space and first == '+') ' ' else first;
            index += 1;
        }
    }
    return output[0..length];
}

fn hex(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

test "decoding handles binary values and URI plus without writes on refusal" {
    var budget: work.Budget = .{ .remaining = 10000 };
    var output: [8]u8 = @splat('!');
    try std.testing.expectEqualSlices(u8, &.{ 'a', 0, ' ', 'b' }, try decode(
        "a%00+b",
        &output,
        true,
        &budget,
    ));
    try std.testing.expectEqualStrings("a+b", try decode("a+b", &output, false, &budget));
    @memset(&output, '!');
    for ([_][]const u8{ "%", "%2", "%zz", "a%0g" }) |bad| {
        try std.testing.expectError(
            error.InvalidPercentEscape,
            decode(bad, &output, true, &budget),
        );
        try std.testing.expectEqualSlices(u8, &(@as([8]u8, @splat('!'))), &output);
    }
    try std.testing.expectError(
        error.DecodedValueLimit,
        decode("123456789", &output, true, &budget),
    );
    budget.remaining = 0;
    try std.testing.expectError(error.WorkLimit, decode("x", &output, true, &budget));
    try std.testing.expectEqualSlices(u8, &(@as([8]u8, @splat('!'))), &output);
}
