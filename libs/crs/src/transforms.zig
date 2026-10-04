//! Initial byte-transform primitives for the C-locale ModSecurity 3.0.14 profile.
//! Unsupported transforms are errors, not identities. Ordered t:none/reset semantics
//! belong to pipeline compilation; the standalone none primitive is byte identity.
const std = @import("std");
const model = @import("model.zig");
const work = @import("work.zig");

pub const Error = error{ UnsupportedTransform, OutputLimit } || work.Error;
pub const Buffer = struct {
    input: []const u8,
    output: []u8,
    budget: *work.Budget,
};

/// All output is caller-owned. Buffers must be disjoint; a transaction uses two
/// reserved buffers to compose a pipeline. Capacity and work are checked before writes.
pub fn apply(kind: model.Transform, buffer: Buffer) Error![]const u8 {
    const maximum = try capacity(kind, buffer.input.len);
    if (buffer.output.len < maximum) return error.OutputLimit;
    const count = std.math.add(u64, @intCast(buffer.input.len), 1) catch
        return error.WorkLimit;
    const cost = if (kind == .hex_encode)
        std.math.add(u64, count, @intCast(buffer.input.len)) catch return error.WorkLimit
    else
        count;
    try buffer.budget.debit(cost);
    assertDisjoint(buffer.input, buffer.output[0..maximum]);
    const length = switch (kind) {
        .none => blk: {
            @memcpy(buffer.output[0..buffer.input.len], buffer.input);
            break :blk buffer.input.len;
        },
        .lowercase => lowercase(buffer),
        .length => decimalLength(buffer),
        .hex_encode => hex(buffer),
        .compress_whitespace => compress(buffer),
        .remove_whitespace, .remove_nulls => remove(kind, buffer),
        else => unreachable,
    };
    return buffer.output[0..length];
}

/// A conservative bound can exceed the eventual output; callers reserve it off-path.
pub fn capacity(kind: model.Transform, length: usize) Error!usize {
    return switch (kind) {
        .none, .lowercase, .compress_whitespace, .remove_whitespace, .remove_nulls => length,
        .hex_encode => std.math.mul(usize, length, 2) catch error.OutputLimit,
        .length => digits(length),
        else => error.UnsupportedTransform,
    };
}

fn assertDisjoint(input: []const u8, output: []u8) void {
    if (input.len == 0 or output.len == 0) return;
    const source = @intFromPtr(input.ptr);
    const destination = @intFromPtr(output.ptr);
    std.debug.assert(source + input.len <= destination or destination + output.len <= source);
}

fn lowercase(buffer: Buffer) usize {
    for (buffer.input, buffer.output[0..buffer.input.len]) |byte, *out| {
        out.* = std.ascii.toLower(byte);
    }
    return buffer.input.len;
}

fn digits(length: usize) usize {
    var remaining = length;
    var result: usize = 1;
    while (remaining >= 10) : (remaining /= 10) result += 1;
    return result;
}

fn decimalLength(buffer: Buffer) usize {
    const length = digits(buffer.input.len);
    var remaining = buffer.input.len;
    var position = length;
    while (position > 0) {
        position -= 1;
        buffer.output[position] = '0' + @as(u8, @intCast(remaining % 10));
        remaining /= 10;
    }
    return length;
}

fn hex(buffer: Buffer) usize {
    const alphabet = "0123456789abcdef";
    for (buffer.input, 0..) |byte, index| {
        buffer.output[index * 2] = alphabet[byte >> 4];
        buffer.output[index * 2 + 1] = alphabet[byte & 15];
    }
    return buffer.input.len * 2;
}

fn compress(buffer: Buffer) usize {
    var written: usize = 0;
    var previous_white = false;
    for (buffer.input) |byte| {
        const white = std.ascii.isWhitespace(byte);
        if (!white or !previous_white) {
            buffer.output[written] = if (white) ' ' else byte;
            written += 1;
        }
        previous_white = white;
    }
    return written;
}

fn remove(kind: model.Transform, buffer: Buffer) usize {
    var written: usize = 0;
    for (buffer.input) |byte| {
        // The pinned removeWhitespace also strips isolated 0xa0 and 0xc2 bytes;
        // replacing that behavior with Unicode whitespace parsing breaks its profile.
        const omit = if (kind == .remove_nulls)
            byte == 0
        else
            std.ascii.isWhitespace(byte) or byte == 0xa0 or byte == 0xc2;
        if (omit) continue;
        buffer.output[written] = byte;
        written += 1;
    }
    return written;
}

test "byte transforms preserve the pinned whitespace and binary semantics" {
    const cases = [_]struct { kind: model.Transform, input: []const u8, output: []const u8 }{
        .{ .kind = .none, .input = "A\x00\xff", .output = "A\x00\xff" },
        .{ .kind = .lowercase, .input = "AZ\x00\xc0", .output = "az\x00\xc0" },
        .{ .kind = .length, .input = "", .output = "0" },
        .{ .kind = .length, .input = "\xc3\xa9", .output = "2" },
        .{ .kind = .hex_encode, .input = "\x00\x0f\xffAB", .output = "000fff4142" },
        .{ .kind = .compress_whitespace, .input = " \tA\r\nB\x0b\x0c ", .output = " A B " },
        .{ .kind = .compress_whitespace, .input = "\xc2\xa0", .output = "\xc2\xa0" },
        .{ .kind = .remove_whitespace, .input = "A\xc2\xa0B \x0b\x00", .output = "AB\x00" },
        .{ .kind = .remove_nulls, .input = "\x00A\x00 B\xff\x00", .output = "A B\xff" },
    };
    var output: [64]u8 = undefined;
    for (cases) |case| {
        var budget: work.Budget = .{ .remaining = 1024 };
        const result = try apply(case.kind, .{
            .input = case.input,
            .output = &output,
            .budget = &budget,
        });
        try std.testing.expectEqualStrings(case.output, result);
    }
}

test "transform bounds and unsupported operations cannot expose partial output" {
    var output: [3]u8 = @splat(0x7f);
    var budget: work.Budget = .{ .remaining = 10 };
    const buffer: Buffer = .{ .input = "AB", .output = &output, .budget = &budget };
    try std.testing.expectError(error.OutputLimit, apply(.hex_encode, buffer));
    try std.testing.expectError(error.UnsupportedTransform, apply(.js_decode, buffer));
    try std.testing.expectEqual(@as(u64, 10), budget.remaining);
    budget.remaining = 0;
    try std.testing.expectError(error.WorkLimit, apply(.lowercase, buffer));
    try std.testing.expectEqualSlices(u8, &.{ 0x7f, 0x7f, 0x7f }, &output);
    try std.testing.expectError(
        error.OutputLimit,
        capacity(.hex_encode, std.math.maxInt(usize)),
    );
}
