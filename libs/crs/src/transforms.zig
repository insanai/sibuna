//! Initial byte-transform primitives for the C-locale ModSecurity 3.0.14 profile.
//! Unsupported transforms are errors, not identities. Ordered t:none/reset semantics
//! belong to pipeline compilation; the standalone none primitive is byte identity.
const std = @import("std");
const model = @import("model.zig");
const work = @import("work.zig");
const types = @import("transform_types.zig");
const scan = @import("transform_scan.zig");
const escapes = @import("transform_escape.zig");
const entity = @import("transform_entity.zig");
const base64 = @import("transform_base64.zig");

pub const Error = types.Error;
pub const Buffer = types.Buffer;
pub const Result = types.Result;
const Write = types.Write;

/// All output is caller-owned. Buffers must be disjoint; a transaction uses two
/// reserved buffers to compose a pipeline. Capacity and work are checked before writes.
pub fn apply(kind: model.Transform, buffer: Buffer) Error![]const u8 {
    return (try step(kind, buffer)).bytes;
}

/// multiMatch consumes the reference's change flag, which is not always byte inequality.
pub fn step(kind: model.Transform, buffer: Buffer) Error!Result {
    const maximum = try capacity(kind, buffer.input.len);
    if (buffer.output.len < maximum) return error.OutputLimit;
    try buffer.budget.debit(try cost(kind, buffer.input.len));
    assertDisjoint(buffer.input, buffer.output[0..maximum]);
    const result: Write = switch (kind) {
        .none => blk: {
            @memcpy(buffer.output[0..buffer.input.len], buffer.input);
            break :blk .{ .length = buffer.input.len, .changed = false };
        },
        .lowercase => lowercase(buffer),
        .length => .{ .length = decimalLength(buffer), .changed = true },
        .hex_encode => .{ .length = hex(buffer), .changed = buffer.input.len != 0 },
        .escape_seq_decode => scan.escapeSequence(buffer),
        .cmd_line => scan.commandLine(buffer),
        .remove_comments_char => scan.removeCommentMarkers(buffer),
        .replace_comments => scan.replaceComments(buffer),
        .sha1 => scan.sha1(buffer),
        .css_decode, .js_decode, .url_decode_uni => escapes.decode(kind, buffer),
        .html_entity_decode => entity.decode(buffer),
        .base64_decode => base64.decode(buffer),
        .compress_whitespace, .remove_whitespace, .remove_nulls => blk: {
            const length = if (kind == .compress_whitespace)
                compress(buffer)
            else
                remove(kind, buffer);
            break :blk .{ .length = length, .changed = length != buffer.input.len };
        },
        else => unreachable,
    };
    return .{ .bytes = buffer.output[0..result.length], .changed = result.changed };
}

/// A conservative bound can exceed the eventual output; callers reserve it off-path.
pub fn capacity(kind: model.Transform, length: usize) Error!usize {
    return switch (kind) {
        .none,
        .lowercase,
        .compress_whitespace,
        .remove_whitespace,
        .remove_nulls,
        .escape_seq_decode,
        .cmd_line,
        .remove_comments_char,
        .replace_comments,
        .css_decode,
        .js_decode,
        .url_decode_uni,
        .html_entity_decode,
        .base64_decode,
        => length,
        .hex_encode => std.math.mul(usize, length, 2) catch error.OutputLimit,
        .length => digits(length),
        .sha1 => 20,
        else => error.UnsupportedTransform,
    };
}

fn cost(kind: model.Transform, length: usize) work.Error!u64 {
    const count: u64 = @intCast(length);
    const factor: u64 = switch (kind) {
        .hex_encode => 2,
        .escape_seq_decode, .cmd_line, .replace_comments, .base64_decode => 8,
        .remove_comments_char, .html_entity_decode => 32,
        .css_decode, .js_decode, .url_decode_uni => 16,
        else => 1,
    };
    var charged = std.math.mul(u64, count, factor) catch return error.WorkLimit;
    if (kind == .sha1) {
        const blocks = count / 64 + @as(u64, if (count % 64 >= 56) 2 else 1);
        const rounds = std.math.mul(u64, blocks, 80) catch return error.WorkLimit;
        charged = std.math.add(u64, charged, rounds) catch return error.WorkLimit;
    }
    return std.math.add(u64, charged, 1) catch error.WorkLimit;
}

fn assertDisjoint(input: []const u8, output: []u8) void {
    if (input.len == 0 or output.len == 0) return;
    const source = @intFromPtr(input.ptr);
    const destination = @intFromPtr(output.ptr);
    std.debug.assert(source + input.len <= destination or destination + output.len <= source);
}

fn lowercase(buffer: Buffer) Write {
    var changed = false;
    for (buffer.input, buffer.output[0..buffer.input.len]) |byte, *out| {
        out.* = std.ascii.toLower(byte);
        changed = changed or out.* != byte;
    }
    return .{ .length = buffer.input.len, .changed = changed };
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
    try std.testing.expectError(error.UnsupportedTransform, apply(.normalize_path, buffer));
    try std.testing.expectEqual(@as(u64, 10), budget.remaining);
    budget.remaining = 0;
    try std.testing.expectError(error.WorkLimit, apply(.lowercase, buffer));
    try std.testing.expectEqualSlices(u8, &.{ 0x7f, 0x7f, 0x7f }, &output);
    try std.testing.expectError(
        error.OutputLimit,
        capacity(.hex_encode, std.math.maxInt(usize)),
    );
}

test "change flags retain reference behavior even when byte inequality disagrees" {
    var output: [8]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 128 };
    const space = try step(.compress_whitespace, .{
        .input = "\t",
        .output = &output,
        .budget = &budget,
    });
    try std.testing.expectEqualStrings(" ", space.bytes);
    try std.testing.expect(!space.changed);
    const length = try step(.length, .{
        .input = "1",
        .output = &output,
        .budget = &budget,
    });
    try std.testing.expectEqualStrings("1", length.bytes);
    try std.testing.expect(length.changed);
    const command = try step(.cmd_line, .{
        .input = "AB",
        .output = &output,
        .budget = &budget,
    });
    try std.testing.expectEqualStrings("ab", command.bytes);
    try std.testing.expect(!command.changed);
}

test "bounded scans preserve binary escapes and distinguish comment operations" {
    const cases = [_]struct { kind: model.Transform, input: []const u8, output: []const u8 }{
        .{ .kind = .escape_seq_decode, .input = "\\x00\\777\\q\\xF\\", .output = "\x00\xffqxF\\" },
        .{ .kind = .cmd_line, .input = " 'A'^ ;\\ /B", .output = " a/b" },
        .{ .kind = .remove_comments_char, .input = "A/*x*/<!--B-->--#", .output = "AxB" },
        .{ .kind = .replace_comments, .input = "A/*x*/B/*", .output = "A B " },
        .{ .kind = .replace_comments, .input = "A\x00B/**/C", .output = "A\x00B C" },
    };
    var output: [64]u8 = undefined;
    for (cases) |case| {
        var budget: work.Budget = .{ .remaining = 4096 };
        const result = try step(case.kind, .{
            .input = case.input,
            .output = &output,
            .budget = &budget,
        });
        try std.testing.expectEqualStrings(case.output, result.bytes);
        try std.testing.expect(result.changed);
    }
}

test "scan and digest work refusal preserves output before any write" {
    var output: [32]u8 = @splat(0x7f);
    var budget: work.Budget = .{ .remaining = 80 };
    const buffer: Buffer = .{ .input = "", .output = &output, .budget = &budget };
    try std.testing.expectError(error.WorkLimit, step(.sha1, buffer));
    try std.testing.expectEqual(@as(u64, 80), budget.remaining);
    for (output) |byte| try std.testing.expectEqual(@as(u8, 0x7f), byte);
    try std.testing.expectError(
        error.WorkLimit,
        cost(.remove_comments_char, std.math.maxInt(usize)),
    );
    try std.testing.expectEqual(@as(u64, 217), try cost(.sha1, 56));
}

test "CSS JavaScript and URL decoders preserve distinct byte and change semantics" {
    const cases = [_]struct {
        kind: model.Transform,
        input: []const u8,
        output: []const u8,
        changed: bool = true,
    }{
        .{ .kind = .css_decode, .input = "\\000041 \\ff01\\\n\\", .output = "A!" },
        .{ .kind = .css_decode, .input = "\\z", .output = "z", .changed = false },
        .{ .kind = .css_decode, .input = "\\41\r\nB", .output = "A\nB" },
        .{ .kind = .js_decode, .input = "\\uFF01\\777\\x00\\q\\", .output = "!?7\x00q\\" },
        .{ .kind = .js_decode, .input = "\\u12g4\\xF", .output = "u12g4xF" },
        .{ .kind = .url_decode_uni, .input = "%uFF01+%00%u0041", .output = "! \x00A" },
        .{
            .kind = .url_decode_uni,
            .input = "%u12g4%2g%",
            .output = "%u12g4%2g%",
            .changed = false,
        },
    };
    var output: [64]u8 = undefined;
    for (cases) |case| {
        var budget: work.Budget = .{ .remaining = 4096 };
        const result = try step(case.kind, .{
            .input = case.input,
            .output = &output,
            .budget = &budget,
        });
        try std.testing.expectEqualStrings(case.output, result.bytes);
        try std.testing.expectEqual(case.changed, result.changed);
        // Every proper prefix includes incomplete escapes. Capacity must suffice
        // and lookahead must remain inside the caller's slice at each boundary.
        for (0..case.input.len) |length| {
            budget.remaining = 4096;
            const partial = try step(case.kind, .{
                .input = case.input[0..length],
                .output = output[0..length],
                .budget = &budget,
            });
            try std.testing.expect(partial.bytes.len <= length);
        }
    }
}

test "HTML entities retain the reference prefix and fixed C64 numeric behavior" {
    const input = "&amplitude;&#x100;&#9223372036854775808;&NBSP;&unknown;&#x;\x00";
    var output: [128]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 8192 };
    const result = try step(.html_entity_decode, .{
        .input = input,
        .output = &output,
        .budget = &budget,
    });
    try std.testing.expectEqualStrings("&\x00\xff\xa0&unknown;&#x;\x00", result.bytes);
    try std.testing.expect(result.changed);
}

test "base64 validation and the reference NUL boundary cannot expose partial output" {
    const cases = [_]struct { input: []const u8, output: []const u8 }{
        .{ .input = "", .output = "" },
        .{ .input = "QQ== \r\n", .output = "A" },
        .{ .input = "QQ==\x00invalid", .output = "A" },
        .{ .input = "\x00QQ==", .output = "" },
        .{ .input = "QU\nJD", .output = "ABC" },
        .{ .input = "Q Q==", .output = "" },
        .{ .input = "QQ==\t", .output = "" },
        .{ .input = "QQ==\r", .output = "" },
        .{ .input = "QQ=", .output = "" },
        .{ .input = "QQ==A", .output = "" },
        .{ .input = "====", .output = "" },
        .{ .input = "AB==", .output = "\x00" },
    };
    var output: [64]u8 = @splat(0x7f);
    for (cases) |case| {
        var budget: work.Budget = .{ .remaining = 1024 };
        const result = try step(.base64_decode, .{
            .input = case.input,
            .output = &output,
            .budget = &budget,
        });
        try std.testing.expectEqualStrings(case.output, result.bytes);
        try std.testing.expectEqual(case.input.len != 0, result.changed);
    }
}

test "base64 decodes independently encoded random binary strings" {
    var random = std.Random.DefaultPrng.init(0x435253);
    var input: [64]u8 = undefined;
    var encoded: [88]u8 = undefined;
    var output: [88]u8 = undefined;
    for (0..512) |index| {
        const length = index % (input.len + 1);
        random.random().bytes(input[0..length]);
        const encoded_length = std.base64.standard.Encoder.calcSize(length);
        const value = std.base64.standard.Encoder.encode(
            encoded[0..encoded_length],
            input[0..length],
        );
        var budget: work.Budget = .{ .remaining = 2048 };
        const result = try step(.base64_decode, .{
            .input = value,
            .output = &output,
            .budget = &budget,
        });
        try std.testing.expectEqualSlices(u8, input[0..length], result.bytes);
    }
}
