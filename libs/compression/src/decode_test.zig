const std = @import("std");
const codec = @import("root.zig");
const t = std.testing;
const payload = "bounded representation\n";
const gzip = @embedFile("testdata/body.gz");
const zlib = @embedFile("testdata/body.zlib");
const Budget = struct {
    remaining: u64 = 1_000_000,

    pub fn debitLinear(self: *Budget, bytes: u64, visits: u64, overhead: u64) !void {
        const cost = std.math.mul(u64, bytes, visits) catch return error.WorkLimit;
        const total = std.math.add(u64, cost, overhead) catch return error.WorkLimit;
        if (total > self.remaining) return error.WorkLimit;
        self.remaining -= total;
    }
};
const Fixture = struct {
    output: [256]u8 = undefined,
    window: [codec.window_length]u8 = undefined,
    budget: Budget = .{},

    fn options(self: *Fixture, input: []const u8, coding: codec.Coding) codec.Options {
        return .{
            .input = input,
            .coding = coding,
            .scratch = .{ .output = &self.output, .window = &self.window },
        };
    }
};

test "gzip and zlib decode into bounded reserved storage and debit shared work" {
    const cases = [_]struct { bytes: []const u8, coding: codec.Coding }{
        .{ .bytes = gzip, .coding = .gzip },
        .{ .bytes = zlib, .coding = .zlib },
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        const options = fixture.options(case.bytes, case.coding);
        const result = try codec.decode(options, &fixture.budget);
        try t.expectEqualStrings(payload, result);
        try t.expectEqualSlices(u8, case.bytes, options.input);
        const charged = 1_000_000 - fixture.budget.remaining;
        const input_cost = case.bytes.len * 16 + 1;
        try t.expect(charged >= input_cost + payload.len * 4);
        try t.expect(charged <= input_cost + 2 * ((fixture.output.len + 1) * 4 + 1));
    }
}

test "every truncated gzip and zlib prefix is refused" {
    const cases = [_]struct { bytes: []const u8, coding: codec.Coding }{
        .{ .bytes = gzip, .coding = .gzip },
        .{ .bytes = zlib, .coding = .zlib },
    };
    for (cases) |case| for (0..case.bytes.len) |length| {
        var fixture: Fixture = .{};
        const options = fixture.options(case.bytes[0..length], case.coding);
        const result = codec.decode(options, &fixture.budget);
        if (result) |_| return error.TestUnexpectedResult else |_| {}
    };
}

test "checksums, terminal size and trailing compressed bytes are validated" {
    var fixture: Fixture = .{};
    var gzip_copy: [gzip.len]u8 = undefined;
    for ([_]usize{ gzip.len - 8, gzip.len - 4 }) |offset| {
        @memcpy(&gzip_copy, gzip);
        gzip_copy[offset] ^= 1;
        const options = fixture.options(&gzip_copy, .gzip);
        try t.expectError(error.InvalidCompressedChecksum, codec.decode(options, &fixture.budget));
    }
    var zlib_copy: [zlib.len]u8 = undefined;
    @memcpy(&zlib_copy, zlib);
    zlib_copy[zlib.len - 1] ^= 1;
    const options = fixture.options(&zlib_copy, .zlib);
    try t.expectError(error.InvalidCompressedChecksum, codec.decode(options, &fixture.budget));
    const trailing = gzip ++ "x";
    const extra = fixture.options(trailing, .gzip);
    try t.expectError(error.InvalidCompressedChecksum, codec.decode(extra, &fixture.budget));
}

test "entity expansion, input and work limits refuse without accepting partial output" {
    var fixture: Fixture = .{};
    @memset(&fixture.output, '!');
    var options = fixture.options(gzip, .gzip);
    options.scratch.output = fixture.output[0..4];
    try t.expectError(error.ExpansionLimit, codec.decode(options, &fixture.budget));
    try t.expectEqualStrings("!!!!", fixture.output[0..4]);
    options = fixture.options(gzip, .gzip);
    options.input_limit = gzip.len - 1;
    try t.expectError(error.CompressedInputLimit, codec.decode(options, &fixture.budget));
    options = fixture.options(gzip, .gzip);
    fixture.budget.remaining = 0;
    try t.expectError(error.WorkLimit, codec.decode(options, &fixture.budget));
    try t.expectEqualStrings("!!!!", fixture.output[0..4]);
    fixture.budget.remaining = gzip.len * 16 + 1;
    try t.expectError(error.WorkLimit, codec.decode(options, &fixture.budget));
    try t.expectEqualStrings("!!!!", fixture.output[0..4]);
}

test "concatenated HTTP gzip members each validate and share the output ceiling" {
    var fixture: Fixture = .{};
    const pair = gzip ++ gzip;
    var options = fixture.options(pair, .gzip);
    try t.expectError(error.InvalidCompressedChecksum, codec.decode(options, &fixture.budget));
    options.member_limit = 2;
    try t.expectEqualStrings(payload ++ payload, try codec.decode(options, &fixture.budget));
    const triple = gzip ++ gzip ++ gzip;
    options.input = triple;
    try t.expectError(error.CompressedMemberLimit, codec.decode(options, &fixture.budget));
    options.input = pair;
    options.scratch.output = fixture.output[0..payload.len];
    try t.expectError(error.ExpansionLimit, codec.decode(options, &fixture.budget));
    var changed: [pair.len]u8 = undefined;
    @memcpy(&changed, pair);
    changed[changed.len - 8] ^= 1;
    options = fixture.options(&changed, .gzip);
    options.member_limit = 2;
    try t.expectError(error.InvalidCompressedChecksum, codec.decode(options, &fixture.budget));
}

test "invalid reservations and member bounds fail before reading input" {
    var fixture: Fixture = .{};
    var options = fixture.options(gzip, .gzip);
    options.member_limit = 0;
    try t.expectError(error.InvalidCompressionLimits, codec.decode(options, &fixture.budget));
    options.member_limit = 65;
    try t.expectError(error.InvalidCompressionLimits, codec.decode(options, &fixture.budget));
    options = fixture.options(zlib, .zlib);
    options.member_limit = 2;
    try t.expectError(error.InvalidCompressionLimits, codec.decode(options, &fixture.budget));
    options = fixture.options(gzip, .gzip);
    options.scratch.window = fixture.window[0..1];
    try t.expectError(error.InvalidCompressionLimits, codec.decode(options, &fixture.budget));
    options = fixture.options(gzip, .gzip);
    options.input_limit = 0;
    try t.expectError(error.InvalidCompressionLimits, codec.decode(options, &fixture.budget));
    try t.expectEqual(@as(u64, 1_000_000), fixture.budget.remaining);
}

test "gzip reserved flags and optional header CRC are validated before expansion" {
    var fixture: Fixture = .{};
    var encoded: [128]u8 = undefined;
    @memcpy(encoded[0..10], gzip[0..10]);
    encoded[3] = 0x1e;
    const metadata = "\x03\x00abcname\x00comment\x00";
    @memcpy(encoded[10..][0..metadata.len], metadata);
    const crc_end = 10 + metadata.len;
    const crc: u16 = @truncate(std.hash.crc.@"CRC-32/ISO-HDLC".hash(encoded[0..crc_end]));
    std.mem.writeInt(u16, encoded[crc_end..][0..2], crc, .little);
    @memcpy(encoded[crc_end + 2 ..][0 .. gzip.len - 10], gzip[10..]);
    const length = crc_end + 2 + gzip.len - 10;
    const options = fixture.options(encoded[0..length], .gzip);
    try t.expectEqualStrings(payload, try codec.decode(options, &fixture.budget));
    @memset(&fixture.output, '!');
    encoded[crc_end] ^= 1;
    try t.expectError(error.InvalidCompressedChecksum, codec.decode(options, &fixture.budget));
    try t.expectEqualStrings("!!!!", fixture.output[0..4]);
    @memcpy(encoded[0..gzip.len], gzip);
    encoded[3] = 0x20;
    const reserved = fixture.options(encoded[0..gzip.len], .gzip);
    try t.expectError(error.InvalidCompressedData, codec.decode(reserved, &fixture.budget));
    try t.expectEqualStrings("!!!!", fixture.output[0..4]);
}

test "zlib FCHECK and external dictionary headers are refused before expansion" {
    var fixture: Fixture = .{};
    var encoded: [zlib.len]u8 = undefined;
    @memcpy(&encoded, zlib);
    encoded[1] ^= 1;
    const options = fixture.options(&encoded, .zlib);
    try t.expectError(error.InvalidCompressedData, codec.decode(options, &fixture.budget));
    encoded[1] = zlib[1] & 0xe0 | 0x20;
    const prefix = @as(u16, encoded[0]) << 8 | encoded[1];
    encoded[1] |= @intCast((31 - prefix % 31) % 31);
    try t.expectError(error.InvalidCompressedData, codec.decode(options, &fixture.budget));
}

test "direct expansion retains the complete DEFLATE history across output and budget steps" {
    const compressed = @embedFile("testdata/window.gz");
    var expected: [30000 * 3]u8 = undefined;
    var state: u32 = 0x12345678;
    for (expected[0..30000]) |*byte| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        byte.* = @truncate(state);
    }
    @memcpy(expected[30000..60000], expected[0..30000]);
    @memcpy(expected[60000..90000], expected[0..30000]);
    var output: [expected.len]u8 = undefined;
    var window: [codec.window_length]u8 = undefined;
    var budget: Budget = .{ .remaining = 4_000_000 };
    const options: codec.Options = .{
        .input = compressed,
        .coding = .gzip,
        .scratch = .{ .output = &output, .window = &window },
    };
    try t.expectEqualSlices(u8, &expected, try codec.decode(options, &budget));
    @memset(&output, '!');
    budget.remaining = compressed.len * 16 + 1;
    try t.expectError(error.WorkLimit, codec.decode(options, &budget));
    try t.expectEqualStrings("!!!!", output[0..4]);
    budget.remaining = compressed.len * 16 + 1 + 8192 * 4 + 1;
    try t.expectError(error.WorkLimit, codec.decode(options, &budget));
    try t.expectEqualSlices(u8, expected[0..8192], output[0..8192]);
    try t.expectEqualStrings("!!!!", output[8192..8196]);
}

test "empty stored flush blocks preserve representation and exact output ceilings" {
    const raw = "\x00\x00\x00\xff\xff" ++ // Empty non-final stored block.
        "\x00\x01\x00\xfe\xffx" ++ // One payload byte, followed by another flush.
        "\x00\x00\x00\xff\xff" ++ "\x01\x00\x00\xff\xff";
    const gz = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff" ++ raw ++
        "\x83\x16\xdc\x8c\x01\x00\x00\x00";
    const zl = "\x78\x01" ++ raw ++ "\x00\x79\x00\x79";
    const cases = [_]struct { bytes: []const u8, coding: codec.Coding }{
        .{ .bytes = gz, .coding = .gzip },
        .{ .bytes = zl, .coding = .zlib },
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        var options = fixture.options(case.bytes, case.coding);
        options.scratch.output = fixture.output[0..1];
        try t.expectEqualStrings("x", try codec.decode(options, &fixture.budget));
        options.scratch.output = fixture.output[0..0];
        try t.expectError(error.ExpansionLimit, codec.decode(options, &fixture.budget));
    }
}
