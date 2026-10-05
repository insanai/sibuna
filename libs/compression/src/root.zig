//! Pure, bounded gzip/zlib expansion into caller-reserved disjoint storage.
//! No allocation, filesystem, socket or application dependency exists here.
const std = @import("std");
const buffers = @import("text").buffers;
pub const Coding = enum { gzip, zlib };
pub const Error = error{
    InvalidCompressionLimits,
    CompressedInputLimit,
    ExpansionLimit,
    InvalidCompressedData,
    InvalidCompressedChecksum,
    CompressedMemberLimit,
    WorkLimit,
};
pub const Scratch = struct { output: []u8, window: []u8 };
pub const Options = struct {
    input: []const u8,
    coding: Coding,
    scratch: Scratch,
    input_limit: usize = 8 * 1024 * 1024,
    // Archives require one member. HTTP gzip can explicitly permit bounded
    // concatenated members; each has its own checksum and terminal size.
    member_limit: u8 = 1,
};
const maximum_bytes = 64 * 1024 * 1024;
pub const window_length = std.compress.flate.max_window_len;

/// Budget supplies debitLinear(bytes, visits, overhead), returning WorkLimit.
/// Failed expansion yields no accepted representation; the caller must discard
/// partial scratch. Original compressed bytes remain immutable for wire replay.
pub fn decode(options: Options, budget: anytype) Error![]const u8 {
    try validate(options);
    const scratch = options.scratch;
    buffers.assertExclusive(&.{ options.input, scratch.output, scratch.window });
    try budget.debitLinear(options.input.len, 16, 1);
    var source: std.Io.Reader = .fixed(options.input);
    var used: usize = 0;
    var members: u8 = 0;
    while (true) {
        if (members == options.member_limit) return error.CompressedMemberLimit;
        members += 1;
        try member(&source, options.coding, scratch, &used, budget);
        if (source.seek == options.input.len) return scratch.output[0..used];
        if (options.coding != .gzip or options.member_limit == 1)
            return error.InvalidCompressedChecksum;
    }
}

fn validate(options: Options) Error!void {
    if (options.input_limit == 0 or options.input_limit > maximum_bytes or
        options.scratch.output.len > maximum_bytes or
        options.scratch.window.len != window_length or
        options.member_limit == 0 or options.member_limit > 64 or
        (options.coding == .zlib and options.member_limit != 1))
        return error.InvalidCompressionLimits;
    if (options.input.len == 0 or options.input.len > options.input_limit)
        return error.CompressedInputLimit;
}

fn member(
    source: *std.Io.Reader,
    coding: Coding,
    scratch: Scratch,
    used: *usize,
    budget: anytype,
) Error!void {
    try @import("headers.zig").validate(source.buffered(), coding);
    const container: std.compress.flate.Container = switch (coding) {
        .gzip => .gzip,
        .zlib => .zlib,
    };
    var inflater: std.compress.flate.Decompress = .init(source, container, scratch.window);
    var buffer: [8192]u8 = undefined;
    var crc = std.hash.crc.@"CRC-32/ISO-HDLC".init();
    var adler: std.hash.Adler32 = .{};
    const start = used.*;
    while (true) {
        const count = inflater.reader.readSliceShort(&buffer) catch
            return error.InvalidCompressedData;
        if (count == 0) break;
        if (count > scratch.output.len - used.*) return error.ExpansionLimit;
        try budget.debitLinear(count, 4, 1);
        const bytes = buffer[0..count];
        @memcpy(scratch.output[used.*..][0..count], bytes);
        crc.update(bytes);
        adler.update(bytes);
        used.* += count;
    }
    const valid = switch (inflater.container_metadata) {
        .gzip => |footer| footer.crc == crc.final() and footer.count == used.* - start,
        .zlib => |footer| footer.adler == adler.adler,
        .raw => unreachable,
    };
    if (!valid) return error.InvalidCompressedChecksum;
}

test {
    _ = @import("decode_test.zig");
}
