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
    // Direct streaming honors the output limit. The indirect reader fills its
    // window ahead of the caller, which would expand bytes before charging work.
    var inflater: std.compress.flate.Decompress = .init(source, container, &.{});
    var writer = std.Io.Writer.fixed(scratch.window);
    var crc = std.hash.crc.@"CRC-32/ISO-HDLC".init();
    var adler: std.hash.Adler32 = .{};
    const start = used.*;
    while (true) {
        const allowance = @min(@as(usize, 8192), scratch.output.len - used.* + 1);
        try budget.debitLinear(allowance, 4, 1);
        retainHistory(&writer, allowance);
        const before = writer.end;
        const consumed = source.seek;
        const finished = if (inflater.reader.stream(&writer, .limited(allowance))) |_|
            false
        else |err| switch (err) {
            error.EndOfStream => true,
            else => return error.InvalidCompressedData,
        };
        const count = writer.end - before;
        std.debug.assert(count <= allowance);
        if (count > scratch.output.len - used.*) return error.ExpansionLimit;
        const bytes = writer.buffer[before..writer.end];
        @memcpy(scratch.output[used.*..][0..count], bytes);
        crc.update(bytes);
        adler.update(bytes);
        used.* += count;
        if (finished) break;
        // Empty stored blocks are legal flush boundaries. They consume framing
        // without producing bytes; refuse only a genuinely stalled decoder.
        if (count == 0 and source.seek == consumed) return error.InvalidCompressedData;
    }
    const valid = switch (inflater.container_metadata) {
        .gzip => |footer| footer.crc == crc.final() and footer.count == used.* - start,
        .zlib => |footer| footer.adler == adler.adler,
        .raw => unreachable,
    };
    if (!valid) return error.InvalidCompressedChecksum;
}

fn retainHistory(writer: *std.Io.Writer, allowance: usize) void {
    if (allowance <= writer.buffer.len - writer.end) return;
    const length = @min(writer.end, std.compress.flate.history_len);
    @memmove(writer.buffer[0..length], writer.buffer[writer.end - length .. writer.end]);
    writer.end = length;
}

test {
    _ = @import("decode_test.zig");
}
