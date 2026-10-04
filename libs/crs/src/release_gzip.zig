//! Bounded archive expansion using Zig's native deflate decoder. Call only after
//! authenticating the compressed archive. No filesystem or external codec exists.
const std = @import("std");
const tar = @import("release_tar.zig");
const buffers = @import("buffers.zig");
const work = @import("work.zig");
pub const Error = work.Error || error{
    ArchiveInputLimit,
    ExpandedArchiveLimit,
    InvalidCompressedArchive,
    InvalidArchiveChecksum,
};
pub const Scratch = struct { output: []u8, window: []u8 };

pub fn decode(input: []const u8, scratch: Scratch, budget: *work.Budget) Error![]const u8 {
    if (input.len == 0 or input.len > 8 * 1024 * 1024) return error.ArchiveInputLimit;
    if (scratch.output.len == 0 or scratch.output.len > tar.maximum_expanded or
        scratch.window.len != std.compress.flate.max_window_len)
        return error.ExpandedArchiveLimit;
    buffers.assertExclusive(&.{ input, scratch.output, scratch.window });
    try budget.debitLinear(input.len, 16, 1);
    var source: std.Io.Reader = .fixed(input);
    var inflater: std.compress.flate.Decompress = .init(&source, .gzip, scratch.window);
    var buffer: [8192]u8 = undefined;
    var crc = std.hash.crc.@"CRC-32/ISO-HDLC".init();
    var used: usize = 0;
    while (true) {
        const count = inflater.reader.readSliceShort(&buffer) catch
            return error.InvalidCompressedArchive;
        if (count == 0) break;
        if (count > scratch.output.len - used) return error.ExpandedArchiveLimit;
        try budget.debitLinear(count, 4, 1);
        @memcpy(scratch.output[used..][0..count], buffer[0..count]);
        crc.update(buffer[0..count]);
        used += count;
    }
    const footer = inflater.container_metadata.gzip;
    if (footer.crc != crc.final() or footer.count != used or source.seek != input.len)
        return error.InvalidArchiveChecksum;
    return scratch.output[0..used];
}

test "archive expansion validates checksum, terminal size and exact compressed consumption" {
    const compressed = @embedFile("testdata/release-body.gz");
    var output: [256]u8 = undefined;
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    const scratch: Scratch = .{ .output = &output, .window = &window };
    var budget: work.Budget = .{ .remaining = 1_000_000 };
    try std.testing.expectEqualStrings(
        "bounded release\n",
        try decode(compressed, scratch, &budget),
    );
    var corrupt: [compressed.len]u8 = undefined;
    @memcpy(&corrupt, compressed);
    corrupt[corrupt.len - 8] ^= 1;
    try std.testing.expectError(error.InvalidArchiveChecksum, decode(&corrupt, scratch, &budget));
    @memcpy(&corrupt, compressed);
    corrupt[corrupt.len - 4] ^= 1;
    try std.testing.expectError(error.InvalidArchiveChecksum, decode(&corrupt, scratch, &budget));
    var trailing: [compressed.len + 1]u8 = undefined;
    @memcpy(trailing[0..compressed.len], compressed);
    trailing[compressed.len] = 0;
    try std.testing.expectError(error.InvalidArchiveChecksum, decode(&trailing, scratch, &budget));
}

test "archive expansion refuses oversized output and exhausted work" {
    const compressed = @embedFile("testdata/release-body.gz");
    var output: [4]u8 = @splat('!');
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    const scratch: Scratch = .{ .output = &output, .window = &window };
    var budget: work.Budget = .{ .remaining = 1_000_000 };
    try std.testing.expectError(error.ExpandedArchiveLimit, decode(compressed, scratch, &budget));
    try std.testing.expectEqualStrings("!!!!", &output);
    budget.remaining = 0;
    try std.testing.expectError(error.WorkLimit, decode(compressed, scratch, &budget));
    try std.testing.expectEqualStrings("!!!!", &output);
}
