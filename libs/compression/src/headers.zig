//! Complete wrapper validation before the standard-library inflater. Its native
//! decoder handles DEFLATE but does not verify every gzip/zlib header constraint.
const std = @import("std");
const codec = @import("root.zig");

pub fn validate(bytes: []const u8, coding: codec.Coding) codec.Error!void {
    switch (coding) {
        .gzip => try gzip(bytes),
        .zlib => {
            if (bytes.len < 2) return error.InvalidCompressedData;
            const header = @as(u16, bytes[0]) << 8 | bytes[1];
            if (header % 31 != 0 or bytes[0] & 15 != 8 or bytes[0] >> 4 > 7 or
                bytes[1] & 0x20 != 0) return error.InvalidCompressedData;
        },
    }
}

fn gzip(bytes: []const u8) codec.Error!void {
    if (bytes.len < 10 or bytes[0] != 0x1f or bytes[1] != 0x8b or bytes[2] != 8)
        return error.InvalidCompressedData;
    const flags = bytes[3];
    if (flags & 0xe0 != 0) return error.InvalidCompressedData;
    var end: usize = 10;
    if (flags & 4 != 0) {
        const length_bytes = try take(bytes, &end, 2);
        const length = std.mem.readInt(u16, length_bytes[0..2], .little);
        _ = try take(bytes, &end, length);
    }
    for ([_]u8{ 8, 16 }) |flag| {
        if (flags & flag == 0) continue;
        const length = std.mem.indexOfScalar(u8, bytes[end..], 0) orelse
            return error.InvalidCompressedData;
        _ = try take(bytes, &end, length + 1);
    }
    if (flags & 2 != 0) {
        const expected: u16 = @truncate(std.hash.crc.@"CRC-32/ISO-HDLC".hash(bytes[0..end]));
        const crc_bytes = try take(bytes, &end, 2);
        if (std.mem.readInt(u16, crc_bytes[0..2], .little) != expected)
            return error.InvalidCompressedChecksum;
    }
}

fn take(bytes: []const u8, end: *usize, length: usize) codec.Error![]const u8 {
    std.debug.assert(end.* <= bytes.len);
    if (length > bytes.len - end.*) return error.InvalidCompressedData;
    const result = bytes[end.*..][0..length];
    end.* += length;
    return result;
}
