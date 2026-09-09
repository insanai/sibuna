//! Fixed 34-byte storage rows: two normalized 16-byte addresses and a two-byte country.
//! Shared by the importer and the storage owner so both validate identical bytes.
const std = @import("std");
const range = @import("range.zig");
const country = @import("country.zig");
pub const row_bytes = 34;
pub const batch_rows = 100;
pub const batch_bytes = batch_rows * row_bytes;
pub const Error = error{InvalidGeneration};

pub fn encodeRow(value: range.Range) [row_bytes]u8 {
    var out: [row_bytes]u8 = undefined;
    @memcpy(out[0..16], &value.first);
    @memcpy(out[16..32], &value.last);
    @memcpy(out[32..34], &value.country);
    return out;
}

/// Encodes at most `batch_rows` ranges; returns the byte length written.
pub fn encodeBatch(ranges: []const range.Range, out: *[batch_bytes]u8) usize {
    std.debug.assert(ranges.len <= batch_rows);
    for (ranges, 0..) |value, index| out[index * row_bytes ..][0..row_bytes].* = encodeRow(value);
    return ranges.len * row_bytes;
}

/// Appends decoded rows, requiring strict ascending order across calls.
pub fn decodeRows(ranges: []range.Range, count: *usize, bytes: []const u8) Error!void {
    if (bytes.len == 0 or bytes.len % row_bytes != 0) return error.InvalidGeneration;
    var offset: usize = 0;
    while (offset < bytes.len) : (offset += row_bytes) {
        if (count.* == ranges.len) return error.InvalidGeneration;
        const value = &ranges[count.*];
        value.* = .{
            .first = bytes[offset..][0..16].*,
            .last = bytes[offset + 16 ..][0..16].*,
            .country = bytes[offset + 32 ..][0..2].*,
        };
        if (!country.valid(&value.country) or country.isUnknown(value.country) or
            std.mem.order(u8, &value.first, &value.last) == .gt) return error.InvalidGeneration;
        if (count.* != 0 and
            std.mem.order(u8, &ranges[count.* - 1].last, &value.first) != .lt)
            return error.InvalidGeneration;
        count.* += 1;
    }
}

/// Structural check of one batch without cross-batch context.
pub fn validBatch(bytes: []const u8) bool {
    if (bytes.len == 0 or bytes.len > batch_bytes or bytes.len % row_bytes != 0) return false;
    var offset: usize = 0;
    while (offset < bytes.len) : (offset += row_bytes) {
        const first = bytes[offset..][0..16];
        const last = bytes[offset + 16 ..][0..16];
        if (std.mem.order(u8, first, last) == .gt) return false;
        if (!country.valid(bytes[offset + 32 ..][0..2])) return false;
        if (offset != 0 and std.mem.order(u8, first, bytes[offset - 18 ..][0..16]) != .gt)
            return false;
    }
    return true;
}

test "storage rows round-trip and reject disorder" {
    const t = std.testing;
    const a: range.Range = .{ .first = @splat(1), .last = @splat(2), .country = .{ 'U', 'S' } };
    const b: range.Range = .{ .first = @splat(3), .last = @splat(4), .country = .{ 'D', 'E' } };
    var batch: [batch_bytes]u8 = undefined;
    const len = encodeBatch(&.{ a, b }, &batch);
    try t.expectEqual(@as(usize, 68), len);
    try t.expect(validBatch(batch[0..len]));
    var decoded: [2]range.Range = undefined;
    var count: usize = 0;
    try decodeRows(&decoded, &count, batch[0..len]);
    try t.expectEqual(@as(usize, 2), count);
    try t.expectEqualStrings("DE", &decoded[1].country);
    const reversed = encodeBatch(&.{ b, a }, &batch);
    try t.expect(!validBatch(batch[0..reversed]));
    count = 0;
    try t.expectError(error.InvalidGeneration, decodeRows(&decoded, &count, batch[0..reversed]));
    try t.expect(!validBatch(batch[0..33]));
}
