//! Streaming CSV expansion for gzip publishers. Compressed bytes, expanded bytes, rows and
//! line length are bounded; the gzip footer CRC and size are verified before publication.
//! The generation digest is the SHA-256 of the compressed bytes, as the publisher ships them.
const std = @import("std");
const database = @import("database.zig");
pub const max_compressed_bytes = 16 * 1024 * 1024;

pub fn decode(
    allocator: std.mem.Allocator,
    io: std.Io,
    provider: database.Provider,
    version: []const u8,
    compressed: []const u8,
    stopping: *const std.atomic.Value(bool),
) !database.Database {
    if (compressed.len == 0 or compressed.len > max_compressed_bytes) return error.Capacity;
    if (provider.compression() != .gzip) return error.InvalidInput;
    var loader = try database.Loader.init(allocator);
    errdefer loader.abandon();
    var input: std.Io.Reader = .fixed(compressed);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var inflater: std.compress.flate.Decompress = .init(&input, .gzip, &window);
    var buffer: [8192]u8 = undefined;
    var crc = std.hash.crc.Crc32.init();
    var expanded: usize = 0;
    while (true) {
        try io.checkCancel();
        if (stopping.load(.acquire)) return error.Canceled;
        const count = try inflater.reader.readSliceShort(&buffer);
        if (count == 0) break;
        expanded += count;
        if (expanded > database.max_csv_bytes) return error.Capacity;
        crc.update(buffer[0..count]);
        try loader.feed(buffer[0..count]);
    }
    const footer = inflater.container_metadata.gzip;
    if (footer.crc != crc.final() or footer.count != expanded or input.seek != compressed.len)
        return error.InvalidChecksum;
    try loader.endFile();
    var result = try loader.finish(provider, version);
    std.crypto.hash.sha2.Sha256.hash(compressed, &result.digest, .{});
    result.file_digests[0] = result.digest;
    return result;
}

test "gzip CRC corruption and shutdown cannot activate a partial country dataset" {
    const t = std.testing;
    const compressed = @embedFile("testdata/countries.csv.gz");
    var stopping = std.atomic.Value(bool).init(false);
    var valid = try decode(t.allocator, t.io, .dbip, "2026-09", compressed, &stopping);
    defer valid.deinit();
    try t.expectEqual(@as(usize, 2), valid.ranges.len);
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(compressed, &expected, .{});
    try t.expectEqualSlices(u8, &expected, &valid.digest);
    var corrupt = compressed.*;
    corrupt[corrupt.len - 8] ^= 1;
    try t.expectError(
        error.InvalidChecksum,
        decode(t.allocator, t.io, .dbip, "2026-09", &corrupt, &stopping),
    );
    try t.expectError(
        error.InvalidInput,
        decode(t.allocator, t.io, .user_country, "2026-09-09", compressed, &stopping),
    );
    stopping.store(true, .release);
    try t.expectError(
        error.Canceled,
        decode(t.allocator, t.io, .dbip, "2026-09", compressed, &stopping),
    );
}
