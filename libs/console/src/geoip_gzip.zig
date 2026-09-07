//! Streaming CSV expansion bounds compressed bytes, expanded bytes, rows and line length.
//! The standard inflater exposes the footer; verify CRC/size here before publication.
const std = @import("std");
const geo = @import("geoip.zig");
const generation = @import("geoip_generation.zig");
pub const max_compressed_bytes = 16 * 1024 * 1024;

pub fn decode(
    allocator: std.mem.Allocator,
    io: std.Io,
    compressed: []const u8,
    stopping: *const std.atomic.Value(bool),
) !generation.Generation {
    if (compressed.len == 0 or compressed.len > max_compressed_bytes) return error.Capacity;
    const storage = try allocator.alloc(geo.Range, generation.max_ranges);
    errdefer allocator.free(storage);
    var parser: Parser = .{ .builder = .{ .storage = storage } };
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
        if (expanded > generation.max_csv_bytes) return error.Capacity;
        crc.update(buffer[0..count]);
        try parser.append(buffer[0..count]);
    }
    const footer = inflater.container_metadata.gzip;
    if (footer.crc != crc.final() or footer.count != expanded or input.seek != compressed.len)
        return error.InvalidChecksum;
    if (parser.length != 0) try parser.builder.append(parser.line[0..parser.length]);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(compressed, &digest, .{});
    return .{
        .allocator = allocator,
        .ranges = try parser.builder.finish(),
        .allocation = storage,
        .digest = digest,
    };
}

const Parser = struct {
    builder: geo.Builder,
    line: [128]u8 = undefined,
    length: usize = 0,

    fn append(self: *Parser, bytes: []const u8) !void {
        for (bytes) |byte| {
            if (byte == '\n') {
                try self.builder.append(self.line[0..self.length]);
                self.length = 0;
                continue;
            }
            if (self.length == self.line.len) return error.InvalidRow;
            self.line[self.length] = byte;
            self.length += 1;
        }
    }
};

test "gzip CRC corruption and shutdown cannot activate a partial country dataset" {
    const t = std.testing;
    const compressed = @embedFile("testdata/countries.csv.gz");
    var stopping = std.atomic.Value(bool).init(false);
    var valid = try decode(t.allocator, t.io, compressed, &stopping);
    defer valid.deinit();
    try t.expectEqual(@as(usize, 2), valid.ranges.len);
    var corrupt = compressed.*;
    corrupt[corrupt.len - 8] ^= 1;
    try t.expectError(error.InvalidChecksum, decode(t.allocator, t.io, &corrupt, &stopping));
    stopping.store(true, .release);
    try t.expectError(error.Canceled, decode(t.allocator, t.io, compressed, &stopping));
}
