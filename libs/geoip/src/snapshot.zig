//! Compact, versioned generation snapshot for embedding or offline transfer. Rows use a
//! canonical tagged width class so decoding is one fixed-shape loop and every byte
//! sequence has at most one valid meaning. The header carries provenance and a payload
//! digest; the decoder rejects anything non-canonical, unordered or unknown.
const std = @import("std");
const address = @import("address.zig");
const country = @import("country.zig");
const ranges = @import("range.zig");
const database = @import("database.zig");
pub const magic = "SBGEOIP1";
pub const header_bytes = 160;
pub const max_bytes = 32 * 1024 * 1024;
pub const max_row_bytes = 1 + 16 + 16 + 2;
pub const Error = error{InvalidSnapshot};
const adjacent_bit: u8 = 0x80;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Class = enum(u2) { v4 = 0, aligned = 1, full = 2 };

pub const Header = struct {
    provider: database.Provider,
    version: database.Version,
    rows: u32,
    payload_len: u32,
    digest: [32]u8,
    file_digests: [database.max_files][32]u8,
    files: u8,
    payload_digest: [32]u8,
};

/// Header-only validation for build-time checks; does not decode rows.
pub fn peek(bytes: []const u8) Error!Header {
    if (bytes.len < header_bytes or bytes.len > max_bytes) return error.InvalidSnapshot;
    if (!std.mem.eql(u8, bytes[0..8], magic) or bytes[9] != 0) return error.InvalidSnapshot;
    const provider = std.enums.fromInt(database.Provider, bytes[8]) orelse
        return error.InvalidSnapshot;
    const version_len = std.mem.indexOfScalar(u8, bytes[10..20], 0) orelse 10;
    const version = database.Version.init(bytes[10..][0..version_len]) catch
        return error.InvalidSnapshot;
    if (!provider.versionValid(version.slice())) return error.InvalidSnapshot;
    const rows = std.mem.readInt(u32, bytes[20..24], .big);
    const payload_len = std.mem.readInt(u32, bytes[24..28], .big);
    const files = bytes[156];
    if (rows == 0 or rows > database.max_ranges or files != provider.fileCount())
        return error.InvalidSnapshot;
    if (payload_len != bytes.len - header_bytes) return error.InvalidSnapshot;
    if (!std.mem.allEqual(u8, bytes[157..160], 0)) return error.InvalidSnapshot;
    return .{
        .provider = provider,
        .version = version,
        .rows = rows,
        .payload_len = payload_len,
        .digest = bytes[28..60].*,
        .file_digests = .{ bytes[60..92].*, bytes[92..124].* },
        .files = files,
        .payload_digest = bytes[124..156].*,
    };
}

fn classOf(first: [16]u8, last: [16]u8) Class {
    if (address.isMapped(first) and address.isMapped(last)) return .v4;
    if (std.mem.allEqual(u8, first[8..16], 0) and std.mem.allEqual(u8, last[8..16], 255))
        return .aligned;
    return .full;
}

fn width(class: Class) usize {
    return switch (class) {
        .v4 => 4,
        .aligned => 8,
        .full => 16,
    };
}

fn significant(class: Class, ip: *const [16]u8) []const u8 {
    return switch (class) {
        .v4 => ip[12..16],
        .aligned => ip[0..8],
        .full => ip[0..16],
    };
}

fn encodeRow(previous: ?ranges.Range, value: ranges.Range, out: *[max_row_bytes]u8) usize {
    const class = classOf(value.first, value.last);
    var tag: u8 = @backingInt(class);
    var length: usize = 1;
    const adjacent = if (previous) |p| blk: {
        const successor = address.next(p.last) orelse break :blk false;
        break :blk std.mem.eql(u8, &successor, &value.first);
    } else false;
    if (adjacent) {
        tag |= adjacent_bit;
    } else {
        const first = significant(class, &value.first);
        @memcpy(out[length..][0..first.len], first);
        length += first.len;
    }
    const last = significant(class, &value.last);
    @memcpy(out[length..][0..last.len], last);
    length += last.len;
    out[length..][0..2].* = value.country;
    out[0] = tag;
    return length + 2;
}

fn expand(class: Class, bytes: []const u8, fill: u8) [16]u8 {
    var ip: [16]u8 = @splat(fill);
    switch (class) {
        .v4 => {
            ip[0..12].* = address.mapped;
            ip[12..16].* = bytes[0..4].*;
        },
        .aligned => ip[0..8].* = bytes[0..8].*,
        .full => ip = bytes[0..16].*,
    }
    return ip;
}

const Decoded = struct { range: ranges.Range, consumed: usize };

fn decodeRow(previous: ?ranges.Range, bytes: []const u8) Error!Decoded {
    if (bytes.len < 1) return error.InvalidSnapshot;
    const tag = bytes[0];
    if (tag & 0x7c != 0 or tag & 0x03 == 3) return error.InvalidSnapshot;
    const class: Class = @fromBackingInt(@intCast(@as(u2, @truncate(tag))));
    const adjacent = tag & adjacent_bit != 0;
    const w = width(class);
    var offset: usize = 1;
    var first: [16]u8 = undefined;
    if (adjacent) {
        const p = previous orelse return error.InvalidSnapshot;
        first = address.next(p.last) orelse return error.InvalidSnapshot;
    } else {
        if (bytes.len < offset + w) return error.InvalidSnapshot;
        first = expand(class, bytes[offset..][0..w], 0);
        offset += w;
    }
    if (bytes.len < offset + w + 2) return error.InvalidSnapshot;
    const last = expand(class, bytes[offset..][0..w], 255);
    offset += w;
    const value: ranges.Range = .{
        .first = first,
        .last = last,
        .country = bytes[offset..][0..2].*,
    };
    offset += 2;
    // Canonical form: the smallest class and the adjacency flag whenever it applies.
    if (classOf(first, last) != class) return error.InvalidSnapshot;
    if (!adjacent) {
        if (previous) |p| if (address.next(p.last)) |successor| {
            if (std.mem.eql(u8, &successor, &first)) return error.InvalidSnapshot;
        };
    }
    if (std.mem.order(u8, &first, &last) == .gt) return error.InvalidSnapshot;
    if (previous) |p| if (std.mem.order(u8, &first, &p.last) != .gt) return error.InvalidSnapshot;
    if (!country.valid(&value.country) or country.isUnknown(value.country))
        return error.InvalidSnapshot;
    return .{ .range = value, .consumed = offset };
}

const Payload = struct { length: u32, digest: [32]u8 };

fn measure(db: *const database.Database) Payload {
    var hasher = Sha256.init(.{});
    var length: usize = 0;
    var previous: ?ranges.Range = null;
    var row: [max_row_bytes]u8 = undefined;
    for (db.ranges) |value| {
        const n = encodeRow(previous, value, &row);
        hasher.update(row[0..n]);
        length += n;
        previous = value;
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return .{ .length = @intCast(length), .digest = digest };
}

pub fn encode(writer: *std.Io.Writer, db: *const database.Database) !void {
    if (db.ranges.len == 0 or db.ranges.len > database.max_ranges) return error.InvalidSnapshot;
    const payload = measure(db);
    if (header_bytes + @as(usize, payload.length) > max_bytes) return error.InvalidSnapshot;
    var header: [header_bytes]u8 = @splat(0);
    header[0..8].* = magic.*;
    header[8] = @backingInt(db.provider);
    @memcpy(header[10..][0..db.version.len], db.version.slice());
    std.mem.writeInt(u32, header[20..24], @intCast(db.ranges.len), .big);
    std.mem.writeInt(u32, header[24..28], payload.length, .big);
    header[28..60].* = db.digest;
    header[60..92].* = db.file_digests[0];
    header[92..124].* = db.file_digests[1];
    header[124..156].* = payload.digest;
    header[156] = db.files;
    try writer.writeAll(&header);
    var previous: ?ranges.Range = null;
    var row: [max_row_bytes]u8 = undefined;
    for (db.ranges) |value| {
        try writer.writeAll(row[0..encodeRow(previous, value, &row)]);
        previous = value;
    }
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !database.Database {
    const header = try peek(bytes);
    const payload = bytes[header_bytes..];
    var digest: [32]u8 = undefined;
    Sha256.hash(payload, &digest, .{});
    if (!std.mem.eql(u8, &digest, &header.payload_digest)) return error.InvalidSnapshot;
    const storage = try allocator.alloc(ranges.Range, header.rows);
    errdefer allocator.free(storage);
    var offset: usize = 0;
    var previous: ?ranges.Range = null;
    for (storage) |*slot| {
        const decoded = try decodeRow(previous, payload[offset..]);
        slot.* = decoded.range;
        offset += decoded.consumed;
        previous = decoded.range;
    }
    if (offset != payload.len) return error.InvalidSnapshot;
    ranges.checkSorted(storage) catch return error.InvalidSnapshot;
    return .{
        .allocator = allocator,
        .ranges = storage,
        .allocation = storage,
        .digest = header.digest,
        .provider = header.provider,
        .version = header.version,
        .file_digests = header.file_digests,
        .files = header.files,
    };
}

test "snapshot round-trips mixed width classes and adjacency" {
    const t = std.testing;
    const csv =
        "1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.3.255,CN\n1.0.8.0,1.0.15.255,CN\n" ++
        "2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP\n" ++
        "2001:201::,2001:201:ffff:ffff:ffff:ffff:ffff:ffff,SG\n" ++
        "2001:218:4000:5::,2001:218:4000:5:7fff:ffff:ffff:ffff,JP\n" ++
        "2001:218:4000:5:8000::,2001:218:4000:5:ffff:ffff:ffff:ffff,HK\n";
    var original = try database.fromCsv(t.allocator, .user_country, "2026-09-09", csv);
    defer original.deinit();
    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try encode(&writer, &original);
    const bytes = writer.buffered();
    try t.expectEqual(header_bytes + (1 + 4 + 4 + 2) + (1 + 4 + 2) + (1 + 4 + 4 + 2) +
        (1 + 8 + 8 + 2) + (1 + 8 + 2) + (1 + 16 + 16 + 2) + (1 + 16 + 2), bytes.len);
    var restored = try decode(t.allocator, bytes);
    defer restored.deinit();
    try t.expectEqual(original.ranges.len, restored.ranges.len);
    for (original.ranges, restored.ranges) |a, b| try t.expectEqual(a, b);
    try t.expectEqualSlices(u8, &original.digest, &restored.digest);
    try t.expectEqualStrings("2026-09-09", restored.version.slice());
    try t.expectEqual(database.Provider.user_country, restored.provider);
    try t.expectEqualStrings("HK", &restored.lookupText("2001:218:4000:5:9000::1").?);
    const header = try peek(bytes);
    try t.expectEqual(@as(u32, 7), header.rows);
}

test "snapshot decoder rejects corruption, truncation and non-canonical rows" {
    const t = std.testing;
    var original = try database.fromCsv(t.allocator, .dbip, "2026-09", "1.0.0.0,1.0.0.255,AU\n");
    defer original.deinit();
    var buffer: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try encode(&writer, &original);
    const bytes = writer.buffered();
    try t.expectError(error.InvalidSnapshot, decode(t.allocator, bytes[0 .. bytes.len - 1]));
    var flipped = buffer;
    flipped[header_bytes + 3] ^= 1;
    try t.expectError(error.InvalidSnapshot, decode(t.allocator, flipped[0..bytes.len]));
    var bad_magic = buffer;
    bad_magic[0] = 'X';
    try t.expectError(error.InvalidSnapshot, peek(bad_magic[0..bytes.len]));
    // A mapped IPv4 range written with the full width class is not canonical.
    var full: [header_bytes + 35]u8 = @splat(0);
    @memcpy(full[0..header_bytes], bytes[0..header_bytes]);
    std.mem.writeInt(u32, full[24..28], 35, .big);
    full[header_bytes] = 2;
    full[header_bytes + 1 ..][0..16].* = original.ranges[0].first;
    full[header_bytes + 17 ..][0..16].* = original.ranges[0].last;
    full[header_bytes + 33 ..][0..2].* = .{ 'A', 'U' };
    Sha256.hash(full[header_bytes..], full[124..156], .{});
    try t.expectError(error.InvalidSnapshot, decode(t.allocator, &full));
}
