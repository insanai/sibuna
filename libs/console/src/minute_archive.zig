//! Fixed little-endian format preserves full u64 counters without SQLite integer coercion.
//! SBM2 appends three resource gauges behind presence bits; SBM1 rows stay readable.
const std = @import("std");
const p = @import("console_protocol").minutes;
pub const legacy_len = 152;
pub const bytes_len = 176;
const gauges = .{ "rss_last_kib", "rss_max_kib", "cpu_ms" };
pub const Error = error{InvalidArchive};
const times = .{ "minute", "utc_start", "utc_end", "start_ms", "end_ms", "observed_ms" };

pub fn validate(record: *const p.Record) Error!void {
    if (record.epoch == 0 or std.mem.allEqual(u8, &record.boot, 0) or
        record.observations == 0 or record.utc_start > record.utc_end or
        record.minute != record.utc_end / 60 or record.end_ms <= record.start_ms or
        record.observed_ms != record.end_ms - record.start_ms or
        (record.complete and (!record.sealed or record.gap))) return error.InvalidArchive;
    inline for (times) |name| {
        if (@field(record, name) > std.math.maxInt(i64)) return error.InvalidArchive;
    }
    inline for (gauges) |name| if (@field(record, name)) |value| {
        if (value > std.math.maxInt(i64)) return error.InvalidArchive;
    };
    // The codec has an explicit field order; a new family requires a new format version.
    comptime std.debug.assert(@typeInfo(@TypeOf(record.counts)).@"struct".field_names.len == 8);
}

pub fn encode(record: *const p.Record, output: *[bytes_len]u8) Error!void {
    try validate(record);
    var writer: std.Io.Writer = .fixed(output);
    write(record, &writer) catch unreachable;
    std.debug.assert(writer.buffered().len == bytes_len);
}

fn write(record: *const p.Record, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeAll("SBM2");
    try w.writeInt(u32, record.node, .little);
    try w.writeAll(&record.boot);
    try w.writeInt(u32, record.epoch, .little);
    const flags = @as(u8, @intFromBool(record.sealed)) |
        (@as(u8, @intFromBool(record.complete)) << 1) |
        (@as(u8, @intFromBool(record.gap)) << 2);
    try w.writeInt(u32, flags, .little);
    inline for (times) |name| try w.writeInt(u64, @field(record, name), .little);
    try w.writeInt(u32, record.observations, .little);
    var present: u32 = 0;
    inline for (gauges, 0..) |name, bit|
        present |= @as(u32, @intFromBool(@field(record, name) != null)) << bit;
    try w.writeInt(u32, present, .little);
    inline for (p.counter_fields) |name| try w.writeInt(u64, @field(record.counts, name), .little);
    inline for (gauges) |name| try w.writeInt(u64, @field(record, name) orelse 0, .little);
}

pub fn decode(bytes: []const u8) Error!p.Record {
    if (bytes.len != bytes_len and bytes.len != legacy_len) return error.InvalidArchive;
    var reader: std.Io.Reader = .fixed(bytes);
    const record = read(&reader, bytes.len == legacy_len) catch return error.InvalidArchive;
    std.debug.assert(reader.seek == bytes.len);
    try validate(&record);
    return record;
}

fn read(r: *std.Io.Reader, legacy: bool) !p.Record {
    const magic: []const u8 = if (legacy) "SBM1" else "SBM2";
    if (!std.mem.eql(u8, try r.take(4), magic)) return error.InvalidArchive;
    var record: p.Record = undefined;
    record.node = try r.takeInt(u32, .little);
    record.boot = (try r.takeArray(16)).*;
    record.epoch = try r.takeInt(u32, .little);
    const flags = try r.takeInt(u32, .little);
    if (flags > 7) return error.InvalidArchive;
    record.sealed = flags & 1 != 0;
    record.complete = flags & 2 != 0;
    record.gap = flags & 4 != 0;
    inline for (times) |name| @field(record, name) = try r.takeInt(u64, .little);
    record.observations = try r.takeInt(u32, .little);
    const present = try r.takeInt(u32, .little);
    if (present > 7 or (legacy and present != 0)) return error.InvalidArchive;
    inline for (p.counter_fields) |name| @field(record.counts, name) = try r.takeInt(u64, .little);
    inline for (gauges, 0..) |name, bit| {
        const value: u64 = if (legacy) 0 else try r.takeInt(u64, .little);
        @field(record, name) = if (present >> bit & 1 != 0) value else null;
    }
    return record;
}

test "minute format preserves maximum counters, rejects reserved bits and validates coverage" {
    const t = std.testing;
    var record: p.Record = .{
        .node = 7,
        .boot = @splat('a'),
        .epoch = 1,
        .minute = 2,
        .utc_start = 119,
        .utc_end = 179,
        .start_ms = 1000,
        .end_ms = 61000,
        .observed_ms = 60000,
        .observations = 240,
        .sealed = true,
        .complete = true,
    };
    inline for (p.counter_fields) |name| @field(record.counts, name) = std.math.maxInt(u64);
    var encoded: [bytes_len]u8 = undefined;
    try encode(&record, &encoded);
    try t.expectEqualDeep(record, try decode(&encoded));
    try t.expectError(error.InvalidArchive, decode(encoded[0 .. bytes_len - 1]));
    encoded[31] = 1;
    try t.expectError(error.InvalidArchive, decode(&encoded));
    encoded[31] = 0;
    encoded[87] = 1;
    try t.expectError(error.InvalidArchive, decode(&encoded));
    encoded[87] = 0;
    // A version-36 row decodes with absent gauges; gauges round-trip with presence bits.
    var legacy = encoded[0..legacy_len].*;
    @memcpy(legacy[0..4], "SBM1");
    legacy[84] = 0;
    const old = try decode(&legacy);
    try t.expect(old.rss_last_kib == null and old.cpu_ms == null);
    record.rss_last_kib = 51200;
    record.cpu_ms = 730;
    try encode(&record, &encoded);
    const gauged = try decode(&encoded);
    try t.expectEqual(@as(?u64, 51200), gauged.rss_last_kib);
    try t.expect(gauged.rss_max_kib == null);
    try t.expectEqual(@as(?u64, 730), gauged.cpu_ms);
    record.gap = true;
    try t.expectError(error.InvalidArchive, encode(&record, &encoded));
    record.complete = false;
    record.observed_ms -= 1;
    try t.expectError(error.InvalidArchive, encode(&record, &encoded));
}
