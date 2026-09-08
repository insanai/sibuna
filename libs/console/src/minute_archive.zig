//! Fixed little-endian format preserves full u64 counters without SQLite integer coercion.
const std = @import("std");
const p = @import("console_protocol").minutes;
pub const bytes_len = 152;
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
    // The codec has an explicit field order; a new family requires a new format version.
    comptime std.debug.assert(@typeInfo(@TypeOf(record.counts)).@"struct".fields.len == 8);
}

pub fn encode(record: *const p.Record, output: *[bytes_len]u8) Error!void {
    try validate(record);
    var writer: std.Io.Writer = .fixed(output);
    write(record, &writer) catch unreachable;
    std.debug.assert(writer.buffered().len == bytes_len);
}

fn write(record: *const p.Record, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeAll("SBM1");
    try w.writeInt(u32, record.node, .little);
    try w.writeAll(&record.boot);
    try w.writeInt(u32, record.epoch, .little);
    const flags = @as(u8, @intFromBool(record.sealed)) |
        (@as(u8, @intFromBool(record.complete)) << 1) |
        (@as(u8, @intFromBool(record.gap)) << 2);
    try w.writeInt(u32, flags, .little);
    inline for (times) |name| try w.writeInt(u64, @field(record, name), .little);
    try w.writeInt(u32, record.observations, .little);
    try w.writeInt(u32, 0, .little);
    inline for (p.counter_fields) |name| try w.writeInt(u64, @field(record.counts, name), .little);
}

pub fn decode(bytes: []const u8) Error!p.Record {
    if (bytes.len != bytes_len) return error.InvalidArchive;
    var reader: std.Io.Reader = .fixed(bytes);
    const record = read(&reader) catch return error.InvalidArchive;
    std.debug.assert(reader.seek == bytes_len);
    try validate(&record);
    return record;
}

fn read(r: *std.Io.Reader) !p.Record {
    if (!std.mem.eql(u8, try r.take(4), "SBM1")) return error.InvalidArchive;
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
    if (try r.takeInt(u32, .little) != 0) return error.InvalidArchive;
    inline for (p.counter_fields) |name| @field(record.counts, name) = try r.takeInt(u64, .little);
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
    encoded[84] = 1;
    try t.expectError(error.InvalidArchive, decode(&encoded));
    record.gap = true;
    try t.expectError(error.InvalidArchive, encode(&record, &encoded));
    record.complete = false;
    record.observed_ms -= 1;
    try t.expectError(error.InvalidArchive, encode(&record, &encoded));
}
