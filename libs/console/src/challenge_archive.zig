//! Fixed little-endian challenge-minute format: a 128-byte header and 96 bytes per active
//! partition, so per-minute deltas keep exact values without SQLite integer coercion.
const std = @import("std");
const p = @import("console_protocol").challenge_minutes;
pub const header_len = 128;
pub const partition_len = 96;
pub const max_len = header_len + p.max_bins * partition_len;
pub const Error = error{InvalidArchive};
const partition_counts = .{ "issued", "accepted" };
const partition_tail = .{ "missing", "invalid", "wasm", "javascript", "unknown_solver" };

pub fn validate(record: *const p.Record) Error!void {
    if (record.epoch == 0 or std.mem.allEqual(u8, &record.boot, 0) or
        record.observations == 0 or record.end_ms <= record.start_ms or
        record.observed_ms != record.end_ms - record.start_ms or record.count > p.max_bins or
        record.minute > std.math.maxInt(i64) or record.end_ms > std.math.maxInt(i64) or
        (record.complete and (!record.sealed or record.gap))) return error.InvalidArchive;
    for (record.bins[0..record.count], 0..) |*entry, i| {
        if (!entry.consistent()) return error.InvalidArchive;
        if (i != 0 and record.bins[i - 1].bin >= entry.bin) return error.InvalidArchive;
    }
}

pub fn length(record: *const p.Record) usize {
    return header_len + @as(usize, record.count) * partition_len;
}

pub fn encode(record: *const p.Record, output: *[max_len]u8) Error![]const u8 {
    try validate(record);
    var writer: std.Io.Writer = .fixed(output);
    write(record, &writer) catch unreachable;
    std.debug.assert(writer.buffered().len == length(record));
    return writer.buffered();
}

fn write(record: *const p.Record, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeAll("SBC1");
    try w.writeInt(u32, record.node, .little);
    try w.writeAll(&record.boot);
    try w.writeInt(u32, record.epoch, .little);
    const flags = @as(u8, @intFromBool(record.sealed)) |
        (@as(u8, @intFromBool(record.complete)) << 1) |
        (@as(u8, @intFromBool(record.gap)) << 2);
    try w.writeInt(u32, flags, .little);
    inline for (.{ "minute", "start_ms", "end_ms", "observed_ms" }) |name|
        try w.writeInt(u64, @field(record, name), .little);
    try w.writeInt(u32, record.observations, .little);
    try w.writeInt(u32, record.submitted, .little);
    for (record.causes) |count| try w.writeInt(u32, count, .little);
    try w.writeByte(record.count);
    try w.writeByte(record.bins_dropped);
    try w.writeInt(u16, 0, .little);
    for (record.bins[0..record.count]) |*entry| {
        try w.writeByte(entry.bin);
        try w.writeAll(&[_]u8{ 0, 0, 0 });
        inline for (partition_counts) |name| try w.writeInt(u32, @field(entry, name), .little);
        for (entry.buckets) |count| try w.writeInt(u32, count, .little);
        inline for (partition_tail) |name| try w.writeInt(u32, @field(entry, name), .little);
    }
}

pub fn decode(bytes: []const u8) Error!p.Record {
    if (bytes.len < header_len or bytes.len > max_len or
        (bytes.len - header_len) % partition_len != 0) return error.InvalidArchive;
    var reader: std.Io.Reader = .fixed(bytes);
    const record = read(&reader, (bytes.len - header_len) / partition_len) catch
        return error.InvalidArchive;
    std.debug.assert(reader.seek == bytes.len);
    try validate(&record);
    return record;
}

fn read(r: *std.Io.Reader, partitions: usize) !p.Record {
    if (!std.mem.eql(u8, try r.take(4), "SBC1")) return error.InvalidArchive;
    var record: p.Record = undefined;
    record.node = try r.takeInt(u32, .little);
    record.boot = (try r.takeArray(16)).*;
    record.epoch = try r.takeInt(u32, .little);
    const flags = try r.takeInt(u32, .little);
    if (flags > 7) return error.InvalidArchive;
    record.sealed = flags & 1 != 0;
    record.complete = flags & 2 != 0;
    record.gap = flags & 4 != 0;
    inline for (.{ "minute", "start_ms", "end_ms", "observed_ms" }) |name|
        @field(record, name) = try r.takeInt(u64, .little);
    record.observations = try r.takeInt(u32, .little);
    record.submitted = try r.takeInt(u32, .little);
    for (&record.causes) |*count| count.* = try r.takeInt(u32, .little);
    record.count = try r.takeByte();
    record.bins_dropped = try r.takeByte();
    if (try r.takeInt(u16, .little) != 0 or record.count != partitions)
        return error.InvalidArchive;
    record.bins = @splat(.{});
    for (record.bins[0..record.count]) |*entry| {
        entry.bin = try r.takeByte();
        if (!std.mem.allEqual(u8, try r.take(3), 0)) return error.InvalidArchive;
        inline for (partition_counts) |name| @field(entry, name) = try r.takeInt(u32, .little);
        for (&entry.buckets) |*count| count.* = try r.takeInt(u32, .little);
        inline for (partition_tail) |name| @field(entry, name) = try r.takeInt(u32, .little);
    }
    return record;
}

test "challenge minute format round-trips partitions and rejects inconsistent or unsorted ones" {
    const t = std.testing;
    var record: p.Record = .{
        .node = 7,
        .boot = @splat('a'),
        .epoch = 1,
        .minute = 2,
        .start_ms = 60000,
        .end_ms = 120000,
        .observed_ms = 60000,
        .observations = 240,
        .sealed = true,
        .complete = true,
        .submitted = 9,
    };
    record.causes[12] = std.math.maxInt(u32);
    const first = record.partition(133).?;
    first.* = .{ .bin = 133, .issued = 4, .accepted = 2, .missing = 1, .wasm = 2 };
    first.buckets[3] = 1;
    _ = record.partition(200).?;
    var bytes: [max_len]u8 = undefined;
    const encoded = try encode(&record, &bytes);
    try t.expectEqual(header_len + 2 * partition_len, encoded.len);
    try t.expectEqualDeep(record, try decode(encoded));
    try t.expectError(error.InvalidArchive, decode(encoded[0 .. encoded.len - 1]));
    record.bins[0].wasm = 1;
    try t.expectError(error.InvalidArchive, encode(&record, &bytes));
    record.bins[0].wasm = 2;
    record.bins[1].bin = 100;
    try t.expectError(error.InvalidArchive, encode(&record, &bytes));
    record.bins[1].bin = 200;
    record.gap = true;
    try t.expectError(error.InvalidArchive, encode(&record, &bytes));
}
