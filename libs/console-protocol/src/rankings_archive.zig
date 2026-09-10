//! Versioned complete minute sketches. Fixed byte order avoids persisting native struct layout.
const std = @import("std");
const Minute = @import("ranking_storage.zig").Minute;
const p = @import("root.zig");
pub const max_bytes = 92 + 256 * (2 + 128 + 16);
pub const Error = error{ InvalidArchive, TooLarge };
pub const Identity = struct {
    node: u32,
    boot: [16]u8,
    queue_loss_start: u64 = 0,
    queue_loss_end: u64 = 0,
};
pub const Archive = struct { identity: Identity, minute: Minute };
const minute_fields = .{ "first_second", "last_second", "truncated_records", "rejected_records" };

pub fn encode(archive: *const Archive, buffer: []u8) Error![]const u8 {
    try validate(archive);
    var w: std.Io.Writer = .fixed(buffer[0..@min(buffer.len, max_bytes)]);
    write(archive, &w) catch return error.TooLarge;
    return w.buffered();
}

fn write(archive: *const Archive, w: *std.Io.Writer) std.Io.Writer.Error!void {
    const minute = &archive.minute;
    try w.writeAll("SBR1");
    try w.writeInt(u32, archive.identity.node, .little);
    try w.writeAll(&archive.identity.boot);
    try w.writeInt(u64, minute.minute.?, .little);
    inline for (minute_fields) |name| try w.writeInt(u64, @field(minute, name), .little);
    try w.writeInt(u64, archive.identity.queue_loss_start, .little);
    try w.writeInt(u64, archive.identity.queue_loss_end, .little);
    try w.writeInt(u64, minute.paths.samples, .little);
    try w.writeInt(u16, 64, .little);
    try w.writeInt(u16, @intCast(minute.paths.len), .little);
    for (minute.paths.counters[0..minute.paths.len]) |*counter| {
        try w.writeInt(u16, @intCast(counter.key.len), .little);
        try w.writeAll(counter.key.slice());
        try w.writeInt(u64, counter.estimate, .little);
        try w.writeInt(u64, counter.error_bound, .little);
    }
}

pub fn decode(bytes: []const u8) Error!Archive {
    var result: Archive = undefined;
    try decodeInto(&result, bytes);
    return result;
}

/// Invalid input may partially fill output; callers publish only after success.
pub fn decodeInto(output: *Archive, bytes: []const u8) Error!void {
    if (bytes.len > max_bytes) return error.TooLarge;
    var reader: std.Io.Reader = .fixed(bytes);
    read(output, &reader) catch return error.InvalidArchive;
    if (reader.seek != bytes.len) return error.InvalidArchive;
    try validate(output);
}

fn read(archive: *Archive, r: *std.Io.Reader) !void {
    if (!std.mem.eql(u8, try r.take(4), "SBR1")) return error.InvalidArchive;
    const node = try r.takeInt(u32, .little);
    const boot = (try r.takeArray(16)).*;
    archive.* = .{ .identity = .{ .node = node, .boot = boot }, .minute = .{} };
    const minute = &archive.minute;
    minute.minute = try r.takeInt(u64, .little);
    inline for (minute_fields) |name| @field(minute, name) = try r.takeInt(u64, .little);
    archive.identity.queue_loss_start = try r.takeInt(u64, .little);
    archive.identity.queue_loss_end = try r.takeInt(u64, .little);
    minute.paths.samples = try r.takeInt(u64, .little);
    if (try r.takeInt(u16, .little) != 64) return error.InvalidArchive;
    minute.paths.len = try r.takeInt(u16, .little);
    if (minute.paths.len > minute.paths.counters.len) return error.InvalidArchive;
    for (minute.paths.counters[0..minute.paths.len]) |*counter| {
        const length = try r.takeInt(u16, .little);
        if (length > 128) return error.InvalidArchive;
        counter.key = try p.Bytes(128).init(try r.take(length));
        counter.estimate = try r.takeInt(u64, .little);
        counter.error_bound = try r.takeInt(u64, .little);
    }
}

fn validate(archive: *const Archive) Error!void {
    const minute = &archive.minute;
    const index = minute.minute orelse return error.InvalidArchive;
    if (index > (std.math.maxInt(u64) - 59) / 60 or
        std.mem.allEqual(u8, &archive.identity.boot, 0) or
        archive.identity.queue_loss_end < archive.identity.queue_loss_start)
        return error.InvalidArchive;
    const summary = &minute.paths;
    if (summary.len > summary.counters.len) return error.InvalidArchive;
    if (summary.samples == 0 and (minute.first_second != 0 or minute.last_second != 0))
        return error.InvalidArchive;
    if (summary.samples != 0 and (minute.first_second < index * 60 or
        minute.last_second >= index * 60 + 60 or minute.first_second > minute.last_second))
        return error.InvalidArchive;
    var estimates: u64 = 0;
    for (summary.counters[0..summary.len], 0..) |*counter, i| {
        if (counter.key.len > 128 or counter.estimate == 0 or
            counter.error_bound >= counter.estimate or
            counter.error_bound > summary.samples / 256) return error.InvalidArchive;
        for (summary.counters[0..i]) |*previous| {
            if (std.mem.eql(u8, previous.key.slice(), counter.key.slice()))
                return error.InvalidArchive;
        }
        estimates = std.math.add(u64, estimates, counter.estimate) catch
            return error.InvalidArchive;
    }
    // Only original collector minutes are archived. Their counter sum equals retained N;
    // serializing local display winners instead would silently discard global candidates.
    if (estimates != summary.samples) return error.InvalidArchive;
}

test "archive retains all 256 counters, errors, node and boot with exact capacity" {
    const t = std.testing;
    var archive: Archive = .{
        .identity = .{ .node = 7, .boot = @splat(9), .queue_loss_start = 4, .queue_loss_end = 6 },
        .minute = .{ .minute = 2, .first_second = 120, .last_second = 179 },
    };
    for (0..512) |i| {
        var key: [128]u8 = @splat('a');
        std.mem.writeInt(u16, key[0..2], @intCast(i), .little);
        try archive.minute.paths.add(&key);
    }
    var buffer: [max_bytes]u8 = undefined;
    const encoded = try encode(&archive, &buffer);
    try t.expectEqual(max_bytes, encoded.len);
    try t.expectEqualDeep(archive, try decode(encoded));
    try t.expectError(error.TooLarge, encode(&archive, buffer[0 .. max_bytes - 1]));
    try t.expectError(error.InvalidArchive, decode(encoded[0 .. encoded.len - 1]));
    buffer[0] = 'X';
    try t.expectError(error.InvalidArchive, decode(&buffer));
    archive.minute.paths.len = 20;
    try t.expectError(error.InvalidArchive, encode(&archive, &buffer));
}
