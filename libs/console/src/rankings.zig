//! Collector-owned path prefixes. Fixed minute slots retain every sketch counter.
const std = @import("std");
const Summary = @import("space_saving.zig").Summary;
const Record = @import("store").telemetry.Record;

pub const Minute = struct {
    minute: ?u64 = null,
    first_second: u64 = 0,
    last_second: u64 = 0,
    truncated_records: u64 = 0,
    rejected_records: u64 = 0,
    paths: Summary = .{},
};

pub const Rankings = struct {
    minutes: [2]Minute = @splat(.{}),

    /// Stats owns synchronization and accepts only records inside its 60-second horizon.
    /// Two slots handle late samples from the preceding minute without mixing intervals.
    pub fn add(self: *Rankings, record: *const Record) void {
        const minute = record.second / 60;
        const slot = &self.minutes[minute % self.minutes.len];
        if (slot.minute != minute) slot.* = .{
            .minute = minute,
            .first_second = record.second,
            .last_second = record.second,
        };
        slot.first_second = @min(slot.first_second, record.second);
        slot.last_second = @max(slot.last_second, record.second);
        if (record.truncated) slot.truncated_records +|= 1;
        slot.paths.add(record.path[0..record.path_len]) catch {
            // Overflow refuses the sample without corrupting estimates; its loss is visible.
            slot.rejected_records +|= 1;
        };
    }

    pub fn snapshot(self: *const Rankings, second: u64) Minute {
        const minute = second / 60;
        const slot = &self.minutes[minute % self.minutes.len];
        return if (slot.minute == minute) slot.* else .{ .minute = minute };
    }
};

test "late samples remain in their original minute and slot reuse drops old populations" {
    const t = std.testing;
    var rankings: Rankings = .{};
    var record = std.mem.zeroes(Record);
    record.path_len = 1;
    record.path[0] = '/';
    for ([_]u64{ 119, 120, 119, 180 }) |second| {
        record.second = second;
        rankings.add(&record);
    }
    try t.expectEqual(@as(u64, 0), rankings.snapshot(119).paths.samples);
    try t.expectEqual(@as(u64, 1), rankings.snapshot(120).paths.samples);
    try t.expectEqual(@as(u64, 1), rankings.snapshot(180).paths.samples);
    try t.expectEqual(@as(u64, 0), rankings.snapshot(240).paths.samples);
}
