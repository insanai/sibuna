//! Collector-owned path prefixes. Fixed minute slots retain every sketch counter.
const std = @import("std");
const Record = @import("store").telemetry.Record;

pub const Minute = @import("console_protocol").ranking_storage.Minute;

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
        const host = record.referer[0..record.referer_len];
        if (host.len != 0) slot.referrers.add(host) catch {
            slot.rejected_records +|= 1;
        };
        const family = @import("console_protocol").client_family;
        // Labels outside the shared numbering count as unknown rather than being dropped.
        const os: usize = if (record.os < slot.families.os.len) record.os else 0;
        const browser: usize =
            if (record.browser < slot.families.browser.len) record.browser else 0;
        slot.families.os[os] +|= 1;
        slot.families.browser[browser] +|= 1;
        slot.families.status[family.statusSlot(record.status)] +|= 1;
    }

    /// Copies straight into the caller's storage: a `Minute` is tens of kilobytes, and a
    /// returned value can be duplicated per frame on a bounded thread stack.
    pub fn snapshot(self: *const Rankings, second: u64, out: *Minute) void {
        const minute = second / 60;
        const slot = &self.minutes[minute % self.minutes.len];
        if (slot.minute == minute) out.* = slot.* else out.* = .{ .minute = minute };
    }
};

fn sampled(rankings: *const Rankings, second: u64) u64 {
    var minute: Minute = undefined;
    rankings.snapshot(second, &minute);
    return minute.paths.samples;
}

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
    try t.expectEqual(@as(u64, 0), sampled(&rankings, 119));
    try t.expectEqual(@as(u64, 1), sampled(&rankings, 120));
    try t.expectEqual(@as(u64, 1), sampled(&rankings, 180));
    try t.expectEqual(@as(u64, 0), sampled(&rankings, 240));
}

test "families and referring hosts are counted beside paths within the same minute" {
    const t = std.testing;
    var rankings: Rankings = .{};
    var record = std.mem.zeroes(Record);
    record.second = 120;
    record.path_len = 1;
    record.path[0] = '/';
    record.status = 429;
    const family = @import("console_protocol").client_family;
    record.os = @intFromEnum(family.Os.linux);
    record.browser = @intFromEnum(family.Browser.firefox);
    const host = "news.example.test";
    @memcpy(record.referer[0..host.len], host);
    record.referer_len = host.len;
    rankings.add(&record);
    record.referer_len = 0;
    rankings.add(&record);
    var minute: Minute = undefined;
    rankings.snapshot(120, &minute);
    try t.expectEqual(@as(u64, 2), minute.families.os[@intFromEnum(family.Os.linux)]);
    try t.expectEqual(@as(u64, 2), minute.families.browser[@intFromEnum(family.Browser.firefox)]);
    try t.expectEqual(@as(u64, 2), minute.families.status[family.statusSlot(429)]);
    try t.expectEqual(@as(u64, 1), minute.referrers.samples);
    try t.expectEqualStrings(host, minute.referrers.counters[0].key.slice());
}
