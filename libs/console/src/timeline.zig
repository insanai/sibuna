//! One collector owns updates. Callers hold the Stats mutex when copying bounded pages.
const std = @import("std");
const p = @import("console_protocol").timeline;
const Totals = @import("store").telemetry.Totals;
const Observation = struct { utc: u64, ms: u64, counts: Totals };

pub const Timeline = struct {
    // Never read an undefined slot before checking its presence and retained sequence.
    slots: [p.capacity]p.Bucket = undefined,
    present: [p.capacity]bool = @splat(false),
    previous: ?Observation = null,
    epoch: u32 = 1,
    discarded: u64 = 0,

    pub fn observe(self: *Timeline, utc: u64, ms: u64, totals: Totals) void {
        const next: Observation = .{ .utc = utc, .ms = ms, .counts = totals };
        const previous = self.previous orelse {
            self.previous = next;
            return;
        };
        // Do not advance a zero-duration baseline: the next timed interval owns those counts.
        if (ms == previous.ms and utc == previous.utc) return;
        self.previous = next;
        const counts = delta(previous.counts, totals) orelse {
            self.reset();
            return;
        };
        if (ms <= previous.ms or utc < previous.utc) {
            self.reset();
            return;
        }
        const elapsed = ms - previous.ms;
        const clock_gap = utc - previous.utc > elapsed / 1000 + 1;
        const sequence = ms / 1000;
        const index = sequence % p.capacity;
        const bucket = &self.slots[index];
        if (!self.present[index] or bucket.sequence != sequence) {
            bucket.* = .{
                .sequence = sequence,
                .utc_start = previous.utc,
                .start_ms = previous.ms,
            };
            self.present[index] = true;
        }
        bucket.utc_end = utc;
        bucket.end_ms = ms;
        bucket.observed_ms += elapsed;
        bucket.observations +|= 1;
        bucket.gap = bucket.gap or elapsed > 1000 or clock_gap;
        inline for (@typeInfo(p.Counts).@"struct".fields) |field|
            @field(bucket.counts, field.name) += @field(counts, field.name);
    }

    fn reset(self: *Timeline) void {
        @memset(&self.present, false);
        self.epoch +|= 1;
        self.discarded +|= 1;
    }

    pub fn page(
        self: *const Timeline,
        query: p.Query,
        node: u32,
        boot: []const u8,
        output: []p.Bucket,
    ) error{ InvalidRequest, Conflict }!p.Page {
        if (query.limit == 0 or query.limit > p.max_rows or output.len < query.limit)
            return error.InvalidRequest;
        if ((query.before != null) != (query.epoch != null) or
            (query.before != null) != (query.boot != null)) return error.InvalidRequest;
        if (query.epoch) |epoch| {
            if (epoch != self.epoch or !std.mem.eql(u8, query.boot.?, boot)) return error.Conflict;
        }
        const ms = if (self.previous) |value| value.ms else 0;
        const newest = ms / 1000;
        const floor = newest -| (p.capacity - 1);
        var sequence = @min(newest + 1, query.before orelse (newest + 1));
        var count: usize = 0;
        var oldest: ?u64 = null;
        var next_before: ?u64 = null;
        // At most 3,600 probes, independent of a caller's cursor magnitude or clock gap.
        for (0..p.capacity) |offset| {
            if (offset > newest) break;
            const retained = newest - offset;
            if (self.has(retained)) oldest = retained;
        }
        while (sequence > floor) {
            sequence -= 1;
            if (!self.has(sequence)) continue;
            if (count == query.limit) {
                next_before = output[count - 1].sequence;
                break;
            }
            output[count] = self.slots[sequence % p.capacity];
            output[count].partial = sequence == newest;
            count += 1;
        }
        return .{
            .node = node,
            .boot = boot,
            .epoch = self.epoch,
            .as_of_ms = ms,
            .discarded_intervals = self.discarded,
            .oldest_sequence = oldest,
            .next_before = next_before,
            .rows = output[0..count],
        };
    }

    fn has(self: *const Timeline, sequence: u64) bool {
        const index = sequence % p.capacity;
        return self.present[index] and self.slots[index].sequence == sequence;
    }
};

fn delta(previous: Totals, next: Totals) ?p.Counts {
    var result: p.Counts = .{};
    inline for (@typeInfo(p.Counts).@"struct".fields) |field| {
        const before = @field(previous, field.name);
        const after = @field(next, field.name);
        if (after < before) return null;
        @field(result, field.name) = after - before;
    }
    return result;
}
