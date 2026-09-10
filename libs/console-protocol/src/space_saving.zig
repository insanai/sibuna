//! Bounded sample-frequency summaries; never used by request producers.
//! Merge follows Cafaro et al., arXiv:1401.0702, Algorithms 3 and 4 (SID 0007).
const std = @import("std");
const p = @import("root.zig");

pub const Summary = Sketch(256, 128);

pub fn Sketch(comptime capacity: usize, comptime key_bytes: usize) type {
    std.debug.assert(capacity > 0 and capacity <= 256);
    return struct {
        const Self = @This();
        pub const Error = error{ TooLarge, Overflow };
        pub const Counter = struct {
            key: p.Bytes(key_bytes) = .{},
            estimate: u64 = 0,
            error_bound: u64 = 0,
        };
        counters: [capacity]Counter = @splat(.{}),
        len: usize = 0,
        samples: u64 = 0,

        /// Input is already normalized by the collector. Oversize keys are rejected, not
        /// silently truncated or hashed: callers must explicitly account for truncation.
        pub fn add(self: *Self, key: []const u8) Error!void {
            if (key.len > key_bytes) return error.TooLarge;
            if (self.samples == std.math.maxInt(u64)) return error.Overflow;
            if (self.find(key)) |index| {
                self.counters[index].estimate += 1;
            } else {
                const index = if (self.len < capacity) self.len else self.minimumIndex();
                const previous = self.counters[index].estimate;
                self.counters[index] = .{
                    .key = try p.Bytes(key_bytes).init(key),
                    .estimate = previous + 1,
                    .error_bound = previous,
                };
                self.len = @min(self.len + 1, capacity);
            }
            self.samples += 1;
        }

        pub fn find(self: *const Self, key: []const u8) ?usize {
            for (self.counters[0..self.len], 0..) |*counter, index| {
                if (std.mem.eql(u8, key, counter.key.slice())) return index;
            }
            return null;
        }

        /// The frequency of an untracked key cannot exceed this value.
        pub fn missingBound(self: *const Self) u64 {
            return if (self.len < capacity) 0 else self.counters[self.minimumIndex()].estimate;
        }

        fn minimumIndex(self: *const Self) usize {
            std.debug.assert(self.len != 0);
            var index: usize = 0;
            for (self.counters[0..self.len], 0..) |counter, i| {
                if (counter.estimate < self.counters[index].estimate) index = i;
            }
            return index;
        }

        /// Merge disjoint sample populations only. The caller owns interval/node/boot
        /// deduplication and probability/loss metadata; this primitive cannot infer them.
        /// Both inputs remain unchanged, including when total samples would overflow.
        pub fn merge(a: *const Self, b: *const Self) Error!Self {
            var result: Self = undefined;
            var candidates: [2 * capacity]Counter = undefined;
            try mergeInto(&result, a, b, &candidates);
            return result;
        }

        /// Scratch is caller-owned so bounded Wasm event arenas can avoid large stack frames.
        pub fn mergeInto(
            output: *Self,
            a: *const Self,
            b: *const Self,
            candidates: *[2 * capacity]Counter,
        ) Error!void {
            return mergeSummaries(Self, output, a, b, candidates);
        }

        /// Stable bytewise tie order makes repeated exports and merge direction deterministic.
        pub fn before(_: void, a: Counter, b: Counter) bool {
            if (a.estimate != b.estimate) return a.estimate > b.estimate;
            return std.mem.order(u8, a.key.slice(), b.key.slice()) == .lt;
        }
    };
}

fn mergeSummaries(
    comptime S: type,
    output: *S,
    a: *const S,
    b: *const S,
    candidates: *[2 * a.counters.len]S.Counter,
) S.Error!void {
    const Counter = S.Counter;
    const samples = std.math.add(u64, a.samples, b.samples) catch return error.Overflow;
    var count: usize = 0;
    const a_missing = a.missingBound();
    const b_missing = b.missingBound();
    for (a.counters[0..a.len]) |counter| {
        const other = if (b.find(counter.key.slice())) |i| b.counters[i] else Counter{
            .estimate = b_missing,
            .error_bound = b_missing,
        };
        candidates[count] = .{
            .key = counter.key,
            .estimate = counter.estimate + other.estimate,
            .error_bound = counter.error_bound + other.error_bound,
        };
        count += 1;
    }
    for (b.counters[0..b.len]) |counter| {
        if (a.find(counter.key.slice()) != null) continue;
        candidates[count] = .{
            .key = counter.key,
            .estimate = counter.estimate + a_missing,
            .error_bound = counter.error_bound + a_missing,
        };
        count += 1;
    }
    std.mem.sort(Counter, candidates[0..count], {}, S.before);
    output.* = .{ .samples = samples, .len = @min(count, a.counters.len) };
    @memcpy(output.counters[0..output.len], candidates[0..output.len]);
}

test "merged sketches bound every frequency through repeated disjoint window merges" {
    const S = Sketch(8, 2);
    var random = std.Random.DefaultPrng.init(0x51707);
    var all: [32]u64 = @splat(0);
    var merged: S = .{};
    for (0..30) |window| {
        var local: S = .{};
        var counts: [32]u64 = @splat(0);
        for (0..200) |i| {
            const key: u8 = if (i % 3 == 0) 0 else random.random().uintLessThan(u8, 32);
            try local.add(&.{key});
            counts[key] += 1;
            all[key] += 1;
        }
        try checkBounds(S, &local, &counts);
        const reverse = try S.merge(&local, &merged);
        merged = try S.merge(&merged, &local);
        try std.testing.expectEqualDeep(reverse, merged);
        try std.testing.expectEqual(@as(u64, (window + 1) * 200), merged.samples);
        try checkBounds(S, &merged, &all);
    }
}

fn checkBounds(comptime S: type, summary: *const S, counts: []const u64) !void {
    const t = std.testing;
    const bound = summary.samples / summary.counters.len;
    try t.expect(summary.missingBound() <= bound);
    for (counts, 0..) |actual, key| {
        if (summary.find(&.{@intCast(key)})) |index| {
            const counter = summary.counters[index];
            try t.expect(counter.estimate >= actual);
            try t.expect(counter.estimate - counter.error_bound <= actual);
            try t.expect(counter.error_bound <= bound);
        } else {
            try t.expect(actual <= summary.missingBound());
        }
    }
}

test "retaining complete local summaries preserves a global winner below local top one" {
    const S = Sketch(4, 8);
    var a: S = .{};
    var b: S = .{};
    for (0..10) |_| {
        try a.add("local-a");
        try b.add("local-b");
    }
    for (0..9) |_| {
        try a.add("global");
        try b.add("global");
    }
    const merged = try S.merge(&a, &b);
    try std.testing.expectEqualStrings("global", merged.counters[0].key.slice());
    try std.testing.expectEqual(@as(u64, 18), merged.counters[0].estimate);
    try std.testing.expectEqual(@as(u64, 0), merged.counters[0].error_bound);
    const previous = a;
    try std.testing.expectError(error.TooLarge, a.add("oversized"));
    try std.testing.expectEqualDeep(previous, a);
    var full: S = .{ .samples = std.math.maxInt(u64) };
    try std.testing.expectError(error.Overflow, full.add("x"));
    try std.testing.expectError(error.Overflow, S.merge(&full, &a));
}
