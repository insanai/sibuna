//! Pure series statistics behind the write benchmark's periodicity
//! instrument, compiled as its own test artifact so an instrument
//! regression fails `zig build test` deterministically. Imported by the
//! benchmark alone; deliberately not part of the library surface.

const std = @import("std");

/// Biased lag autocorrelation of a time-ordered series: the numerator
/// sums `n - lag` products against a full-series denominator, so a
/// series holding an integer number of aligned, identical periods at
/// `lag` yields exactly `(n - lag) / n` rather than 1.0 (a partial
/// final period shifts that ratio, since the omitted tail need not
/// carry a proportional share of the centered energy). Zero for a
/// constant series or an out-of-range lag.
pub fn autocorrelation(samples: []const u64, lag: usize) f64 {
    if (lag == 0 or lag >= samples.len) return 0;
    var mean: f64 = 0;
    for (samples) |sample| mean += @floatFromInt(sample);
    mean /= @floatFromInt(samples.len);
    var denominator: f64 = 0;
    for (samples) |sample| {
        const centered = @as(f64, @floatFromInt(sample)) - mean;
        denominator += centered * centered;
    }
    if (denominator == 0) return 0;
    var numerator: f64 = 0;
    for (samples[0 .. samples.len - lag], samples[lag..]) |early, late| {
        numerator += (@as(f64, @floatFromInt(early)) - mean) *
            (@as(f64, @floatFromInt(late)) - mean);
    }
    return numerator / denominator;
}

/// The paired-shift estimate plus its honesty counters: how many
/// anchors found a plain partner and how many were dropped for lacking
/// one within the search window.
pub const ShiftResult = struct {
    shift: u64,
    paired: usize,
    dropped: usize,
};

/// Median of the per-anchor paired deltas over every anchor: each
/// anchor-bearing iteration minus the nearest preceding iteration that
/// carried no anchor at all (walking back at most eight slots, so a
/// natural anchor in the adjacent slot cannot poison the pair; an
/// anchor with no plain partner in that window is counted dropped).
/// `scratch` must hold at least one slot per anchor, so the median is
/// exact, never truncated to a prefix of the run. The metric is a
/// deliberately nonnegative, zero-censored "added cost": a noisy pair
/// where the plain iteration was slower contributes zero rather than a
/// negative cost.
pub fn pairedAnchorShift(
    scratch: []u64,
    intervals: []const u64,
    anchored: []const bool,
) ShiftResult {
    std.debug.assert(intervals.len == anchored.len);
    var count: usize = 0;
    var dropped: usize = 0;
    for (anchored, 0..) |is_anchor, index| {
        if (!is_anchor) continue;
        const pair = pairIndex(anchored, index) orelse {
            dropped += 1;
            continue;
        };
        scratch[count] = intervals[index] -| intervals[pair];
        count += 1;
    }
    if (count == 0) return .{ .shift = 0, .paired = 0, .dropped = dropped };
    std.mem.sort(u64, scratch[0..count], {}, std.sort.asc(u64));
    return .{
        .shift = scratch[count / 2],
        .paired = count,
        .dropped = dropped,
    };
}

/// The nearest preceding non-anchored iteration within a short window,
/// or null when anchors crowd out every candidate.
fn pairIndex(anchored: []const bool, index: usize) ?usize {
    var back: usize = 1;
    while (back <= 8 and back <= index) : (back += 1) {
        if (!anchored[index - back]) return index - back;
    }
    return null;
}

test "paired shift is the exact median of every anchor delta" {
    const intervals = [_]u64{ 100, 100, 900, 100, 100, 400, 100, 100, 250 };
    const anchored = [_]bool{
        false, false, true, false, false, true, false, false, true,
    };
    var scratch: [3]u64 = undefined;
    // Deltas: 800, 300, 150; the median is 300, with no drops.
    const result = pairedAnchorShift(&scratch, &intervals, &anchored);
    try std.testing.expectEqual(@as(u64, 300), result.shift);
    try std.testing.expectEqual(@as(usize, 3), result.paired);
    try std.testing.expectEqual(@as(usize, 0), result.dropped);
}

test "a slower plain neighbor censors that pair at zero" {
    const intervals = [_]u64{ 500, 100, 500, 90 };
    const anchored = [_]bool{ false, true, false, true };
    var scratch: [2]u64 = undefined;
    // Deltas censor to 0 and 0; the metric never goes negative.
    const result = pairedAnchorShift(&scratch, &intervals, &anchored);
    try std.testing.expectEqual(@as(u64, 0), result.shift);
}

test "an even number of anchors takes the upper median" {
    const intervals = [_]u64{ 100, 300, 100, 700 };
    const anchored = [_]bool{ false, true, false, true };
    var scratch: [2]u64 = undefined;
    // Deltas: 200 and 600; count/2 selects the upper median, 600.
    const result = pairedAnchorShift(&scratch, &intervals, &anchored);
    try std.testing.expectEqual(@as(u64, 600), result.shift);
}

test "a natural anchor in the adjacent slot is skipped when pairing" {
    const intervals = [_]u64{ 100, 800, 900, 100 };
    const anchored = [_]bool{ false, true, true, false };
    var scratch: [2]u64 = undefined;
    // The second anchor pairs with index 0, not the anchored index 1.
    const result = pairedAnchorShift(&scratch, &intervals, &anchored);
    try std.testing.expectEqual(@as(u64, 800), result.shift);
    try std.testing.expectEqual(@as(usize, 2), result.paired);
}

test "an anchor with no plain partner in the window is counted dropped" {
    var intervals: [10]u64 = @splat(100);
    var anchored: [10]bool = @splat(true);
    anchored[0] = false;
    intervals[9] = 700;
    var scratch: [9]u64 = undefined;
    // Only anchors within eight slots of index 0 can pair; the rest drop.
    const result = pairedAnchorShift(&scratch, &intervals, &anchored);
    try std.testing.expectEqual(@as(usize, 8), result.paired);
    try std.testing.expectEqual(@as(usize, 1), result.dropped);
}

test "empty and anchorless series report zero shift" {
    var scratch: [1]u64 = undefined;
    const empty = pairedAnchorShift(scratch[0..0], &.{}, &.{});
    try std.testing.expectEqual(@as(u64, 0), empty.shift);
    const intervals = [_]u64{ 100, 200 };
    const anchored = [_]bool{ false, false };
    const none = pairedAnchorShift(&scratch, &intervals, &anchored);
    try std.testing.expectEqual(@as(u64, 0), none.shift);
}

test "sixty-five anchors keep an exact, untruncated median" {
    // Thirty-two large deltas arrive first, then thirty-three small
    // ones: the full-set median is the small value, while any
    // truncation to the first sixty-four pairs would report the large
    // one. This is the boundary a fixed-size delta buffer once broke.
    var intervals: [130]u64 = undefined;
    var anchored: [130]bool = undefined;
    for (0..65) |pair| {
        intervals[pair * 2] = 100;
        anchored[pair * 2] = false;
        intervals[pair * 2 + 1] = if (pair < 32) 1100 else 110;
        anchored[pair * 2 + 1] = true;
    }
    var scratch: [65]u64 = undefined;
    const result = pairedAnchorShift(&scratch, &intervals, &anchored);
    try std.testing.expectEqual(@as(usize, 65), result.paired);
    try std.testing.expectEqual(@as(usize, 0), result.dropped);
    try std.testing.expectEqual(@as(u64, 10), result.shift);
}

test "autocorrelation matches the biased estimator on a periodic signal" {
    var series: [64]u64 = undefined;
    for (&series, 0..) |*value, index| {
        value.* = if (index % 8 == 0) 1000 else 100;
    }
    // A perfect lag-8 repetition over 64 samples yields (64 - 8) / 64.
    const r = autocorrelation(&series, 8);
    try std.testing.expect(std.math.approxEqAbs(f64, r, 0.875, 0.01));
    try std.testing.expect(@abs(autocorrelation(&series, 5)) < 0.2);
    const flat = @as([16]u64, @splat(7));
    try std.testing.expectEqual(@as(f64, 0), autocorrelation(&flat, 4));
}
