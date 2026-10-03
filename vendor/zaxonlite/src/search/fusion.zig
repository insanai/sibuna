//! Fusion formulas for hybrid search (ZDS 0009): weighted reciprocal rank
//! fusion, distribution-based score fusion, and the Welford state behind
//! the sample standard deviation window function. Pure numeric contracts;
//! the SQLite adapter lives in `sqlite/search_extension.zig`.

const std = @import("std");

pub const FusionError = error{
    InvalidRank,
    InvalidK,
    InvalidWeight,
    InvalidScore,
    InvalidStddev,
};

/// Default RRF rank constant.
pub const default_rrf_k: f64 = 60.0;
/// Default retriever weight for both fusions.
pub const default_weight: f64 = 1.0;

/// Weighted reciprocal rank contribution `w / (k + r)` for a one-based
/// rank `r`. Rank must be positive, `k` finite and positive, and the
/// weight finite and nonnegative.
pub fn rrf(rank: i64, k: f64, weight: f64) FusionError!f64 {
    if (rank < 1) return error.InvalidRank;
    if (!std.math.isFinite(k) or k <= 0) return error.InvalidK;
    if (!std.math.isFinite(weight) or weight < 0) return error.InvalidWeight;
    return weight / (k + @as(f64, @floatFromInt(rank)));
}

/// Distribution-based score contribution `w * (0.5 + (s - mu) / (6 sigma))`,
/// the mean +- 3 sigma normalization. A zero deviation (singleton or
/// constant score set) yields the neutral `0.5 * w`. Values are
/// deliberately not clipped.
pub fn dbsf(score: f64, mean: f64, stddev: f64, weight: f64) FusionError!f64 {
    if (!std.math.isFinite(score) or !std.math.isFinite(mean)) {
        return error.InvalidScore;
    }
    if (!std.math.isFinite(stddev) or stddev < 0) return error.InvalidStddev;
    if (!std.math.isFinite(weight) or weight < 0) return error.InvalidWeight;
    if (stddev == 0) return 0.5 * weight;
    return weight * (0.5 + (score - mean) / (6.0 * stddev));
}

/// Welford online mean/variance state: exactly the 24 bytes the SQLite
/// aggregate context allocates. All-zero bytes are a valid empty state
/// because SQLite zero-initializes that allocation.
pub const Welford = extern struct {
    count: u64 = 0,
    mean: f64 = 0,
    m2: f64 = 0,

    comptime {
        std.debug.assert(@sizeOf(Welford) == 24);
    }

    pub fn step(self: *Welford, x: f64) void {
        self.count += 1;
        const delta = x - self.mean;
        self.mean += delta / @as(f64, @floatFromInt(self.count));
        self.m2 += delta * (x - self.mean);
    }

    /// Removes one previously stepped value (sliding window frames). Tiny
    /// negative `m2` from floating-point cancellation is clamped to zero;
    /// a materially negative `m2` reports state corruption.
    pub fn inverse(self: *Welford, x: f64) error{InternalState}!void {
        if (self.count == 0) return error.InternalState;
        if (self.count == 1) {
            self.* = .{};
            return;
        }
        const remaining = @as(f64, @floatFromInt(self.count - 1));
        const delta = x - self.mean;
        const new_mean = self.mean - delta / remaining;
        self.m2 -= (x - new_mean) * delta;
        self.mean = new_mean;
        self.count -= 1;
        if (self.m2 < 0) {
            const tolerance = 1e-8 * @max(1.0, x * x);
            if (self.m2 < -tolerance) return error.InternalState;
            self.m2 = 0;
        }
    }

    /// Sample standard deviation: null for an empty set and zero for a
    /// singleton, so `dbsf` applies its neutral rule.
    pub fn sampleStddev(self: *const Welford) ?f64 {
        if (self.count == 0) return null;
        if (self.count == 1) return 0;
        return @sqrt(self.m2 / @as(f64, @floatFromInt(self.count - 1)));
    }
};

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

const testing = std.testing;

test "rrf matches the contract table" {
    // Defaults: k = 60, w = 1.
    try testing.expectApproxEqAbs(
        @as(f64, 1.0 / 61.0),
        try rrf(1, default_rrf_k, default_weight),
        1e-15,
    );
    try testing.expectApproxEqAbs(
        @as(f64, 1.0 / 160.0),
        try rrf(100, default_rrf_k, default_weight),
        1e-15,
    );
    // Weight scales linearly; zero weight contributes zero.
    try testing.expectApproxEqAbs(
        @as(f64, 2.0 / 61.0),
        try rrf(1, 60, 2.0),
        1e-15,
    );
    try testing.expectEqual(@as(f64, 0), try rrf(7, 60, 0));
    // Equal ranks tie exactly.
    try testing.expectEqual(try rrf(3, 60, 1), try rrf(3, 60, 1));
}

test "rrf rejects contract violations" {
    try testing.expectError(error.InvalidRank, rrf(0, 60, 1));
    try testing.expectError(error.InvalidRank, rrf(-5, 60, 1));
    try testing.expectError(error.InvalidK, rrf(1, 0, 1));
    try testing.expectError(error.InvalidK, rrf(1, -60, 1));
    try testing.expectError(error.InvalidK, rrf(1, std.math.nan(f64), 1));
    try testing.expectError(error.InvalidK, rrf(1, std.math.inf(f64), 1));
    try testing.expectError(error.InvalidWeight, rrf(1, 60, -1));
    try testing.expectError(error.InvalidWeight, rrf(1, 60, std.math.nan(f64)));
}

test "dbsf normalizes around the mean" {
    // Score at the mean contributes exactly 0.5 * weight.
    try testing.expectApproxEqAbs(@as(f64, 0.5), try dbsf(5, 5, 2, 1), 1e-15);
    // Mean + 3 sigma maps to 1, mean - 3 sigma maps to 0.
    try testing.expectApproxEqAbs(@as(f64, 1.0), try dbsf(11, 5, 2, 1), 1e-15);
    try testing.expectApproxEqAbs(@as(f64, 0.0), try dbsf(-1, 5, 2, 1), 1e-15);
    // Outliers are deliberately not clipped.
    try testing.expect(try dbsf(20, 5, 2, 1) > 1.0);
    // Weight scales the whole contribution.
    try testing.expectApproxEqAbs(@as(f64, 1.5), try dbsf(5, 5, 2, 3), 1e-15);
}

test "dbsf neutral rule and contract violations" {
    // Zero deviation: every row gets the neutral 0.5 * weight.
    try testing.expectApproxEqAbs(@as(f64, 0.5), try dbsf(7, 7, 0, 1), 1e-15);
    try testing.expectApproxEqAbs(@as(f64, 2.0), try dbsf(7, 7, 0, 4), 1e-15);
    try testing.expectError(error.InvalidScore, dbsf(std.math.nan(f64), 0, 1, 1));
    try testing.expectError(error.InvalidScore, dbsf(0, std.math.inf(f64), 1, 1));
    try testing.expectError(error.InvalidStddev, dbsf(0, 0, -1, 1));
    try testing.expectError(error.InvalidStddev, dbsf(0, 0, std.math.nan(f64), 1));
    try testing.expectError(error.InvalidWeight, dbsf(0, 0, 1, -2));
}

test "welford matches a known distribution" {
    const values = [_]f64{ 2, 4, 4, 4, 5, 5, 7, 9 };
    var state = Welford{};
    for (values) |x| state.step(x);
    try testing.expectEqual(@as(u64, 8), state.count);
    try testing.expectApproxEqAbs(@as(f64, 5.0), state.mean, 1e-12);
    // Sum of squared deviations is 32; sample variance is 32 / 7.
    try testing.expectApproxEqAbs(
        @sqrt(@as(f64, 32.0 / 7.0)),
        state.sampleStddev().?,
        1e-12,
    );
}

test "welford empty and singleton follow the dbsf neutral rule" {
    var state = Welford{};
    try testing.expectEqual(@as(?f64, null), state.sampleStddev());
    state.step(42.5);
    try testing.expectEqual(@as(?f64, 0), state.sampleStddev());
    // Removing the only value returns to the empty state.
    try state.inverse(42.5);
    try testing.expectEqual(@as(?f64, null), state.sampleStddev());
    try testing.expectError(error.InternalState, state.inverse(1.0));
}

test "welford sliding window stays consistent with recomputation" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const random = prng.random();
    var values: [256]f64 = undefined;
    for (&values) |*x| x.* = random.floatNorm(f64) * 100.0 + 50.0;

    const window = 16;
    var state = Welford{};
    for (values, 0..) |x, i| {
        state.step(x);
        if (i >= window) try state.inverse(values[i - window]);
        if (i >= window - 1) {
            // Recompute the window from scratch and compare.
            var fresh = Welford{};
            const start = i + 1 - window;
            for (values[start .. i + 1]) |w| fresh.step(w);
            try testing.expectApproxEqAbs(fresh.mean, state.mean, 1e-6);
            try testing.expectApproxEqAbs(
                fresh.sampleStddev().?,
                state.sampleStddev().?,
                1e-6,
            );
        }
    }
}
