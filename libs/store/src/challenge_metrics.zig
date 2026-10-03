//! Console-only observations, owned by the console collector. Producers use only fixed
//! counters; authenticated challenge parameters select bins, never client metadata.
const std = @import("std");
const Counter = std.atomic.Value(u64);
pub const Algorithm = enum(u1) { hashcash, posw };
pub const Cause = enum {
    address_banned,
    body_too_large,
    missing_id,
    malformed_solution,
    malformed_challenge,
    invalid_tag,
    expired,
    fingerprint_mismatch,
    difficulty_not_met,
    invalid_proof,
    wrong_solution_type,
    replay,
    capacity,
};
pub const cause_count = @typeInfo(Cause).@"enum".field_names.len;
pub const bin_count = 256;
pub const Timing = union(enum) { missing, invalid, milliseconds: f64 };
pub const Solver = enum { unknown, wasm, javascript };
pub const Bin = struct {
    issued: Counter = .init(0),
    accepted: Counter = .init(0),
    buckets: [16]Counter = @splat(.init(0)),
    missing: Counter = .init(0),
    invalid: Counter = .init(0),
    wasm: Counter = .init(0),
    javascript: Counter = .init(0),
    unknown_solver: Counter = .init(0),
};
pub const Metrics = struct {
    submitted: Counter = .init(0),
    causes: [cause_count]Counter = @splat(.init(0)),
    bins: [bin_count]Bin = @splat(.{}),
    last_parameters: std.atomic.Value(u32) = .init(0),

    pub fn issue(self: *Metrics, algorithm: Algorithm, parameter: u8, openings: u8) void {
        _ = self.bins[index(algorithm, parameter, openings)].issued.fetchAdd(1, .monotonic);
        const encoded = @as(u32, @backingInt(algorithm)) | (@as(u32, parameter) << 8) |
            (@as(u32, openings) << 16) | (1 << 24);
        self.last_parameters.store(encoded, .monotonic);
    }

    pub fn reject(self: *Metrics, cause: Cause) void {
        _ = self.causes[@backingInt(cause)].fetchAdd(1, .monotonic);
    }

    pub fn accept(
        self: *Metrics,
        algorithm: Algorithm,
        parameter: u8,
        openings: u8,
        timing: Timing,
        solver: Solver,
    ) void {
        const bin = &self.bins[index(algorithm, parameter, openings)];
        switch (timing) {
            .missing => _ = bin.missing.fetchAdd(1, .monotonic),
            .invalid => _ = bin.invalid.fetchAdd(1, .monotonic),
            .milliseconds => |ms| {
                if (!std.math.isFinite(ms) or ms < 0 or ms > 3600000) {
                    _ = bin.invalid.fetchAdd(1, .monotonic);
                } else _ = bin.buckets[bucket(ms)].fetchAdd(1, .monotonic);
            },
        }
        const counter = switch (solver) {
            .wasm => &bin.wasm,
            .javascript => &bin.javascript,
            .unknown => &bin.unknown_solver,
        };
        _ = counter.fetchAdd(1, .monotonic);
        _ = bin.accepted.fetchAdd(1, .monotonic);
    }
};

/// 32 parameter bins of width eight, and four opening-count bins of width sixteen.
/// Hashcash has no openings and always uses opening bin zero; the last bin is saturated.
pub fn index(algorithm: Algorithm, parameter: u8, openings: u8) usize {
    const opening: usize = if (algorithm == .hashcash) 0 else @min(openings / 16, 3);
    return @as(usize, @backingInt(algorithm)) * 128 + @as(usize, parameter / 8) * 4 + opening;
}

pub fn bucket(ms: f64) usize {
    std.debug.assert(std.math.isFinite(ms) and ms >= 0);
    var result: usize = 0;
    var boundary: f64 = 1;
    while (result < 15 and ms >= boundary) : (result += 1) boundary *= 2;
    return result;
}

test "client timing partitions parameters and covers every histogram boundary" {
    try std.testing.expectEqual(@as(usize, 0), bucket(0.5));
    var boundary: f64 = 1;
    for (1..16) |expected| {
        try std.testing.expectEqual(expected, bucket(boundary));
        boundary *= 2;
    }
    try std.testing.expectEqual(@as(usize, 15), bucket(3600000));
    var metrics: Metrics = .{};
    metrics.accept(.posw, 13, 16, .{ .milliseconds = 8 }, .wasm);
    metrics.accept(.posw, 13, 16, .{ .milliseconds = std.math.nan(f64) }, .unknown);
    metrics.accept(.posw, 13, 16, .missing, .javascript);
    const bin = &metrics.bins[index(.posw, 13, 16)];
    try std.testing.expectEqual(@as(u64, 1), bin.buckets[4].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), bin.invalid.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), bin.missing.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 3), bin.accepted.load(.monotonic));
    try std.testing.expect(index(.hashcash, 13, 0) != index(.posw, 13, 16));
}
