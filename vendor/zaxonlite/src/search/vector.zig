//! Vector distance kernels (ZDS 0009): exact float32 cosine distance with
//! a portable 128-bit SIMD implementation and an always-compiled scalar
//! reference kernel. The backend is decided by the resolved compile
//! target, never a runtime CPU probe, so an artifact can only contain
//! instructions its target guarantees.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.target.cpu.arch.endian() == .big) {
        @compileError(
            "zaxon_search vectors are little-endian float32 BLOBs; " ++
                "big-endian targets are rejected until a canonical " ++
                "cross-endian representation exists (ZDS 0009)",
        );
    }
}

pub const Backend = enum {
    neon128,
    sse128,
    wasm128,
    scalar,

    pub fn name(self: Backend) [:0]const u8 {
        return switch (self) {
            .neon128 => "neon128",
            .sse128 => "sse128",
            .wasm128 => "wasm128",
            .scalar => "scalar",
        };
    }
};

/// The SIMD backend compiled into this artifact. 128-bit lanes only:
/// Advanced SIMD is architectural on AArch64 and SSE is baseline x86-64;
/// everything else must prove the feature in its resolved target or fall
/// back to the scalar kernel.
pub const backend: Backend = pick: {
    const cpu = builtin.target.cpu;
    break :pick switch (cpu.arch) {
        .aarch64 => .neon128,
        .x86_64 => .sse128,
        .x86 => if (cpu.has(.x86, .sse2)) .sse128 else .scalar,
        .arm, .thumb => if (cpu.has(.arm, .neon)) .neon128 else .scalar,
        .wasm32, .wasm64 => if (cpu.has(.wasm, .simd128)) .wasm128 else .scalar,
        else => .scalar,
    };
};

pub const VectorError = error{
    LengthMismatch,
    EmptyVector,
    MalformedBlob,
    NonFinite,
    ZeroMagnitude,
};

/// Validates a float32 BLOB pair and returns the shared dimension count.
fn validate(a: []const u8, b: []const u8) VectorError!usize {
    if (a.len != b.len) return error.LengthMismatch;
    if (a.len == 0) return error.EmptyVector;
    if (a.len % 4 != 0) return error.MalformedBlob;
    return a.len / 4;
}

/// Cosine distance `1 - dot / sqrt(|a|^2 |b|^2)` over raw float32 BLOBs,
/// dispatched to the compiled backend. SQLite blob pointers carry no
/// alignment promise, so all loads are byte-aligned.
pub fn cosineDistanceBytes(a: []const u8, b: []const u8) VectorError!f64 {
    return switch (backend) {
        .scalar => cosineDistanceScalar(a, b),
        else => cosineDistanceSimd(a, b),
    };
}

/// The scalar reference kernel: f64 accumulation in element order. Always
/// compiled; callers needing a canonical audit result select it directly.
pub fn cosineDistanceScalar(a_bytes: []const u8, b_bytes: []const u8) VectorError!f64 {
    const dims = try validate(a_bytes, b_bytes);
    const a = std.mem.bytesAsSlice(f32, a_bytes);
    const b = std.mem.bytesAsSlice(f32, b_bytes);
    var dot: f64 = 0;
    var mag_a: f64 = 0;
    var mag_b: f64 = 0;
    for (0..dims) |i| {
        const x: f64 = a[i];
        const y: f64 = b[i];
        dot += x * y;
        mag_a += x * x;
        mag_b += y * y;
    }
    return finish(dot, mag_a, mag_b);
}

/// The 128-bit SIMD kernel: four-way unrolled `@Vector(4, f32)` with
/// twelve accumulation vectors (dot, |a|^2, |b|^2 times four), sixteen
/// dimensions per iteration, a fixed horizontal reduction order, and a
/// scalar f64 tail. No fused multiply-add: NEON, SSE, and wasm simd128
/// share one arithmetic graph (ZDS 0009).
pub fn cosineDistanceSimd(a_bytes: []const u8, b_bytes: []const u8) VectorError!f64 {
    const dims = try validate(a_bytes, b_bytes);
    const a = std.mem.bytesAsSlice(f32, a_bytes);
    const b = std.mem.bytesAsSlice(f32, b_bytes);

    const zero: @Vector(4, f32) = @splat(0);
    var dot = [_]@Vector(4, f32){ zero, zero, zero, zero };
    var mag_a = [_]@Vector(4, f32){ zero, zero, zero, zero };
    var mag_b = [_]@Vector(4, f32){ zero, zero, zero, zero };

    var i: usize = 0;
    while (i + 16 <= dims) : (i += 16) {
        inline for (0..4) |lane| {
            const av = load4(a, i + lane * 4);
            const bv = load4(b, i + lane * 4);
            dot[lane] += av * bv;
            mag_a[lane] += av * av;
            mag_b[lane] += bv * bv;
        }
    }

    var dot_total = reduce(dot);
    var mag_a_total = reduce(mag_a);
    var mag_b_total = reduce(mag_b);
    while (i < dims) : (i += 1) {
        const x: f64 = a[i];
        const y: f64 = b[i];
        dot_total += x * y;
        mag_a_total += x * x;
        mag_b_total += y * y;
    }
    return finish(dot_total, mag_a_total, mag_b_total);
}

fn load4(values: []align(1) const f32, i: usize) @Vector(4, f32) {
    return .{ values[i], values[i + 1], values[i + 2], values[i + 3] };
}

/// Fixed reduction topology: pairwise vector sums, then lane order.
fn reduce(acc: [4]@Vector(4, f32)) f64 {
    const s01 = acc[0] + acc[1];
    const s23 = acc[2] + acc[3];
    const s = s01 + s23;
    return @as(f64, s[0]) + @as(f64, s[1]) + @as(f64, s[2]) + @as(f64, s[3]);
}

fn finish(dot: f64, mag_a: f64, mag_b: f64) VectorError!f64 {
    // A NaN element poisons its magnitude sum and an infinity overflows
    // it, so checking the totals covers non-finite inputs.
    if (!std.math.isFinite(dot) or
        !std.math.isFinite(mag_a) or
        !std.math.isFinite(mag_b))
    {
        return error.NonFinite;
    }
    if (mag_a == 0 or mag_b == 0) return error.ZeroMagnitude;
    return 1.0 - dot / @sqrt(mag_a * mag_b);
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

const testing = std.testing;

fn asBytes(values: []const f32) []const u8 {
    return std.mem.sliceAsBytes(values);
}

test "cosine distance identities" {
    const unit_x = [_]f32{ 1, 0, 0, 0 };
    const unit_y = [_]f32{ 0, 1, 0, 0 };
    const opposite = [_]f32{ -1, 0, 0, 0 };
    try testing.expectApproxEqAbs(
        @as(f64, 0),
        try cosineDistanceBytes(asBytes(&unit_x), asBytes(&unit_x)),
        1e-7,
    );
    try testing.expectApproxEqAbs(
        @as(f64, 1),
        try cosineDistanceBytes(asBytes(&unit_x), asBytes(&unit_y)),
        1e-7,
    );
    try testing.expectApproxEqAbs(
        @as(f64, 2),
        try cosineDistanceBytes(asBytes(&unit_x), asBytes(&opposite)),
        1e-7,
    );
}

test "cosine distance rejects malformed input" {
    const four = [_]f32{ 1, 2, 3, 4 };
    const three = [_]f32{ 1, 2, 3 };
    try testing.expectError(
        error.LengthMismatch,
        cosineDistanceBytes(asBytes(&four), asBytes(&three)),
    );
    try testing.expectError(error.EmptyVector, cosineDistanceBytes("", ""));
    try testing.expectError(
        error.MalformedBlob,
        cosineDistanceBytes(asBytes(&four)[0..7], asBytes(&four)[0..7]),
    );
    const zero = [_]f32{ 0, 0, 0, 0 };
    try testing.expectError(
        error.ZeroMagnitude,
        cosineDistanceBytes(asBytes(&zero), asBytes(&four)),
    );
    const with_nan = [_]f32{ 1, std.math.nan(f32), 0, 0 };
    try testing.expectError(
        error.NonFinite,
        cosineDistanceBytes(asBytes(&with_nan), asBytes(&four)),
    );
    const with_inf = [_]f32{ 1, std.math.inf(f32), 0, 0 };
    try testing.expectError(
        error.NonFinite,
        cosineDistanceBytes(asBytes(&with_inf), asBytes(&four)),
    );
}

test "scalar and simd kernels agree within tolerance" {
    var prng = std.Random.DefaultPrng.init(0xd15c0);
    const random = prng.random();
    // Dimensions cover SIMD blocks, scalar tails, and sub-block sizes.
    const dims_cases = [_]usize{ 1, 2, 3, 4, 15, 16, 17, 31, 64, 384, 768, 1024, 1536, 1537 };
    var a_buffer: [1537]f32 = undefined;
    var b_buffer: [1537]f32 = undefined;
    for (dims_cases) |dims| {
        for (a_buffer[0..dims], b_buffer[0..dims]) |*x, *y| {
            x.* = @floatCast(random.floatNorm(f64));
            y.* = @floatCast(random.floatNorm(f64));
        }
        const scalar = try cosineDistanceScalar(
            asBytes(a_buffer[0..dims]),
            asBytes(b_buffer[0..dims]),
        );
        const simd = try cosineDistanceSimd(
            asBytes(a_buffer[0..dims]),
            asBytes(b_buffer[0..dims]),
        );
        // f32 inputs, differing reduction order: relative 1e-5 tolerance.
        const tolerance = 1e-5 * @max(1.0, @abs(scalar));
        try testing.expectApproxEqAbs(scalar, simd, tolerance);
    }
}

test "unaligned blobs produce the same distances" {
    var prng = std.Random.DefaultPrng.init(0xa119);
    const random = prng.random();
    const dims = 33;
    var aligned_a: [dims]f32 = undefined;
    var aligned_b: [dims]f32 = undefined;
    for (&aligned_a, &aligned_b) |*x, *y| {
        x.* = @floatCast(random.floatNorm(f64));
        y.* = @floatCast(random.floatNorm(f64));
    }
    // Copy the same bytes to an odd offset to force unaligned access.
    var storage_a: [dims * 4 + 1]u8 = undefined;
    var storage_b: [dims * 4 + 1]u8 = undefined;
    @memcpy(storage_a[1..], asBytes(&aligned_a));
    @memcpy(storage_b[1..], asBytes(&aligned_b));

    const from_aligned = try cosineDistanceBytes(
        asBytes(&aligned_a),
        asBytes(&aligned_b),
    );
    const from_unaligned = try cosineDistanceBytes(
        storage_a[1..],
        storage_b[1..],
    );
    try testing.expectEqual(from_aligned, from_unaligned);
}

test "nearly tied vectors keep a stable relative order per kernel" {
    // Two candidates whose distances differ by little more than f32
    // resolution: each kernel must order them consistently with itself.
    const query = [_]f32{ 1, 0, 0, 0, 1, 0, 0, 0 };
    var near_a = query;
    var near_b = query;
    near_a[1] = 1e-3;
    near_b[1] = 1.0001e-3;
    const scalar_a = try cosineDistanceScalar(asBytes(&query), asBytes(&near_a));
    const scalar_b = try cosineDistanceScalar(asBytes(&query), asBytes(&near_b));
    const simd_a = try cosineDistanceSimd(asBytes(&query), asBytes(&near_a));
    const simd_b = try cosineDistanceSimd(asBytes(&query), asBytes(&near_b));
    try testing.expect(scalar_a < scalar_b);
    try testing.expect(simd_a < simd_b);
}

test "backend selection matches the compile target" {
    switch (builtin.target.cpu.arch) {
        .aarch64 => try testing.expectEqual(Backend.neon128, backend),
        .x86_64 => try testing.expectEqual(Backend.sse128, backend),
        else => {},
    }
    try testing.expect(backend.name().len > 0);
}
