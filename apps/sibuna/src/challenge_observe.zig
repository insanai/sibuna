//! Optional console observations. Client metadata never reaches the verifier.
const std = @import("std");
const options = @import("build_options");
const challenge = @import("challenge");
const counters = @import("store").challenge_metrics;
const AppState = @import("server.zig").AppState;

pub fn submit(state: *AppState) void {
    if (options.console) if (state.telemetry) |telemetry| {
        _ = telemetry.challenges.submitted.fetchAdd(1, .monotonic);
    };
}

pub fn reject(state: *AppState, ip: []const u8, now: u64, cause: counters.Cause) void {
    if (options.console) if (state.telemetry) |telemetry| {
        telemetry.challenges.reject(cause);
        telemetry.challengeEvent(event(ip, now, 2, @intFromEnum(cause), 0, 0, 0, null));
    };
}

pub fn verificationFailure(
    state: *AppState,
    ip: []const u8,
    now: u64,
    err: challenge.VerifyError,
) void {
    reject(state, ip, now, switch (err) {
        error.MalformedChallenge => .malformed_challenge,
        error.InvalidChallengeTag => .invalid_tag,
        error.ChallengeExpired => .expired,
        error.FingerprintMismatch => .fingerprint_mismatch,
        error.DifficultyNotMet => .difficulty_not_met,
        error.InvalidProof => .invalid_proof,
        error.WrongSolutionType => .wrong_solution_type,
        error.DoubleSpendAttempt => .replay,
        error.StoreFull => .capacity,
    });
}

pub fn issue(
    state: *AppState,
    ip: []const u8,
    now: u64,
    algorithm: challenge.Algorithm,
    parameter: u32,
    openings: u8,
) void {
    if (options.console) if (state.telemetry) |telemetry| {
        telemetry.challenges.issue(convert(algorithm), @intCast(parameter), openings);
        telemetry.adaptive_bits.store(state.coordinator.adaptive.bump(), .monotonic);
        telemetry.adaptive_rate_256.store(
            state.coordinator.adaptive.rate_256.load(.monotonic),
            .monotonic,
        );
        const kind: u8 = @intFromEnum(convert(algorithm));
        const bits: u8 = @intCast(parameter);
        telemetry.challengeEvent(event(ip, now, 0, no_cause, kind, bits, openings, null));
    };
}

pub fn accept(
    state: *AppState,
    ip: []const u8,
    now: u64,
    result: challenge.VerifiedResult,
    body: []const u8,
) void {
    if (options.console) if (state.telemetry) |telemetry| {
        const metadata = parseMetadata(body);
        telemetry.challenges.accept(
            convert(result.algorithm),
            result.difficulty,
            result.challenges,
            metadata.timing,
            metadata.solver,
        );
        const duration: ?u32 = switch (metadata.timing) {
            .milliseconds => |ms| if (std.math.isFinite(ms) and ms >= 0 and ms <= 3600000)
                @intFromFloat(ms)
            else
                null,
            else => null,
        };
        const kind: u8 = @intFromEnum(convert(result.algorithm));
        telemetry.challengeEvent(event(
            ip,
            now,
            1,
            no_cause,
            kind,
            result.difficulty,
            result.challenges,
            duration,
        ));
    };
}

const no_cause = @import("store").telemetry.no_cause;

fn event(
    ip: []const u8,
    now: u64,
    outcome: u8,
    cause: u8,
    algorithm: u8,
    parameter: u8,
    openings: u8,
    duration_ms: ?u32,
) @import("store").telemetry.ChallengeRecord {
    var record: @import("store").telemetry.ChallengeRecord = .{
        .second = now,
        .duration_ms = duration_ms orelse @import("store").telemetry.no_duration,
        .ip_len = @intCast(@min(ip.len, 48)),
        .outcome = outcome,
        .cause = cause,
        .algorithm = algorithm,
        .parameter = parameter,
        .openings = openings,
        .ip = undefined,
    };
    @memcpy(record.ip[0..record.ip_len], ip[0..record.ip_len]);
    return record;
}

fn convert(algorithm: challenge.Algorithm) counters.Algorithm {
    return switch (algorithm) {
        .hashcash => .hashcash,
        .posw => .posw,
    };
}

const Metadata = struct {
    timing: counters.Timing = .missing,
    solver: counters.Solver = .unknown,
};

/// A small fixed scanner arena bounds nesting. Unexpected JSON is invalid telemetry,
/// even if the existing proof parser accepted it; this cannot change admission.
fn parseMetadata(body: []const u8) Metadata {
    var arena: [256]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&arena);
    var scanner = std.json.Scanner.initCompleteInput(fixed.allocator(), body);
    defer scanner.deinit();
    return readMetadata(&scanner) catch .{ .timing = .invalid };
}

fn readMetadata(scanner: *std.json.Scanner) !Metadata {
    if (try scanner.next() != .object_begin) return error.Invalid;
    var result: Metadata = .{};
    var timing_seen = false;
    var solver_seen = false;
    while (true) {
        const key = try scanner.next();
        if (key == .object_end) break;
        if (key != .string) return error.Invalid;
        const timing = std.mem.eql(u8, key.string, "elapsed_ms");
        const solver = std.mem.eql(u8, key.string, "solver");
        if (!timing and !solver) {
            try scanner.skipValue();
            continue;
        }
        const value = try scanner.next();
        if (timing) {
            if (timing_seen or value != .number) return error.Invalid;
            timing_seen = true;
            result.timing = .{ .milliseconds = try std.fmt.parseFloat(f64, value.number) };
        } else {
            if (solver_seen or value != .string) return error.Invalid;
            solver_seen = true;
            if (std.mem.eql(u8, value.string, "wasm")) result.solver = .wasm;
            if (std.mem.eql(u8, value.string, "javascript")) result.solver = .javascript;
        }
    }
    if (try scanner.next() != .end_of_document) return error.Invalid;
    return result;
}

test "timing metadata excludes nested fields and rejects ambiguous or malformed values" {
    try std.testing.expect(parseMetadata("{\"nonce\":1}").timing == .missing);
    const good = parseMetadata("{\"elapsed_ms\":12.5,\"solver\":\"wasm\",\"nonce\":1}");
    try std.testing.expectEqual(@as(f64, 12.5), good.timing.milliseconds);
    try std.testing.expectEqual(counters.Solver.wasm, good.solver);
    const nested = parseMetadata("{\"other\":{\"elapsed_ms\":1}}");
    try std.testing.expect(nested.timing == .missing);
    const invalid = [_][]const u8{
        "{\"elapsed_ms\":\"12\"}",
        "{\"elapsed_ms\":1,\"elapsed_ms\":2}",
        "{\"elapsed_ms\":null}",
        "{\"elapsed_ms\":1}garbage",
    };
    for (invalid) |body| try std.testing.expect(parseMetadata(body).timing == .invalid);
}
