//! Only the daemon composition layer translates native generation ownership to
//! the pure UI contract. The pin ends before the copied result is enqueued.
const std = @import("std");
const p = @import("console").protocol;
const server = @import("server.zig");

pub fn snapshot(state: *server.AppState) !p.crs.Status {
    const publisher = state.crs orelse return .{};
    const current = publisher.snapshot() catch |err| switch (err) {
        error.NoGeneration => return .{},
        else => return err,
    };
    var version: [17]u8 = undefined;
    const selected: p.crs.Selection = .{
        .mode = switch (current.activation.mode) {
            .off => .off,
            .audit => .audit,
            .enforce => .enforce,
        },
        .profile = switch (current.activation.profile) {
            .headers => .headers,
            .full => .full,
        },
        .revision = current.revision,
        .release = if (current.version) |value|
            try p.Bytes(17).init(try value.write(&version))
        else
            .{},
        .source_digest = try digest(current.digest),
        .operator_digest = try digest(current.operator_digest),
        .blocking_paranoia = current.activation.blocking_paranoia,
        .detection_paranoia = current.activation.detection_paranoia,
        .inbound_threshold = current.thresholds.inbound,
        .outbound_threshold = current.thresholds.outbound,
        .compiled_peak = current.compiled_peak,
        .reserved_bytes = current.reservation,
        .slots = @intCast(current.slots),
        .small_slots = @intCast(current.small_slots),
        .request_bytes = current.request_bytes,
        .response_bytes = current.response_bytes,
        .work_budget = current.work_budget,
        .timeout_ms = state.crs_timeout_ms,
    };
    try selected.validate();
    var counts: p.crs.Counts = .{};
    inline for (@typeInfo(p.crs.Counts).@"struct".field_names) |name| {
        @field(counts, name) = @field(state.crs_counts, name).load(.monotonic);
    }
    return .{ .selection = selected, .counts = counts };
}

fn digest(value: ?[32]u8) !p.Bytes(64) {
    const bytes = value orelse return .{};
    return p.Bytes(64).init(&std.fmt.bytesToHex(&bytes, .lower));
}
