//! Validate the complete stored envelope instead of inventing missing fields.
const std = @import("std");
const evidence = @import("core").security_evidence;
const store = @import("console_store.zig");

pub fn decode(row: []const ?[]const u8) !?evidence.Crs {
    std.debug.assert(row.len == 13);
    if (row[12] == null) return null;
    const coverage = try number(u8, row[8]);
    const input: evidence.Wire = .{
        .rule_id = try number(u32, row[0]),
        .phase = try number(u8, row[1]),
        .severity = try number(u8, row[2]),
        .revision = row[3] orelse return error.InvalidStoredValue,
        .source_digest = row[4] orelse return error.InvalidStoredValue,
        .enforcing = try boolean(row[5]),
        .denied = try boolean(row[6]),
        .would_deny = try boolean(row[7]),
        .coverage = std.enums.fromInt(evidence.Coverage, coverage) orelse
            return error.InvalidStoredValue,
        .selected_status = try number(u16, row[9]),
        .blocking_paranoia = try number(u8, row[10]),
        .detection_paranoia = try number(u8, row[11]),
    };
    return try input.decode();
}

fn number(comptime T: type, value: ?[]const u8) !T {
    return std.math.cast(T, try store.number(value)) orelse error.InvalidStoredValue;
}

fn boolean(value: ?[]const u8) !bool {
    return switch (try number(u8, value)) {
        0 => false,
        1 => true,
        else => error.InvalidStoredValue,
    };
}
