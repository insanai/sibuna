//! Observed counter intervals, grouped by monotonic ending second. UTC labels are descriptive.
const std = @import("std");
pub const capacity = 3600;
pub const max_rows = 16;
pub const Query = struct {
    before: ?u64 = null,
    epoch: ?u32 = null,
    boot: ?[]const u8 = null,
    limit: u8 = 12,
};
pub const Counts = struct {
    admitted: u64 = 0,
    challenged: u64 = 0,
    denied: u64 = 0,
    banned: u64 = 0,
    rate_limited: u64 = 0,
    other: u64 = 0,
    origin_4xx: u64 = 0,
    origin_5xx: u64 = 0,

    pub fn jsonStringify(self: Counts, writer: *std.json.Stringify) std.json.Stringify.Error!void {
        return writeFields(self, writer);
    }
};
pub const Bucket = struct {
    sequence: u64 = 0,
    utc_start: u64 = 0,
    utc_end: u64 = 0,
    start_ms: u64 = 0,
    end_ms: u64 = 0,
    observed_ms: u64 = 0,
    observations: u32 = 0,
    /// A delayed collector or wall-clock discontinuity prevents per-second attribution.
    gap: bool = false,
    partial: bool = false,
    counts: Counts = .{},

    pub fn jsonStringify(self: Bucket, writer: *std.json.Stringify) std.json.Stringify.Error!void {
        return writeFields(self, writer);
    }
};
pub const Page = struct {
    version: u8 = 1,
    node: u32,
    boot: []const u8,
    epoch: u32,
    retention_seconds: u16 = capacity,
    as_of_ms: u64,
    discarded_intervals: u64,
    oldest_sequence: ?u64,
    next_before: ?u64,
    rows: []const Bucket,

    pub fn jsonStringify(self: Page, writer: *std.json.Stringify) std.json.Stringify.Error!void {
        return writeFields(self, writer);
    }
};

fn writeFields(value: anytype, writer: *std.json.Stringify) std.json.Stringify.Error!void {
    const counter = @import("root.zig").writeCounter;
    try writer.beginObject();
    inline for (@typeInfo(@TypeOf(value)).@"struct".fields) |field| {
        try writer.objectField(field.name);
        const item = @field(value, field.name);
        if (field.type == u64) {
            try counter(writer, item);
        } else if (field.type == ?u64) {
            if (item) |number| try counter(writer, number) else try writer.write(null);
        } else try writer.write(item);
    }
    try writer.endObject();
}
