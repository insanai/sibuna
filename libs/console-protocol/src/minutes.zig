//! Durable, sample-aligned minute counter intervals. Every asynchronous value is owned.
const std = @import("std");
pub const max_rows = 8;
pub const retention_days = 90;
pub const counter_fields = .{
    "admitted",   "challenged", "denied", "banned", "rate_limited", "other",
    "origin_4xx", "origin_5xx",
};
pub const Record = struct {
    node: u32,
    boot: [16]u8,
    epoch: u32,
    minute: u64,
    utc_start: u64,
    utc_end: u64,
    start_ms: u64,
    end_ms: u64,
    observed_ms: u64,
    observations: u32,
    sealed: bool = false,
    complete: bool = false,
    gap: bool = false,
    counts: @import("timeline.zig").Counts = .{},

    pub fn cursor(self: Record) Cursor {
        return .{
            .minute = self.minute,
            .node = self.node,
            .boot = self.boot,
            .epoch = self.epoch,
        };
    }

    pub fn jsonStringify(self: Record, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, w);
    }
};
pub const Cursor = struct {
    minute: u64,
    node: u32,
    boot: [16]u8,
    epoch: u32,

    pub fn jsonStringify(self: Cursor, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, w);
    }
};
pub const Write = struct { record: Record, now: u64 };
pub const Request = struct {
    from_minute: ?u64 = null,
    until_minute: ?u64 = null,
    node: ?u32 = null,
    before: ?Cursor = null,
    limit: u8 = max_rows,
};
pub const Reply = struct {
    version: u8 = 1,
    retention_days: u16 = retention_days,
    from_minute: u64,
    until_minute: u64,
    observed_at: u64,
    rows: []const Record,
    next: ?Cursor,
};
pub const Query = struct {
    session_digest: [32]u8,
    // A frozen range boundary, never the authority clock.
    observed_at: u64,
    require_totp: bool = false,
    from_minute: u64,
    until_minute: u64,
    node: ?u32 = null,
    before: ?Cursor = null,
    limit: u8 = max_rows,
};
pub const Page = struct {
    retention_days: u16 = retention_days,
    rows: [max_rows]Record = undefined,
    count: u8 = 0,
    next: ?Cursor = null,
};
pub const Status = struct {
    available: bool = false,
    pending: u32 = 0,
    saved_snapshots: u64 = 0,
    unconfirmed_snapshots: u64 = 0,
    retention_failures: u64 = 0,
    last_saved_end_ms: u64 = 0,

    pub fn jsonStringify(self: Status, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, w);
    }
};

pub fn validate(query: Query) error{InvalidLimit}!void {
    if (query.limit == 0 or query.limit > max_rows or query.observed_at > std.math.maxInt(i64) or
        query.from_minute > query.until_minute or query.until_minute > query.observed_at / 60 or
        query.until_minute - query.from_minute > retention_days * 1440)
        return error.InvalidLimit;
    if (query.before) |cursor| {
        if (cursor.minute > std.math.maxInt(i64) or cursor.epoch == 0 or
            std.mem.allEqual(u8, &cursor.boot, 0)) return error.InvalidLimit;
    }
}

fn fields(value: anytype, w: *std.json.Stringify) std.json.Stringify.Error!void {
    try w.beginObject();
    inline for (@typeInfo(@TypeOf(value)).@"struct".fields) |field| {
        try w.objectField(field.name);
        const item = @field(value, field.name);
        if (field.type == [16]u8) {
            try w.beginArray();
            for (item) |byte| try w.write(byte);
            try w.endArray();
        } else if (field.type == u64) {
            try @import("root.zig").writeCounter(w, item);
        } else try w.write(item);
    }
    try w.endObject();
}
