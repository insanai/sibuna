//! Rule identities and interval data are independent of engines, sockets and database handles.
const std = @import("std");
const p = @import("root.zig");
pub const max_rules = 128;
pub const batch_rows = 8;
pub const Key = p.Bytes(160);
pub const Name = p.Bytes(128);
pub const Identity = struct { key: Key = .{}, name: Name = .{} };
pub const Clock = struct { utc: u64, ms: u64 };
pub const Generation = struct {
    node: u32,
    boot: [16]u8,
    number: u64,
    revision: u64,
    born: Clock,
    rules: [max_rules]Identity = @splat(.{}),
    len: usize = 0,
};
pub const Span = struct {
    node: u32 = 0,
    boot: [16]u8 = @splat(0),
    generation: u64 = 0,
    revision: u64 = 0,
    sequence: u64 = 0,
    minute: u64 = 0,
    utc_start: u64 = 0,
    utc_end: u64 = 0,
    start_ms: u64 = 0,
    end_ms: u64 = 0,
    observed_ms: u64 = 0,
    observations: u32 = 0,
    complete: bool = false,
    gap: bool = false,
    unconfirmed: u64 = 0,

    pub fn validate(self: Span) error{InvalidInterval}!void {
        if (self.node == 0 or self.generation == 0 or self.sequence == 0 or
            self.revision > std.math.maxInt(i64) or self.sequence > std.math.maxInt(i64) or
            self.generation > std.math.maxInt(i64) or self.utc_end > std.math.maxInt(i64) or
            self.end_ms > std.math.maxInt(i64) or self.end_ms <= self.start_ms or
            self.utc_start > self.utc_end or self.observed_ms != self.end_ms - self.start_ms or
            self.minute != self.utc_end / 60 or self.observations == 0 or
            std.mem.allEqual(u8, &self.boot, 0)) return error.InvalidInterval;
        if (self.complete and (self.gap or self.observed_ms < 59000 or
            self.observed_ms > 61000)) return error.InvalidInterval;
    }
};
pub const Entry = struct {
    identity: Identity = .{},
    hits: ?u64 = 0,
};
pub const Frame = struct {
    span: Span = .{},
    entries: [max_rules]Entry = @splat(.{}),
    len: usize = 0,
};
pub const Status = struct {
    pending: u32 = 0,
    confirmed: u64 = 0,
    unconfirmed: u64 = 0,
    last_stored_utc: u64 = 0,
    clock_resets: u64 = 0,
    overflow: bool = false,
};
