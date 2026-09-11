//! Per-address challenge records and adaptive-difficulty transitions. Records are bounded
//! observations drained from a data-plane queue (loss is counted, never hidden); client
//! timing stays untrusted telemetry. Difficulty rows record the console's once-per-second
//! observation of the effective adaptive bump, not every request's parameters.
const std = @import("std");
const p = @import("root.zig");
pub const max_batch = 32;
pub const max_rows = 12;
pub const max_transitions = 32;
pub const retention_days = 7;
pub const no_cause = 255;
pub const Outcome = enum(u8) { issued, accepted, rejected };

pub const Record = struct {
    second: u64,
    ip: p.Bytes(48) = .{},
    outcome: Outcome = .issued,
    /// A `challenge_metrics.Cause` ordinal for rejections, `no_cause` otherwise.
    cause: u8 = no_cause,
    algorithm: u8 = 0,
    parameter: u8 = 0,
    openings: u8 = 0,
    /// Client-reported solve time; null when absent or invalid.
    duration_ms: ?u32 = null,
};

pub const Batch = struct {
    node: u32,
    boot: [16]u8,
    count: u8 = 0,
    records: [max_batch]Record = undefined,
    /// Queue losses since boot at the time of the batch, for coverage notes.
    dropped: u64 = 0,
    now: u64,
};

pub const Cursor = struct {
    second: u64,
    id: u64,

    pub fn jsonStringify(self: Cursor, w: *std.json.Stringify) std.json.Stringify.Error!void {
        try w.beginObject();
        try w.objectField("second");
        try p.writeCounter(w, self.second);
        try w.objectField("id");
        try p.writeCounter(w, self.id);
        try w.endObject();
    }
};

pub const Query = struct {
    session_digest: [32]u8,
    require_totp: bool = false,
    observed_at: u64,
    from: u64,
    until: u64,
    node: ?u32 = null,
    outcome: ?Outcome = null,
    cause: ?u8 = null,
    /// Exact address match; an empty prefix selects every address.
    address: p.Bytes(48) = .{},
    before: ?Cursor = null,
    limit: u8 = max_rows,
};

pub const Row = struct {
    id: u64,
    node: u32,
    second: u64,
    ip: p.Bytes(48),
    outcome: Outcome,
    cause: u8,
    algorithm: u8,
    parameter: u8,
    openings: u8,
    duration_ms: ?u32,

    pub fn jsonStringify(self: Row, w: *std.json.Stringify) std.json.Stringify.Error!void {
        try w.beginObject();
        inline for (@typeInfo(Row).@"struct".fields) |field| {
            try w.objectField(field.name);
            const value = @field(self, field.name);
            if (field.type == u64) {
                try p.writeCounter(w, value);
            } else if (field.type == p.Bytes(48)) {
                try w.write(value.slice());
            } else try w.write(value);
        }
        try w.endObject();
    }
};

pub const Page = struct {
    version: u8 = 1,
    retention_days: u16 = retention_days,
    observed_at: u64 = 0,
    from: u64 = 0,
    until: u64 = 0,
    dropped_since_boot: u64 = 0,
    /// Batches whose write was not acknowledged as recorded; their rows may be absent.
    unconfirmed_since_boot: u64 = 0,
    rows: [max_rows]Row = undefined,
    count: u8 = 0,
    next: ?Cursor = null,

    pub fn jsonStringify(self: Page, w: *std.json.Stringify) std.json.Stringify.Error!void {
        try w.beginObject();
        try w.objectField("version");
        try w.write(self.version);
        try w.objectField("retention_days");
        try w.write(self.retention_days);
        inline for (.{
            "observed_at",            "from",
            "until",                  "dropped_since_boot",
            "unconfirmed_since_boot",
        }) |name| {
            try w.objectField(name);
            try p.writeCounter(w, @field(self, name));
        }
        try w.objectField("rows");
        try w.write(self.rows[0..self.count]);
        try w.objectField("next");
        if (self.next) |cursor| try w.write(cursor) else try w.write(null);
        try w.endObject();
    }
};

pub const Transition = struct {
    node: u32,
    boot: [16]u8,
    second: u64,
    previous_bits: u8,
    bits: u8,
    /// Smoothed issue rate in 1/256 challenges per second when the bump changed.
    rate_256: u64,
};

pub const DifficultyQuery = struct {
    session_digest: [32]u8,
    require_totp: bool = false,
    observed_at: u64,
    from: u64,
    until: u64,
    node: ?u32 = null,
    limit: u8 = max_transitions,
};

pub const TransitionRow = struct {
    node: u32,
    second: u64,
    previous_bits: u8,
    bits: u8,
    rate_256: u64,

    pub fn jsonStringify(
        self: TransitionRow,
        w: *std.json.Stringify,
    ) std.json.Stringify.Error!void {
        try w.beginObject();
        try w.objectField("node");
        try w.write(self.node);
        try w.objectField("second");
        try p.writeCounter(w, self.second);
        try w.objectField("previous_bits");
        try w.write(self.previous_bits);
        try w.objectField("bits");
        try w.write(self.bits);
        try w.objectField("rate_256");
        try p.writeCounter(w, self.rate_256);
        try w.endObject();
    }
};

pub const DifficultyPage = struct {
    version: u8 = 1,
    retention_days: u16 = retention_days,
    observed_at: u64 = 0,
    from: u64 = 0,
    until: u64 = 0,
    /// The current effective bump of the serving node, observed once per second.
    current_bits: ?u8 = null,
    /// Changes this node observed but did not record: a previous transition was still
    /// pending, or the write was not acknowledged. Coverage is boot-local, never zero loss.
    missed_since_boot: u64 = 0,
    rows: [max_transitions]TransitionRow = undefined,
    count: u8 = 0,
    truncated: bool = false,

    pub fn jsonStringify(
        self: DifficultyPage,
        w: *std.json.Stringify,
    ) std.json.Stringify.Error!void {
        try w.beginObject();
        try w.objectField("version");
        try w.write(self.version);
        try w.objectField("retention_days");
        try w.write(self.retention_days);
        inline for (.{ "observed_at", "from", "until" }) |name| {
            try w.objectField(name);
            try p.writeCounter(w, @field(self, name));
        }
        try w.objectField("current_bits");
        try w.write(self.current_bits);
        try w.objectField("missed_since_boot");
        try p.writeCounter(w, self.missed_since_boot);
        try w.objectField("rows");
        try w.write(self.rows[0..self.count]);
        try w.objectField("truncated");
        try w.write(self.truncated);
        try w.endObject();
    }
};

pub fn validate(query: Query) error{InvalidLimit}!void {
    if (query.limit == 0 or query.limit > max_rows or query.observed_at > std.math.maxInt(i64) or
        query.from > query.until or query.until > query.observed_at or
        query.until - query.from > retention_days * 86400) return error.InvalidLimit;
    if (query.cause) |cause| if (cause >= 13 and cause != no_cause) return error.InvalidLimit;
    if (query.before) |cursor| if (cursor.second > std.math.maxInt(i64) or
        cursor.id > std.math.maxInt(i64)) return error.InvalidLimit;
}

pub fn validateDifficulty(query: DifficultyQuery) error{InvalidLimit}!void {
    if (query.limit == 0 or query.limit > max_transitions or
        query.observed_at > std.math.maxInt(i64) or query.from > query.until or
        query.until > query.observed_at or query.until - query.from > retention_days * 86400)
        return error.InvalidLimit;
}

test "record queries stay within retention and page bounds" {
    const t = std.testing;
    const base: Query = .{
        .session_digest = @splat(1),
        .observed_at = 1000,
        .from = 0,
        .until = 1000,
    };
    try validate(base);
    var wide = base;
    wide.from = 0;
    wide.observed_at = 10 * 86400;
    wide.until = 10 * 86400;
    try t.expectError(error.InvalidLimit, validate(wide));
    var cause = base;
    cause.cause = 13;
    try t.expectError(error.InvalidLimit, validate(cause));
    cause.cause = no_cause;
    try validate(cause);
    var limit = base;
    limit.limit = max_rows + 1;
    try t.expectError(error.InvalidLimit, validate(limit));
}
