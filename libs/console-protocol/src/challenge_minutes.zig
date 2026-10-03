//! Durable per-minute challenge observations: submissions, rejection causes and, per
//! authenticated parameter partition, issuance, acceptance and untrusted solve timing.
//! Counts are per-minute deltas of boot-local counters; a restart starts a new boot rather
//! than subtracting. Every value crossing the mailbox is owned.
const std = @import("std");
const p = @import("root.zig");
pub const max_bins = 8;
/// Rows per storage statement: a full record is 896 bytes, 1,792 hex on the wire, so 32
/// rows plus the look-ahead row stay inside the 64 KiB statement envelope.
pub const max_rows = 32;
/// Statements one summary request may spend before it hands back a continuation cursor.
pub const max_pages = 48;
pub const retention_days = p.minutes.retention_days;
pub const cause_count = 13;
pub const bin_count = 256;
pub const Cursor = p.minutes.Cursor;

/// One partition's minute deltas. `accepted` equals both the timing split (buckets, missing,
/// invalid) and the solver split (wasm, javascript, unknown_solver).
pub const Partition = struct {
    bin: u8 = 0,
    issued: u32 = 0,
    accepted: u32 = 0,
    buckets: [16]u32 = @splat(0),
    missing: u32 = 0,
    invalid: u32 = 0,
    wasm: u32 = 0,
    javascript: u32 = 0,
    unknown_solver: u32 = 0,

    pub fn consistent(self: *const Partition) bool {
        var timing: u64 = @as(u64, self.missing) + self.invalid;
        for (self.buckets) |count| timing += count;
        const solvers = @as(u64, self.wasm) + self.javascript + self.unknown_solver;
        return timing == self.accepted and solvers == self.accepted;
    }
};

pub const Record = struct {
    node: u32,
    boot: [16]u8,
    epoch: u32,
    minute: u64,
    start_ms: u64,
    end_ms: u64,
    observed_ms: u64,
    observations: u32,
    sealed: bool = false,
    complete: bool = false,
    gap: bool = false,
    submitted: u32 = 0,
    causes: [cause_count]u32 = @splat(0),
    /// Partitions active in this minute, ascending by bin; further partitions are counted
    /// in `bins_dropped` and their deltas are lost for the minute.
    bins: [max_bins]Partition = @splat(.{}),
    count: u8 = 0,
    bins_dropped: u8 = 0,

    pub fn cursor(self: Record) Cursor {
        return .{
            .minute = self.minute,
            .node = self.node,
            .boot = self.boot,
            .epoch = self.epoch,
        };
    }

    pub fn partition(self: *Record, bin: u8) ?*Partition {
        for (self.bins[0..self.count]) |*entry| if (entry.bin == bin) return entry;
        if (self.count == max_bins) return null;
        var index: usize = self.count;
        while (index != 0 and self.bins[index - 1].bin > bin) : (index -= 1)
            self.bins[index] = self.bins[index - 1];
        self.bins[index] = .{ .bin = bin };
        self.count += 1;
        return &self.bins[index];
    }
};

pub const Write = struct { record: Record, now: u64 };

pub const Query = struct {
    session_digest: [32]u8,
    require_totp: bool = false,
    /// A frozen range boundary, never the authority clock.
    observed_at: u64,
    from_minute: u64,
    until_minute: u64,
    node: ?u32 = null,
    before: ?Cursor = null,
    /// The partition whose timing histogram the summary carries.
    selected: u8 = 0,
    limit: u8 = max_rows,
};

/// Coverage of one bounded scan; the consumer owns continuation and never treats a partial
/// scan or missing minutes as zero activity.
pub const Coverage = struct {
    node: ?u32 = null,
    from: u64 = 0,
    until: u64 = 0,
    rows: u64 = 0,
    complete_rows: u64 = 0,
    observed_ms: u64 = 0,
    bins_dropped: u64 = 0,
    first: ?Cursor = null,
    last: ?Cursor = null,
    next: ?Cursor = null,
    finished: bool = false,
    retention_days: u16 = 0,
    retention_changed: bool = false,

    pub fn jsonStringify(self: Coverage, w: *std.json.Stringify) std.json.Stringify.Error!void {
        try w.beginObject();
        inline for (@typeInfo(Coverage).@"struct".field_names) |field_name| {
            try w.objectField(field_name);
            if (@FieldType(Coverage, field_name) == u64) {
                try p.writeCounter(w, @field(self, field_name));
            } else try w.write(@field(self, field_name));
        }
        try w.endObject();
    }
};

/// Window totals in the live snapshot's shape, so one renderer serves both; `configured`
/// and `last_issued` stay at their defaults and `timestamp` is the frozen observation.
pub const Summary = struct {
    version: u8 = 1,
    coverage: Coverage = .{},
    totals: p.challenges.Snapshot = .{},
};

pub fn validate(query: Query) error{InvalidLimit}!void {
    if (query.limit == 0 or query.limit > max_rows or query.observed_at > std.math.maxInt(i64) or
        query.from_minute > query.until_minute or query.until_minute >= query.observed_at / 60 or
        query.until_minute - query.from_minute > retention_days * 1440)
        return error.InvalidLimit;
    if (query.before) |cursor| {
        if (cursor.minute > std.math.maxInt(i64) or cursor.epoch == 0 or
            std.mem.allEqual(u8, &cursor.boot, 0)) return error.InvalidLimit;
        if (query.node) |node| if (cursor.node != node) return error.InvalidLimit;
    }
}

/// Folds one record into a summary. Overflow is a protocol error, never a wrapped counter.
pub fn add(summary: *Summary, record: *const Record) error{InvalidResponse}!void {
    const c = &summary.coverage;
    const t = &summary.totals;
    if (record.count > max_bins or (record.complete and (!record.sealed or record.gap)))
        return error.InvalidResponse;
    if (c.last) |last| {
        if (!p.minute_summary.precedes(record.cursor(), last)) return error.InvalidResponse;
    } else c.first = record.cursor();
    c.last = record.cursor();
    c.rows = try sum(c.rows, 1);
    c.complete_rows += @intFromBool(record.complete);
    c.observed_ms = try sum(c.observed_ms, record.observed_ms);
    c.bins_dropped = try sum(c.bins_dropped, record.bins_dropped);
    t.submitted = try sum(t.submitted, record.submitted);
    for (&t.causes, record.causes) |*total, count| {
        total.* = try sum(total.*, count);
        t.rejected = try sum(t.rejected, count);
    }
    for (record.bins[0..record.count]) |*entry| {
        if (!entry.consistent()) return error.InvalidResponse;
        t.issued = try sum(t.issued, entry.issued);
        t.accepted = try sum(t.accepted, entry.accepted);
        t.bin_accepted[entry.bin] = try sum(t.bin_accepted[entry.bin], entry.accepted);
        if (entry.bin != t.selected) continue;
        for (&t.buckets, entry.buckets) |*total, count| total.* = try sum(total.*, count);
        inline for (.{ "missing", "invalid", "wasm", "javascript", "unknown_solver" }) |name|
            @field(t, name) = try sum(@field(t, name), @field(entry, name));
    }
}

/// Continues a window with the next bounded scan. Parts must chain on the cursor the
/// previous part announced; a replay or a widened part is a protocol error.
pub fn merge(into: *Summary, part: Summary) error{InvalidResponse}!void {
    const c = &into.coverage;
    const item = part.coverage;
    if (part.version != 1 or c.finished or item.node != c.node or item.from != c.from or
        item.until != c.until or item.rows > max_rows * max_pages or
        item.complete_rows > item.rows or item.finished != (item.next == null) or
        (item.rows == 0 and (item.first != null or item.last != null)) or
        (item.rows != 0 and (item.first == null or item.last == null)))
        return error.InvalidResponse;
    if (c.next) |expected| if (item.first) |first| {
        if (!p.minute_summary.precedes(first, expected)) return error.InvalidResponse;
    };
    c.rows = try sum(c.rows, item.rows);
    c.complete_rows = try sum(c.complete_rows, item.complete_rows);
    c.observed_ms = try sum(c.observed_ms, item.observed_ms);
    c.bins_dropped = try sum(c.bins_dropped, item.bins_dropped);
    c.first = c.first orelse item.first;
    c.last = item.last orelse c.last;
    c.next = item.next;
    c.finished = item.finished;
    c.retention_changed = c.retention_changed or item.retention_changed or
        (c.retention_days != 0 and c.retention_days != item.retention_days);
    c.retention_days = item.retention_days;
    const t = &into.totals;
    const s = &part.totals;
    if (s.selected != t.selected) return error.InvalidResponse;
    inline for (.{
        "issued",  "submitted", "accepted",   "rejected",       "missing",
        "invalid", "wasm",      "javascript", "unknown_solver",
    }) |name|
        @field(t, name) = try sum(@field(t, name), @field(s, name));
    for (&t.causes, s.causes) |*total, count| total.* = try sum(total.*, count);
    for (&t.bin_accepted, s.bin_accepted) |*total, count| total.* = try sum(total.*, count);
    for (&t.buckets, s.buckets) |*total, count| total.* = try sum(total.*, count);
}

fn sum(total: u64, count: anytype) error{InvalidResponse}!u64 {
    return std.math.add(u64, total, count) catch error.InvalidResponse;
}

test "partitions stay sorted, bounded and internally consistent" {
    const t = std.testing;
    var record: Record = .{
        .node = 1,
        .boot = @splat(1),
        .epoch = 1,
        .minute = 5,
        .start_ms = 0,
        .end_ms = 60000,
        .observed_ms = 60000,
        .observations = 240,
    };
    for ([_]u8{ 133, 5, 200, 5 }) |bin| _ = record.partition(bin).?;
    try t.expectEqual(@as(u8, 3), record.count);
    try t.expectEqual(@as(u8, 5), record.bins[0].bin);
    try t.expectEqual(@as(u8, 200), record.bins[2].bin);
    for (0..5) |i| _ = record.partition(@intCast(10 + i));
    try t.expect(record.partition(250) == null);
    var entry = record.bins[0];
    entry.accepted = 2;
    entry.buckets[3] = 1;
    entry.missing = 1;
    entry.wasm = 2;
    try t.expect(entry.consistent());
    entry.javascript = 1;
    try t.expect(!entry.consistent());
}
