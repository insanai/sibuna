//! Bounded historical comparisons share their arithmetic between the owner and Wasm.
const std = @import("std");
const p = @import("root.zig");
const hits = @import("rule_hits.zig");
pub const page_rows = 48;
pub const bin_count = 24;
pub const Cursor = struct {
    minute: u64,
    boot: [16]u8,
    sequence: u64,

    pub fn jsonStringify(self: Cursor, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return @import("json_counters.zig").object(self, w);
    }
};
pub const Request = struct {
    key: hits.Key,
    node: u32,
    from_minute: u64,
    until_minute: u64,
    revision: ?u64 = null,
    before: ?Cursor = null,

    pub fn jsonStringify(self: Request, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return @import("json_counters.zig").object(self, w);
    }
};
pub const Query = struct {
    session_digest: [32]u8,
    require_totp: bool = false,
    observed_at: u64,
    request: Request,
};
pub const Row = struct { span: hits.Span, hits: ?u64 };
pub const Bin = struct {
    hits: ?u64 = 0,
    rows: u32 = 0,
    complete: u32 = 0,

    pub fn jsonStringify(self: Bin, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return @import("json_counters.zig").object(self, w);
    }
};
pub const Window = struct {
    request: Request,
    hits: ?u64 = 0,
    rows: u32 = 0,
    complete: u32 = 0,
    observed_ms: u64 = 0,
    first: ?Cursor = null,
    last: ?Cursor = null,
    next: ?Cursor = null,
    finished: bool = false,
    ambiguous: bool = false,
    clipped: bool = false,
    retention_days: ?u16 = null,
    unconfirmed: u64 = 0,
    min_revision: ?u64 = null,
    max_revision: ?u64 = null,
    bins: [bin_count]Bin = @splat(.{}),

    pub fn covered(self: *const Window) bool {
        return self.finished and !self.ambiguous and !self.clipped and self.hits != null and
            self.rows == self.request.until_minute - self.request.from_minute + 1 and
            self.complete == self.rows;
    }

    pub fn add(self: *Window, row: Row) error{InvalidResponse}!void {
        row.span.validate() catch return error.InvalidResponse;
        const span = row.span;
        if (span.node != self.request.node or span.minute < self.request.from_minute or
            span.minute > self.request.until_minute or (self.request.revision != null and
            span.revision != self.request.revision.?)) return error.InvalidResponse;
        const cursor: Cursor = .{
            .minute = span.minute,
            .boot = span.boot,
            .sequence = span.sequence,
        };
        if (self.last orelse self.request.before) |last| {
            if (!precedes(cursor, last)) return error.InvalidResponse;
            self.ambiguous = self.ambiguous or cursor.minute == last.minute;
        }
        if (self.first == null) self.first = cursor;
        self.hits = sum(self.hits, row.hits);
        self.rows = std.math.add(u32, self.rows, 1) catch return error.InvalidResponse;
        self.complete += @intFromBool(span.complete);
        self.observed_ms = std.math.add(u64, self.observed_ms, span.observed_ms) catch
            return error.InvalidResponse;
        self.unconfirmed = @max(self.unconfirmed, span.unconfirmed);
        self.min_revision = @min(self.min_revision orelse span.revision, span.revision);
        self.max_revision = @max(self.max_revision orelse span.revision, span.revision);
        const bin = &self.bins[
            (span.minute - self.request.from_minute) * bin_count /
                (self.request.until_minute - self.request.from_minute + 1)
        ];
        bin.hits = sum(bin.hits, row.hits);
        bin.rows += 1;
        bin.complete += @intFromBool(span.complete);
        self.last = cursor;
    }

    pub fn jsonStringify(self: Window, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return @import("json_counters.zig").object(self, w);
    }
};
pub const Part = struct { version: u8 = 1, observed_at: u64, window: Window };

pub fn validate(query: Query) error{InvalidLimit}!void {
    const request = query.request;
    if (request.key.len == 0 or request.key.len > request.key.data.len or
        !std.unicode.utf8ValidateSlice(request.key.slice()) or request.node == 0 or
        request.from_minute > request.until_minute or
        request.until_minute - request.from_minute >= 90 * 1440 or
        query.observed_at > std.math.maxInt(i64) or
        request.until_minute >= query.observed_at / 60 or
        (request.revision orelse 0) > std.math.maxInt(i64)) return error.InvalidLimit;
    if (request.before) |cursor| {
        if (cursor.minute < request.from_minute or cursor.minute > request.until_minute or
            cursor.sequence == 0 or cursor.sequence > std.math.maxInt(i64) or
            std.mem.allEqual(u8, &cursor.boot, 0)) return error.InvalidLimit;
    }
}

pub const BinRange = struct { from_minute: u64, until_minute: u64 };

/// Empty display slots have no corresponding minute in short windows. They are not gaps.
/// This inverse of add()'s floor projection keeps charts and accessible tables consistent.
pub fn binRange(request: Request, index: usize) ?BinRange {
    std.debug.assert(index < bin_count and request.from_minute <= request.until_minute);
    const duration = request.until_minute - request.from_minute + 1;
    const start = (index * duration + bin_count - 1) / bin_count;
    const end = ((index + 1) * duration + bin_count - 1) / bin_count;
    if (start == end) return null;
    return .{
        .from_minute = request.from_minute + start,
        .until_minute = request.from_minute + end - 1,
    };
}

pub fn precedes(a: Cursor, b: Cursor) bool {
    if (a.minute != b.minute) return a.minute < b.minute;
    const order = std.mem.order(u8, &a.boot, &b.boot);
    if (order != .eq) return order == .lt;
    return a.sequence < b.sequence;
}

fn sum(a: ?u64, b: ?u64) ?u64 {
    return std.math.add(u64, a orelse return null, b orelse return null) catch null;
}

/// A candidate copy commits only after all scope, cursor and arithmetic checks succeed.
pub fn accept(self: *Window, part: Part) error{InvalidResponse}!void {
    const item = &part.window;
    validate(.{
        .request = item.request,
        .observed_at = part.observed_at,
        .session_digest = @splat(0),
    }) catch return error.InvalidResponse;
    if (self.finished or part.version != 1 or !std.meta.eql(self.request, item.request) or
        item.rows > page_rows or item.complete > item.rows or item.retention_days == null or
        item.retention_days.? == 0 or item.retention_days.? > 90 or
        item.finished != (item.next == null) or
        (self.retention_days != null and self.retention_days != item.retention_days))
        return error.InvalidResponse;
    try endpoints(item);
    var candidate = self.*;
    try merge(&candidate, item);
    self.* = candidate;
}

fn endpoints(item: *const Window) error{InvalidResponse}!void {
    if ((item.rows == 0) != (item.first == null) or
        (item.first == null) != (item.last == null) or
        (item.rows == 0) != (item.min_revision == null) or
        (item.min_revision == null) != (item.max_revision == null)) return error.InvalidResponse;
    if (item.min_revision) |minimum| {
        if (minimum > item.max_revision.? or item.max_revision.? > std.math.maxInt(i64))
            return error.InvalidResponse;
        if (item.request.revision) |revision| if (minimum != revision or
            item.max_revision.? != revision) return error.InvalidResponse;
    }
    if (item.next) |next| {
        if (item.last == null or !std.meta.eql(next, item.last.?)) return error.InvalidResponse;
    }
    if (item.first) |first| {
        for ([_]Cursor{ first, item.last.? }) |cursor| {
            if (cursor.sequence == 0 or cursor.sequence > std.math.maxInt(i64) or
                std.mem.allEqual(u8, &cursor.boot, 0)) return error.InvalidResponse;
        }
        if (item.request.before) |before| if (!precedes(first, before))
            return error.InvalidResponse;
        if (item.rows == 1 and !std.meta.eql(first, item.last.?)) return error.InvalidResponse;
        if (item.rows > 1 and !precedes(item.last.?, first)) return error.InvalidResponse;
        if (first.minute > item.request.until_minute or
            item.last.?.minute < item.request.from_minute) return error.InvalidResponse;
    }
}

fn merge(self: *Window, item: *const Window) error{InvalidResponse}!void {
    self.hits = sum(self.hits, item.hits);
    self.rows = std.math.add(u32, self.rows, item.rows) catch return error.InvalidResponse;
    self.complete = std.math.add(u32, self.complete, item.complete) catch
        return error.InvalidResponse;
    self.observed_ms = std.math.add(u64, self.observed_ms, item.observed_ms) catch
        return error.InvalidResponse;
    self.ambiguous = self.ambiguous or item.ambiguous;
    self.clipped = self.clipped or item.clipped;
    self.unconfirmed = @max(self.unconfirmed, item.unconfirmed);
    if (item.min_revision) |rev| self.min_revision = @min(self.min_revision orelse rev, rev);
    if (item.max_revision) |rev| self.max_revision = @max(self.max_revision orelse rev, rev);
    self.retention_days = item.retention_days;
    var bin_rows: u64 = 0;
    var bin_complete: u64 = 0;
    var bin_hits: ?u64 = 0;
    for (&self.bins, item.bins) |*bin, added| {
        if (added.complete > added.rows or (added.rows == 0 and added.hits != 0))
            return error.InvalidResponse;
        bin_hits = sum(bin_hits, added.hits);
        bin.hits = sum(bin.hits, added.hits);
        bin.rows = std.math.add(u32, bin.rows, added.rows) catch return error.InvalidResponse;
        bin.complete = std.math.add(u32, bin.complete, added.complete) catch
            return error.InvalidResponse;
        bin_rows += added.rows;
        bin_complete += added.complete;
    }
    if (bin_rows != item.rows or bin_complete != item.complete or bin_hits != item.hits)
        return error.InvalidResponse;
    self.first = self.first orelse item.first;
    self.last = item.last orelse self.last;
    self.next = item.next;
    self.request.before = item.next;
    self.finished = item.finished;
}

/// A bounded read of today's hourly cohorts. Null hours have no retained observations;
/// an incomplete scan cannot be presented as the day's total. Current minutes seal later.
pub const Today = struct {
    hits: ?u64 = null,
    hours: [24]?u64 = @splat(null),
    rows: u32 = 0,
    complete: u32 = 0,
    observed_at: u64 = 0,
    from_minute: u64 = 0,
    partial: bool = false,
    unconfirmed: u64 = 0,

    pub fn jsonStringify(self: Today, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return @import("json_counters.zig").object(self, w);
    }
};
