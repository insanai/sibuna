//! Recorded findings are a separate population from exact external-request outcomes.
//! Ranges are half-open, frozen by the caller, and limited to incident retention.
const std = @import("std");
const p = @import("root.zig");
pub const buckets = 12;
pub const Module = enum { inspection, honeypot, other };
pub const View = enum { modules, categories, paths };

pub fn classify(category: []const u8) Module {
    if (std.mem.startsWith(u8, category, "waf:") or
        std.mem.startsWith(u8, category, "audit:")) return .inspection;
    if (std.mem.eql(u8, category, "honeypot")) return .honeypot;
    return .other;
}
pub const Request = struct {
    view: View = .modules,
    node: u32 = 0,
    from: u64,
    until: u64,
};
pub const Query = struct {
    session_digest: [32]u8,
    require_totp: bool = false,
    request: Request,
};
pub const Rank = struct {
    label: p.Bytes(96) = .{},
    count: u64 = 0,
    truncated: bool = false,

    pub fn jsonStringify(self: Rank, w: *std.json.Stringify) !void {
        try w.beginObject();
        try w.objectField("label");
        try w.write(self.label.slice());
        try w.objectField("count");
        try p.writeCounter(w, self.count);
        try w.objectField("truncated");
        try w.write(self.truncated);
        try w.endObject();
    }
};
pub const Findings = struct {
    total: u64 = 0,
    trend: [buckets]u64 = @splat(0),
    sources: [3]?Rank = @splat(null),

    pub fn jsonStringify(self: Findings, w: *std.json.Stringify) !void {
        try w.beginObject();
        try w.objectField("total");
        try p.writeCounter(w, self.total);
        try w.objectField("trend");
        try w.beginArray();
        for (self.trend) |count| try p.writeCounter(w, count);
        try w.endArray();
        try w.objectField("sources");
        try w.write(self.sources);
        try w.endObject();
    }
};
pub const Page = struct {
    request: Request,
    observed_at: u64,
    modules: [3]Findings = @splat(.{}),
    rows: [5]?Rank = @splat(null),
    /// Total recorded findings, including categories outside the top five.
    total: u64 = 0,

    pub fn jsonStringify(self: Page, w: *std.json.Stringify) !void {
        try w.beginObject();
        try w.objectField("request");
        try w.write(self.request);
        try w.objectField("observed_at");
        try w.write(self.observed_at);
        try w.objectField("total");
        try p.writeCounter(w, self.total);
        try w.objectField("modules");
        try w.write(self.modules);
        try w.objectField("rows");
        try w.write(self.rows);
        try w.endObject();
    }
};

pub fn validate(query: Query) error{InvalidLimit}!void {
    const r = query.request;
    if (r.from >= r.until or r.until > std.math.maxInt(i64) or
        r.until - r.from > 30 * 86400 or r.node >= 1 << 23) return error.InvalidLimit;
}

test "security windows cannot overflow buckets or exceed incident retention" {
    const t = std.testing;
    try validate(.{ .session_digest = @splat(0), .request = .{ .from = 1, .until = 2 } });
    try t.expectError(error.InvalidLimit, validate(.{
        .session_digest = @splat(0),
        .request = .{ .from = 0, .until = 30 * 86400 + 1 },
    }));
    try t.expectError(error.InvalidLimit, validate(.{
        .session_digest = @splat(0),
        .request = .{ .from = 1, .until = 1 },
    }));
}
