//! Observe committed numeric bucket transitions without changing evaluator semantics.
//! Caller-reserved rows belong to one transaction; no operand bytes are retained.
const std = @import("std");
const Phase = @import("model.zig").Phase;
pub const bucket_count = 8;
pub const Row = struct {
    rule_id: u32 = 0,
    phase: Phase = .request_headers,
    delta: [bucket_count]i64 = @splat(0),
    writes: [bucket_count]u32 = @splat(0),
    unknown: u8 = 0,

    pub fn value(self: *const Row, bucket: usize) ?i64 {
        std.debug.assert(bucket < bucket_count);
        const bit = @as(u8, 1) << @as(u3, @intCast(bucket));
        if (self.writes[bucket] == 0 or self.unknown & bit != 0) return null;
        return self.delta[bucket];
    }

    pub fn observed(self: *const Row) bool {
        for (self.writes) |count| if (count != 0) return true;
        return false;
    }
};

pub const Journal = struct {
    rows: []Row,
    owner: ?usize = null,

    pub fn reset(self: *Journal) void {
        self.owner = null;
        @memset(self.rows, .{});
    }

    pub fn bind(self: *Journal, root: usize, id: u32, phase: Phase) void {
        std.debug.assert(self.owner == null and root < self.rows.len and id != 0);
        const row = &self.rows[root];
        std.debug.assert(row.rule_id == 0 or (row.rule_id == id and row.phase == phase));
        row.rule_id = id;
        row.phase = phase;
        self.owner = root;
    }

    pub fn unbind(self: *Journal) void {
        std.debug.assert(self.owner != null);
        self.owner = null;
    }

    /// The store calls this after its last fallible operation and successful commit.
    /// Unknown observations never throw or change work, values or transaction health.
    pub fn committed(
        self: *Journal,
        key: []const u8,
        before: ?[]const u8,
        after: ?[]const u8,
    ) void {
        const root = self.owner orelse return;
        const bucket = classify(key) orelse return;
        const row = &self.rows[root];
        const bit = @as(u8, 1) << @as(u3, @intCast(bucket));
        row.writes[bucket] = std.math.add(u32, row.writes[bucket], 1) catch {
            row.unknown |= bit;
            return;
        };
        if (row.unknown & bit != 0) return;
        const left = numeric(before) orelse {
            row.unknown |= bit;
            return;
        };
        const right = numeric(after) orelse {
            row.unknown |= bit;
            return;
        };
        const change = std.math.sub(i64, right, left) catch {
            row.unknown |= bit;
            return;
        };
        row.delta[bucket] = std.math.add(i64, row.delta[bucket], change) catch {
            row.unknown |= bit;
            return;
        };
    }
};

/// The terminal digit determines paranoia. Length checks also exclude rollups and
/// category counters before touching their contents; matching follows TX case rules.
pub fn classify(key: []const u8) ?usize {
    const inbound = "inbound_anomaly_score_pl";
    const outbound = "outbound_anomaly_score_pl";
    const is_inbound = key.len == inbound.len + 1 and
        std.ascii.eqlIgnoreCase(key[0..inbound.len], inbound);
    const is_outbound = key.len == outbound.len + 1 and
        std.ascii.eqlIgnoreCase(key[0..outbound.len], outbound);
    const offset: usize = if (is_inbound) 0 else if (is_outbound) 4 else return null;
    const digit = key[key.len - 1];
    if (digit < '1' or digit > '4') return null;
    return offset + digit - '1';
}

fn numeric(value: ?[]const u8) ?i64 {
    const bytes = value orelse return 0;
    if (bytes.len == 0 or bytes.len > 20) return null;
    const sign: usize = if (bytes[0] == '-' or bytes[0] == '+') 1 else 0;
    if (sign == bytes.len) return null;
    for (bytes[sign..]) |byte| if (!std.ascii.isDigit(byte)) return null;
    return std.fmt.parseInt(i64, bytes, 10) catch null;
}

test {
    _ = @import("score_journal_test.zig");
    _ = @import("score_execution_test.zig");
}
