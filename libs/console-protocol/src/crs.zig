//! Copied local generation metadata. This is an observation, never a durable
//! activation receipt or an assertion about a different node's applied state.
const std = @import("std");
const p = @import("root.zig");
pub const Mode = enum { off, audit, enforce };
pub const Profile = enum { headers, full };
pub const Selection = struct {
    mode: Mode,
    profile: Profile,
    revision: u64,
    release: p.Bytes(17) = .{},
    source_digest: p.Bytes(64) = .{},
    operator_digest: p.Bytes(64) = .{},
    blocking_paranoia: u8,
    detection_paranoia: u8,
    inbound_threshold: u16,
    outbound_threshold: u16,
    compiled_peak: u64,
    reserved_bytes: u64,
    slots: u8,
    /// Derived from spare reservation; zero from nodes that predate tiered pools.
    small_slots: u16 = 0,
    request_bytes: u64,
    response_bytes: u64,
    work_budget: u64,
    timeout_ms: u64,

    pub fn validate(self: Selection) error{InvalidCrsStatus}!void {
        if (self.revision == 0 or self.blocking_paranoia < 1 or
            self.blocking_paranoia > 4 or self.detection_paranoia < self.blocking_paranoia or
            self.detection_paranoia > 4 or self.inbound_threshold == 0 or
            self.outbound_threshold == 0) return error.InvalidCrsStatus;
        const source = self.release.len != 0;
        if (source != (self.source_digest.len != 0) or
            source != (self.operator_digest.len != 0)) return error.InvalidCrsStatus;
        if (source) {
            if (!digest(self.source_digest.slice()) or !digest(self.operator_digest.slice()))
                return error.InvalidCrsStatus;
            try release(self.release.slice());
        }
        if (self.mode != .off and !source) return error.InvalidCrsStatus;
        if (self.mode == .off and (self.reserved_bytes != 0 or self.slots != 0 or
            self.small_slots != 0)) return error.InvalidCrsStatus;
        if (@as(usize, self.slots) + self.small_slots > 1024) return error.InvalidCrsStatus;
        if (self.mode != .off and (self.slots == 0 or self.slots > 31 or
            self.reserved_bytes == 0)) return error.InvalidCrsStatus;
        if (self.request_bytes == 0 or self.request_bytes > 64 * 1024 * 1024 or
            self.response_bytes == 0 or self.response_bytes > 64 * 1024 * 1024 or
            self.work_budget == 0 or self.work_budget > 1_000_000_000 or
            self.timeout_ms < 1000 or self.timeout_ms > 300_000) return error.InvalidCrsStatus;
    }

    pub fn jsonStringify(self: Selection, json: *std.json.Stringify) !void {
        try @import("json_counters.zig").object(self, json);
    }
};
pub const Counts = struct {
    inspected: u64 = 0,
    headers: u64 = 0,
    handshake: u64 = 0,
    streaming: u64 = 0,
    incomplete: u64 = 0,
    denied: u64 = 0,
    would_deny: u64 = 0,

    pub fn jsonStringify(self: Counts, json: *std.json.Stringify) !void {
        try @import("json_counters.zig").object(self, json);
    }
};
pub const Status = struct {
    selection: ?Selection = null,
    counts: Counts = .{},
};

fn digest(value: []const u8) bool {
    if (value.len != 64) return false;
    for (value) |byte| if (!std.ascii.isHex(byte)) return false;
    return true;
}

fn release(value: []const u8) error{InvalidCrsStatus}!void {
    var parts = std.mem.splitScalar(u8, value, '.');
    for (0..3) |_| {
        const part = parts.next() orelse return error.InvalidCrsStatus;
        if (part.len == 0) return error.InvalidCrsStatus;
        for (part) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidCrsStatus;
        _ = std.fmt.parseInt(u16, part, 10) catch return error.InvalidCrsStatus;
    }
    if (parts.next() != null) return error.InvalidCrsStatus;
}
