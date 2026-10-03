//! Local command identity includes a boot and expected control revision. A durable intent
//! alone never proves a runtime effect; callers retain the operation id across retries.
const std = @import("std");
const p = @import("root.zig");
pub const Kind = enum { drain, @"resume", clear_local_bans };
pub const command_seconds = 30;
pub const receipt_days = 30;
pub const command_capacity = 4096;
pub const State = enum { intent, applied, rejected, uncertain };
pub const max_members = 9;
pub const max_probes = 8;
/// Bounded so a full page stays within the fixed storage-result envelope.
pub const max_address = 64;
pub const max_url = 128;
pub const Role = enum { unknown, single, leader, follower, candidate };
pub const Health = enum { unknown, healthy, degraded, down };
/// One console's view of its cluster: itself plus every configured peer probe. Peers
/// without an observation count as unknown, never as healthy zeros.
pub const Summary = struct {
    healthy: u8 = 0,
    degraded: u8 = 0,
    down: u8 = 0,
    unknown: u8 = 0,

    pub fn total(self: Summary) u16 {
        return @as(u16, self.healthy) + self.degraded + self.down + self.unknown;
    }
};
/// Storage-owned view of the local member's consensus state; stale values keep their
/// last observation and `quorum` becomes false rather than inventing progress.
pub const Storage = struct {
    role: Role = .unknown,
    leader: ?u32 = null,
    term: u64 = 0,
    decided: u64 = 0,
    applied: u64 = 0,
    durable: u64 = 0,
    quorum: bool = false,
    observed_at: u64 = 0,

    pub fn jsonStringify(self: Storage, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, w);
    }
};
pub const Member = struct {
    node: u32,
    address: p.Bytes(max_address) = .{},
    console_url: p.Bytes(max_url) = .{},
    version: p.Bytes(32) = .{},
    boot: p.Bytes(32) = .{},
    first_seen: u64 = 0,
    last_seen: u64 = 0,
    applied_revision: u64 = 0,
    control_revision: u64 = 0,
    applied_slot: u64 = 0,
    decided_slot: u64 = 0,
    draining: bool = false,

    pub fn jsonStringify(self: Member, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, w);
    }
};
/// One configured peer's most recent data-plane probe. `requests` is the counter delta
/// between the last two successful probes, not a rate; zero means not yet observed twice.
pub const Probe = struct {
    node: u32,
    health: Health = .unknown,
    latency_ms: u32 = 0,
    last_seen: u64 = 0,
    observed_at: u64 = 0,
    draining: bool = false,
    requests: u64 = 0,

    pub fn jsonStringify(self: Probe, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, w);
    }
};
/// Direct local-only telemetry received over an authenticated management connection.
pub const PeerStatus = enum { unobserved, connecting, current, stale, rejected };
pub const Peer = struct {
    node: u32,
    status: PeerStatus,
    boot: ?p.Bytes(32) = null,
    age_seconds: ?u64 = null,
    clock_skew_seconds: ?u64 = null,
    sequence: u64 = 0,
    watermark: u64 = 0,
    resets: u64 = 0,
    requests: ?u64 = null,
    sample_loss: ?u64 = null,
    geoip_available: bool = false,
    rss_kib: ?u64 = null,
    cpu_permille: ?u32 = null,

    pub fn jsonStringify(self: Peer, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, w);
    }
};
pub const Page = struct {
    self: u32,
    committed: u64,
    storage: Storage,
    members: [max_members]Member = undefined,
    count: u8 = 0,

    pub fn jsonStringify(self: Page, w: *std.json.Stringify) std.json.Stringify.Error!void {
        try w.beginObject();
        try w.objectField("self");
        try w.write(self.self);
        try w.objectField("committed");
        try p.writeCounter(w, self.committed);
        try w.objectField("storage");
        try w.write(self.storage);
        try w.objectField("members");
        try w.beginArray();
        for (self.members[0..self.count]) |member| try w.write(member);
        try w.endArray();
        try w.endObject();
    }
};

/// Console links rendered from replicated rows must be plain http(s) origins.
pub fn safeUrl(text: []const u8) bool {
    if (text.len == 0 or text.len > max_url) return false;
    if (!std.mem.startsWith(u8, text, "https://") and !std.mem.startsWith(u8, text, "http://"))
        return false;
    for (text) |byte| if (byte <= 32 or byte >= 127 or byte == '"' or byte == '\'' or byte == '<')
        return false;
    return true;
}

pub const Command = struct {
    auth: p.users.Auth,
    id: [16]u8,
    boot: [16]u8,
    node: u32,
    expected_revision: u64,
    expires: u64,
    kind: Kind,
};
pub const Read = struct { auth: p.users.Auth, id: [16]u8 };
pub const Status = struct {
    operation_id: p.Bytes(32),
    receipt_retention_days: u16 = receipt_days,
    command_capacity: u16 = 4096,
    node: u32,
    boot: p.Bytes(32),
    control_revision: u64,
    draining: bool,
    connections: u32,
    active_ban_entries: u32,
    committed: u64,
    applied: u64,
    observed_at: u64,
    uptime_ms: u64,
    completion_pending: bool,

    pub fn jsonStringify(self: Status, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, w);
    }
};
pub const Receipt = struct {
    id: p.Bytes(32),
    boot: p.Bytes(32),
    node: u32,
    kind: Kind,
    state: State,
    expected_revision: u64,
    applied_revision: ?u64 = null,
    cleared_entries: ?u32 = null,
    requested_at: u64,
    completed_at: ?u64 = null,
    completion_persisted: bool = false,

    pub fn jsonStringify(self: Receipt, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, w);
    }
};

pub fn validate(input: Command) error{InvalidLimit}!void {
    if (input.node == 0 or input.expected_revision >= std.math.maxInt(i64) or
        input.expires > std.math.maxInt(i64) or
        std.mem.allEqual(u8, &input.id, 0) or std.mem.allEqual(u8, &input.boot, 0))
        return error.InvalidLimit;
}

fn fields(value: anytype, w: *std.json.Stringify) std.json.Stringify.Error!void {
    try w.beginObject();
    inline for (@typeInfo(@TypeOf(value)).@"struct".field_names) |field_name| {
        const FieldType = @FieldType(@TypeOf(value), field_name);
        try w.objectField(field_name);
        const item = @field(value, field_name);
        if (FieldType == p.Bytes(32) or FieldType == p.Bytes(max_address) or
            FieldType == p.Bytes(max_url))
        {
            try w.write(item.slice());
        } else if (FieldType == ?p.Bytes(32)) {
            if (item) |text| try w.write(text.slice()) else try w.write(null);
        } else if (FieldType == u64) {
            try p.writeCounter(w, item);
        } else if (FieldType == ?u64) {
            if (item) |number| try p.writeCounter(w, number) else try w.write(null);
        } else try w.write(item);
    }
    try w.endObject();
}

test "console links from replicated rows are restricted to plain origins" {
    const t = std.testing;
    try t.expect(safeUrl("https://console.example:9443"));
    try t.expect(safeUrl("http://127.0.0.1:9443"));
    try t.expect(!safeUrl("javascript:alert(1)"));
    try t.expect(!safeUrl("https://a\"b"));
    try t.expect(!safeUrl(""));
}
