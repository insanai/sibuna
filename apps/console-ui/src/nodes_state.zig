const std = @import("std");
const p = @import("console_protocol");
pub const Kind = enum { idle, status, command, receipt };
/// Decoded `/console/api/nodes` reply: replicated member rows plus this console's probes.
pub const Members = struct {
    self: u32,
    committed: u64,
    storage: p.nodes.Storage,
    members: []const p.nodes.Member,
    probes: []const p.nodes.Probe,
    observed_at: u64,
};
pub const Wire = struct {
    page: struct {
        self: u32,
        committed: u64,
        storage: p.nodes.Storage,
        members: []const p.nodes.Member,
    },
    probes: []const p.nodes.Probe,
    observed_at: u64,
    peers: []const p.nodes.Peer = &.{},
};
pub const Peers = struct {
    self: u32 = 0,
    committed: u64 = 0,
    storage: p.nodes.Storage = .{},
    members: [p.nodes.max_members]p.nodes.Member = undefined,
    count: u8 = 0,
    probes: [p.nodes.max_probes]p.nodes.Probe = undefined,
    probe_count: u8 = 0,
    direct: [p.nodes.max_probes]p.nodes.Peer = undefined,
    direct_count: u8 = 0,
    received_at: u64 = 0,
    loaded: bool = false,
    ticket: p.Bytes(32) = .{},
    busy: bool = false,
};
pub const Input = struct {
    id: p.Bytes(32),
    boot: p.Bytes(32),
    node: u32,
    revision: u64,
    kind: p.nodes.Kind,
};
pub const Model = struct {
    status: ?p.nodes.Status = null,
    receipt: ?p.nodes.Receipt = null,
    pending: ?Input = null,
    attempted: bool = false,
    loaded: bool = false,
    received_at: u64 = 0,
    last_attempt: u64 = 0,
    ticket: p.Bytes(32) = .{},
    busy: Kind = .idle,
    peers: Peers = .{},

    pub fn fresh(self: *const Model, now: u64) bool {
        return self.loaded and now >= self.received_at and now - self.received_at <= 10;
    }

    pub fn statusValue(self: *Model, body: std.json.Value, alloc: std.mem.Allocator) !void {
        var candidate: p.nodes.Status = undefined;
        try @import("json_value.zig").into(&candidate, body, alloc);
        if (candidate.node == 0 or candidate.active_ban_entries > 4096 or
            candidate.control_revision > std.math.maxInt(i64) or
            !identifier(candidate.boot.slice()) or !identifier(candidate.operation_id.slice()))
            return error.InvalidResponse;
        if (candidate.crs) |crs| if (crs.selection) |selection| try selection.validate();
        self.status = candidate;
        self.loaded = true;
    }

    /// Publishes a member page only after every row and probe validates; a rejected reply
    /// keeps the previous page so a transient decode failure cannot blank the cluster view.
    pub fn membersValue(self: *Model, body: std.json.Value, alloc: std.mem.Allocator) !void {
        var wire: Wire = undefined;
        try @import("json_value.zig").into(&wire, body, alloc);
        if (wire.page.self == 0 or wire.page.members.len > p.nodes.max_members or
            wire.probes.len > p.nodes.max_probes or
            wire.peers.len > p.nodes.max_probes) return error.InvalidResponse;
        var peers: Peers = .{
            .self = wire.page.self,
            .committed = wire.page.committed,
            .storage = wire.page.storage,
            .received_at = 0,
            .loaded = true,
            .ticket = self.peers.ticket,
        };
        for (wire.page.members) |member| {
            if (member.node == 0 or (member.console_url.len != 0 and
                !p.nodes.safeUrl(member.console_url.slice()))) return error.InvalidResponse;
            for (peers.members[0..peers.count]) |seen| {
                if (seen.node == member.node) return error.InvalidResponse;
            }
            peers.members[peers.count] = member;
            peers.count += 1;
        }
        for (wire.probes) |probe| {
            if (probe.node == 0) return error.InvalidResponse;
            peers.probes[peers.probe_count] = probe;
            peers.probe_count += 1;
        }
        for (wire.peers) |direct| {
            if (direct.node == 0 or direct.node == peers.self or
                (direct.boot == null) != (direct.requests == null) or
                (direct.requests == null) != (direct.age_seconds == null))
                return error.InvalidResponse;
            if (direct.boot) |boot| if (!identifier(boot.slice())) return error.InvalidResponse;
            for (peers.direct[0..peers.direct_count]) |seen|
                if (seen.node == direct.node) return error.InvalidResponse;
            peers.direct[peers.direct_count] = direct;
            peers.direct_count += 1;
        }
        self.peers = peers;
    }

    pub fn receiptValue(self: *Model, body: std.json.Value, alloc: std.mem.Allocator) !void {
        const pending = self.pending orelse return error.InvalidResponse;
        var candidate: p.nodes.Receipt = undefined;
        try @import("json_value.zig").into(&candidate, body, alloc);
        if (!std.mem.eql(u8, candidate.id.slice(), pending.id.slice()) or
            !std.mem.eql(u8, candidate.boot.slice(), pending.boot.slice()) or
            candidate.node != pending.node or candidate.kind != pending.kind or
            candidate.expected_revision != pending.revision) return error.InvalidResponse;
        // An intent cannot establish a local effect, even if a malformed response includes
        // completion fields. Publish only a receipt whose identity and state agree.
        const terminal = candidate.state == .applied or candidate.state == .rejected;
        if ((candidate.completed_at != null) != terminal or
            (candidate.completion_persisted and !terminal)) return error.InvalidResponse;
        if (candidate.state == .applied) {
            if (pending.revision >= std.math.maxInt(i64) or
                candidate.applied_revision != pending.revision + 1 or
                (candidate.cleared_entries != null) != (candidate.kind == .clear_local_bans))
                return error.InvalidResponse;
        } else if (candidate.applied_revision != null or candidate.cleared_entries != null)
            return error.InvalidResponse;
        if ((candidate.cleared_entries orelse 0) > 4096) return error.InvalidResponse;
        self.receipt = candidate;
        if (candidate.completion_persisted) self.pending = null;
    }
};

fn identifier(text: []const u8) bool {
    if (text.len != 32) return false;
    var nonzero = false;
    for (text) |byte| {
        if (!std.ascii.isHex(byte)) return false;
        nonzero = nonzero or byte != '0';
    }
    return nonzero;
}

test "CRS node observations retain exact revisions and refuse invalid source metadata" {
    const t = std.testing;
    const bytes =
        \\{"operation_id":"11111111111111111111111111111111","node":1,
        \\ "boot":"22222222222222222222222222222222","control_revision":"1",
        \\ "draining":false,"connections":0,"active_ban_entries":0,"committed":"3",
        \\ "applied":"3","observed_at":"4","uptime_ms":"5000",
        \\ "completion_pending":false,"crs":{"selection":{"mode":"audit",
        \\ "profile":"full","revision":"18446744073709551615","release":"4.30.0",
        \\ "source_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\ "operator_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\ "blocking_paranoia":1,"detection_paranoia":2,"inbound_threshold":5,
        \\ "outbound_threshold":4,"compiled_peak":"20","reserved_bytes":"30",
        \\ "slots":2,"request_bytes":"4194304","response_bytes":"1048576",
        \\ "work_budget":"16000000","timeout_ms":"30000"},
        \\ "counts":{"incomplete":"18446744073709551615"}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, bytes, .{});
    defer parsed.deinit();
    var model: Model = .{};
    try model.statusValue(parsed.value, t.allocator);
    try t.expectEqual(std.math.maxInt(u64), model.status.?.crs.?.selection.?.revision);
    try t.expectEqual(std.math.maxInt(u64), model.status.?.crs.?.counts.incomplete);
    const previous = model.status.?;
    var invalid = previous;
    try invalid.crs.?.selection.?.release.set("....");
    const encoded = try std.json.Stringify.valueAlloc(t.allocator, invalid, .{});
    defer t.allocator.free(encoded);
    const changed = try std.json.parseFromSlice(std.json.Value, t.allocator, encoded, .{});
    defer changed.deinit();
    try t.expectError(error.InvalidCrsStatus, model.statusValue(changed.value, t.allocator));
    try t.expectEqualDeep(previous, model.status.?);
}
