const std = @import("std");
const p = @import("console_protocol");
pub const Kind = enum { idle, status, command, receipt };
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
        self.status = candidate;
        self.loaded = true;
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
