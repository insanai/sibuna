//! Local command identity includes a boot and expected control revision. A durable intent
//! alone never proves a runtime effect; callers retain the operation id across retries.
const std = @import("std");
const p = @import("root.zig");
pub const Kind = enum { drain, @"resume", clear_local_bans };
pub const command_seconds = 30;
pub const receipt_days = 30;
pub const command_capacity = 4096;
pub const State = enum { intent, applied, rejected, uncertain };
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
    inline for (@typeInfo(@TypeOf(value)).@"struct".fields) |field| {
        try w.objectField(field.name);
        const item = @field(value, field.name);
        if (field.type == p.Bytes(32)) {
            try w.write(item.slice());
        } else if (field.type == u64) {
            try p.writeCounter(w, item);
        } else if (field.type == ?u64) {
            if (item) |number| try p.writeCounter(w, number) else try w.write(null);
        } else try w.write(item);
    }
    try w.endObject();
}
