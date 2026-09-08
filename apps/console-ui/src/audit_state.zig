const std = @import("std");
const p = @import("console_protocol");
const decode = @import("json_value.zig").decode;
pub const Kind = enum { query, read, export_page };
const WireRow = struct {
    id: u64,
    actor: u64,
    subject: u64,
    recorded_at: u64,
    action: []const u8,
    target: ?[]const u8,
    actor_role: ?p.Role,
};

pub const Model = struct {
    // Unpublished slots have no readable payload. Count/has_detail gate every access.
    rows: [8]p.audit.Row = undefined,
    detail: p.audit.Detail = undefined,
    has_detail: bool = false,
    count: usize = 0,
    pages: [128]u64 = @splat(0),
    page: usize = 0,
    next: ?u64 = null,
    selected: u64 = 0,
    kind: Kind = .query,
    busy: bool = false,
    loaded: bool = false,
    ticket: p.Bytes(40) = .{},
    actor: p.Bytes(20) = .{},
    action: p.Bytes(48) = .{},
    days: u16 = 7,
    since: u64 = 0,
    until: u64 = 0,

    pub fn clear(self: *Model) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.next = null;
        self.kind = .query;
        self.days = 7;
        self.pages[0] = p.audit.last_id;
    }

    pub fn pageValue(self: *Model, value: std.json.Value, allocator: std.mem.Allocator) !void {
        const wire = try decode(struct {
            version: u8,
            rows: []const WireRow,
            next: ?u64,
        }, value, allocator);
        if (wire.version != 1 or wire.rows.len > self.rows.len) return error.InvalidResponse;
        var candidate: [8]p.audit.Row = undefined;
        var previous = self.pages[self.page];
        for (wire.rows, candidate[0..wire.rows.len], 0..) |row, *item, index| {
            if (row.id > previous or (index != 0 and row.id == previous))
                return error.InvalidResponse;
            try owned(row, item);
            previous = row.id;
        }
        if (wire.next) |next| {
            if (wire.rows.len != 8 or next != previous - 1) return error.InvalidResponse;
        }
        @memcpy(self.rows[0..wire.rows.len], candidate[0..wire.rows.len]);
        self.count = wire.rows.len;
        self.next = wire.next;
        self.loaded = true;
    }

    pub fn detailValue(self: *Model, value: std.json.Value, allocator: std.mem.Allocator) !void {
        const wire = try decode(struct {
            version: u8,
            row: WireRow,
            before: ?[]const u8,
            after: ?[]const u8,
            before_truncated: bool,
            after_truncated: bool,
            before_redacted: bool,
            after_redacted: bool,
        }, value, allocator);
        if (wire.version != 1 or wire.row.id != self.selected) return error.InvalidResponse;
        var candidate: p.audit.Detail = .{ .row = undefined };
        try owned(wire.row, &candidate.row);
        inline for (.{ "before", "after" }) |field| {
            if (@field(wire, field)) |source| {
                if (!std.unicode.utf8ValidateSlice(source)) return error.InvalidResponse;
                @field(candidate, field) = .{};
                try @field(candidate, field).?.set(source);
            }
            @field(candidate, field ++ "_truncated") = @field(wire, field ++ "_truncated");
            @field(candidate, field ++ "_redacted") = @field(wire, field ++ "_redacted");
        }
        self.detail = candidate;
        self.has_detail = true;
    }
};

fn owned(wire: WireRow, output: *p.audit.Row) !void {
    if (wire.id == 0 or wire.id > p.audit.last_id or wire.actor > p.audit.last_id or
        wire.subject > p.audit.last_id or wire.recorded_at > p.audit.last_id or
        wire.action.len == 0 or !std.unicode.utf8ValidateSlice(wire.action))
        return error.InvalidResponse;
    output.* = .{
        .id = wire.id,
        .actor = wire.actor,
        .subject = wire.subject,
        .recorded_at = wire.recorded_at,
        .actor_role = wire.actor_role,
    };
    try output.action.set(wire.action);
    if (wire.target) |target| {
        if (!std.unicode.utf8ValidateSlice(target)) return error.InvalidResponse;
        output.target = .{};
        try output.target.?.set(target);
    }
}
