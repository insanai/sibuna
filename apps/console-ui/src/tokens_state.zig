const std = @import("std");
const p = @import("console_protocol");
pub const Kind = enum { query, create, revoke, remove };
const WireRow = struct {
    id: u64,
    revision: u64,
    label: []const u8,
    role: p.Role,
    scopes: []const p.tokens.Scope,
    created_by: u64,
    created_at: u64,
    expires: ?u64,
    disabled: bool,
    active: bool,
};

pub const Model = struct {
    rows: [8]p.tokens.Row = @splat(.{}),
    count: usize = 0,
    pages: [128]u64 = @splat(0),
    page: usize = 0,
    next: ?u64 = null,
    selected: ?usize = null,
    busy: bool = false,
    loaded: bool = false,
    kind: Kind = .query,
    ticket: p.Bytes(40) = .{},
    label: p.Bytes(64) = .{},
    role: p.Role = .viewer,
    scopes: u32 = 0,
    days: u8 = 7,
    confirmed: bool = false,
    secret: p.Bytes(64) = .{},
    issued_id: u64 = 0,
    expires: ?u64 = null,

    pub fn clear(self: *Model) void {
        @memset(std.mem.asBytes(self), 0);
        self.next = null;
        self.selected = null;
        self.expires = null;
        self.role = .viewer;
        self.kind = .query;
        self.days = 7;
    }

    pub fn clearSecret(self: *Model) void {
        std.crypto.secureZero(u8, &self.secret.data);
        self.secret.len = 0;
        self.issued_id = 0;
        self.expires = null;
    }

    pub fn decode(self: *Model, value: std.json.Value, allocator: std.mem.Allocator) !void {
        const wire = try @import("json_value.zig").decode(struct {
            version: u8,
            rows: []const WireRow,
            next: ?u64,
        }, value, allocator);
        if (wire.version != 1 or wire.rows.len > self.rows.len) return error.InvalidResponse;
        var rows: [8]p.tokens.Row = undefined;
        var previous = self.pages[self.page];
        for (wire.rows, rows[0..wire.rows.len]) |row, *item| {
            if (row.id <= previous or !positive(row.id) or !positive(row.revision) or
                !positive(row.created_by) or !p.tokens.validLabel(row.label) or
                row.created_at > std.math.maxInt(i64) or (row.disabled and row.active))
                return error.InvalidResponse;
            if (row.expires) |expires| {
                if (!positive(expires) or expires <= row.created_at) return error.InvalidResponse;
            }
            var scopes: u32 = 0;
            for (row.scopes) |scope| {
                if (scopes & scope.bit() != 0) return error.InvalidResponse;
                scopes |= scope.bit();
            }
            if (!p.tokens.validScopes(scopes, row.role)) return error.InvalidResponse;
            previous = row.id;
            item.* = .{
                .id = row.id,
                .revision = row.revision,
                .label = try p.Bytes(64).init(row.label),
                .role = row.role,
                .scopes = scopes,
                .created_by = row.created_by,
                .created_at = row.created_at,
                .expires = row.expires,
                .disabled = row.disabled,
                .active = row.active,
            };
        }
        if (wire.next) |next| {
            if (wire.rows.len != self.rows.len or next != previous) return error.InvalidResponse;
        }
        @memcpy(self.rows[0..wire.rows.len], rows[0..wire.rows.len]);
        self.count = wire.rows.len;
        self.next = wire.next;
        self.selected = null;
        self.loaded = true;
    }
};

pub fn positive(value: u64) bool {
    return value != 0 and value <= std.math.maxInt(i64);
}
