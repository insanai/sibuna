const std = @import("std");
const p = @import("console_protocol");
pub const Kind = enum { query, create, access, password, revoke };
const WireRow = struct {
    id: u64,
    username: []const u8,
    role: p.Role,
    revision: u64,
    disabled: bool,
    must_change: bool,
    totp_enabled: bool,
    password_expires: u64,
    last_login: ?u64,
};

pub const Model = struct {
    rows: [8]p.users.Row = @splat(.{}),
    count: usize = 0,
    pages: [128]u64 = @splat(0),
    page: usize = 0,
    next: ?u64 = null,
    selected: ?usize = null,
    busy: bool = false,
    loaded: bool = false,
    kind: Kind = .query,
    ticket: p.Bytes(40) = .{},
    self_revoke: bool = false,
    username: p.Bytes(64) = .{},
    role: p.Role = .viewer,
    disabled: bool = false,
    confirmed: bool = false,
    temporary: p.Bytes(64) = .{},
    expires: u64 = 0,

    pub fn clear(self: *Model) void {
        @memset(std.mem.asBytes(self), 0);
        self.next = null;
        self.selected = null;
        self.role = .viewer;
        self.kind = .query;
    }

    pub fn clearSecret(self: *Model) void {
        std.crypto.secureZero(u8, &self.temporary.data);
        self.temporary.len = 0;
        self.expires = 0;
    }

    pub fn decode(self: *Model, value: std.json.Value, allocator: std.mem.Allocator) !void {
        const wire = try @import("json_value.zig").decode(struct {
            version: u8,
            rows: []const WireRow,
            next: ?u64,
        }, value, allocator);
        if (wire.version != 1 or wire.rows.len > self.rows.len) return error.InvalidResponse;
        var rows: [8]p.users.Row = undefined;
        var previous = self.pages[self.page];
        for (wire.rows, rows[0..wire.rows.len]) |row, *item| {
            if (row.id <= previous or row.revision == 0 or !p.validUsername(row.username))
                return error.InvalidResponse;
            previous = row.id;
            item.* = .{
                .id = row.id,
                .username = try p.Bytes(64).init(row.username),
                .role = row.role,
                .revision = row.revision,
                .disabled = row.disabled,
                .must_change = row.must_change,
                .totp_enabled = row.totp_enabled,
                .password_expires = row.password_expires,
                .last_login = row.last_login,
            };
        }
        if (wire.next) |next| {
            if (wire.rows.len == 0 or next != previous) return error.InvalidResponse;
        }
        @memcpy(self.rows[0..wire.rows.len], rows[0..wire.rows.len]);
        self.count = wire.rows.len;
        self.next = wire.next;
        self.selected = null;
        self.loaded = true;
    }
};

test "account pages own names, reject unordered IDs and erase temporary credentials" {
    const t = std.testing;
    var model: Model = .{};
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const page = try std.json.parseFromSlice(std.json.Value, t.allocator,
        \\{"version":1,"next":null,"rows":[{"id":1,"username":"viewer","role":"viewer",
        \\"revision":1,"disabled":false,"must_change":false,"totp_enabled":false,
        \\"password_expires":0,"last_login":null}]}
    , .{});
    defer page.deinit();
    try model.decode(page.value, arena.allocator());
    try t.expectEqualStrings("viewer", model.rows[0].username.slice());
    try t.expect(model.rows[0].last_login == null);
    model.pages[0] = 1;
    try t.expectError(error.InvalidResponse, model.decode(page.value, arena.allocator()));
    try t.expectEqual(@as(usize, 1), model.count);
    model.temporary = try p.Bytes(64).init("one-time secret");
    model.clear();
    try t.expect(model.next == null and model.selected == null and model.temporary.len == 0);
    try t.expect(std.mem.allEqual(u8, &model.temporary.data, 0));
}
