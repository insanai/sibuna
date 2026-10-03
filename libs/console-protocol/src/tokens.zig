//! Automation permissions are explicit endpoint capabilities, independent of browser roles.
//! Credentials contain 256 random bits; records and mailboxes carry only their digest.
const std = @import("std");
const p = @import("root.zig");
pub const capacity = 1024;
pub const page_rows = 8;
pub const Scope = enum(u5) {
    stats_read,
    events_read,
    policy_read,
    policy_write,
    geoip_read,
    geoip_write,
    users_read,
    users_write,

    pub fn action(self: Scope) p.Action {
        return switch (self) {
            .policy_write => .manage_policy,
            .geoip_write => .manage_settings,
            .users_write => .manage_users,
            else => .read,
        };
    }

    pub fn bit(self: Scope) u32 {
        return @as(u32, 1) << @backingInt(self);
    }
};
pub const known_scopes = (@as(u32, 1) << @typeInfo(Scope).@"enum".field_names.len) - 1;
pub const Query = struct { auth: p.users.Auth, after: u64 = 0, limit: u8 = page_rows };
pub const Create = struct {
    auth: p.users.Auth,
    label: p.Bytes(64),
    role: p.Role,
    scopes: u32,
    expires: ?u64 = null,
    digest: [32]u8,
};
pub const Revoke = struct {
    auth: p.users.Auth,
    target: u64,
    expected_revision: u64,
    // Inactive metadata may be removed explicitly; the redacted audit remains retained.
    remove: bool = false,
};
pub const Row = struct {
    id: u64 = 0,
    revision: u64 = 0,
    label: p.Bytes(64) = .{},
    role: p.Role = .viewer,
    scopes: u32 = 0,
    created_by: u64 = 0,
    created_at: u64 = 0,
    expires: ?u64 = null,
    disabled: bool = false,
    active: bool = false,

    pub fn jsonStringify(self: Row, writer: *std.json.Stringify) std.json.Stringify.Error!void {
        try writer.beginObject();
        inline for (@typeInfo(Row).@"struct".field_names) |field_name| {
            const FieldType = @FieldType(Row, field_name);
            try writer.objectField(field_name);
            if (FieldType == p.Bytes(64)) {
                try writer.write(@field(self, field_name).slice());
            } else if (FieldType == u64) {
                try p.writeCounter(writer, @field(self, field_name));
            } else if (FieldType == ?u64) {
                if (@field(self, field_name)) |value|
                    try p.writeCounter(writer, value)
                else
                    try writer.write(null);
            } else if (std.mem.eql(u8, field_name, "scopes")) {
                try writeScopes(self.scopes, writer);
            } else try writer.write(@field(self, field_name));
        }
        try writer.endObject();
    }
};
pub const Page = struct {
    rows: [page_rows]Row = @splat(.{}),
    count: usize = 0,
    next: ?u64 = null,

    pub fn jsonStringify(self: Page, writer: *std.json.Stringify) std.json.Stringify.Error!void {
        std.debug.assert(self.count <= self.rows.len);
        try writer.beginObject();
        try writer.objectField("version");
        try writer.write(@as(u8, 1));
        try writer.objectField("rows");
        try writer.write(self.rows[0..self.count]);
        try writer.objectField("next");
        if (self.next) |value| try p.writeCounter(writer, value) else try writer.write(null);
        try writer.endObject();
    }
};

pub fn writeScopes(scopes: u32, writer: *std.json.Stringify) std.json.Stringify.Error!void {
    std.debug.assert(scopes & ~known_scopes == 0);
    try writer.beginArray();
    inline for (@typeInfo(Scope).@"enum".field_names) |field_name| {
        const scope: Scope = @field(Scope, field_name);
        if (scopes & scope.bit() != 0) try writer.write(scope);
    }
    try writer.endArray();
}

pub fn validScopes(scopes: u32, role: p.Role) bool {
    if (scopes == 0 or scopes & ~known_scopes != 0) return false;
    inline for (@typeInfo(Scope).@"enum".field_names) |field_name| {
        const scope: Scope = @field(Scope, field_name);
        if (scopes & scope.bit() != 0 and !role.allows(scope.action())) return false;
    }
    return true;
}

pub fn validLabel(label: []const u8) bool {
    if (label.len == 0 or label.len > 64 or !std.unicode.utf8ValidateSlice(label)) return false;
    for (label) |byte| if (byte < 32 or byte == 127) return false;
    return std.mem.trim(u8, label, " ").len != 0;
}

pub fn validateCreate(input: Create) error{ InvalidLimit, TooLarge }!void {
    if (input.label.len > 64) return error.TooLarge;
    if (!validLabel(input.label.slice()) or !validScopes(input.scopes, input.role))
        return error.InvalidLimit;
    if (input.expires) |expires| {
        if (expires == 0 or expires > std.math.maxInt(i64)) return error.InvalidLimit;
    }
}

pub fn validateRevoke(input: Revoke) error{InvalidLimit}!void {
    if (input.target == 0 or input.target > std.math.maxInt(i64) or
        input.expected_revision == 0 or input.expected_revision >= std.math.maxInt(i64))
        return error.InvalidLimit;
}

test "token scopes reject unknown capabilities and permissions above their role" {
    const t = std.testing;
    try t.expect(validScopes(Scope.stats_read.bit() | Scope.events_read.bit(), .viewer));
    try t.expect(!validScopes(Scope.policy_write.bit(), .viewer));
    try t.expect(validScopes(Scope.policy_read.bit() | Scope.policy_write.bit(), .operator));
    try t.expect(!validScopes(Scope.users_write.bit(), .operator));
    try t.expect(validScopes(known_scopes, .admin));
    try t.expect(!validScopes(0, .admin));
    try t.expect(!validScopes(known_scopes + 1, .admin));
    try t.expect(validLabel("production deploy 日本"));
    try t.expect(!validLabel("\xff"));
    try t.expect(!validLabel("line\nbreak"));
    try t.expect(!validLabel("   "));
}
