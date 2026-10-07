//! Owned account-management requests. Password plaintext never crosses the storage mailbox.
const std = @import("std");
const root = @import("root.zig");
pub const capacity = 1024;
pub const page_rows = 8;
pub const temporary_seconds = 3600;

pub const Auth = struct {
    session_digest: [32]u8,
    csrf_digest: [32]u8 = @splat(0),
    require_totp: bool = false,
    /// Address presenting the credential for this request; empty when not captured.
    client: root.Bytes(48) = .{},
};
pub const Query = struct {
    auth: Auth,
    after: u64 = 0,
    limit: u8 = page_rows,
};
pub const Create = struct {
    auth: Auth,
    username: root.Bytes(64),
    role: root.Role,
    password_hash: root.Bytes(255),
};
pub const Change = struct {
    auth: Auth,
    target: u64,
    expected_revision: u64,
    operation: union(enum) {
        access: struct { role: root.Role, disabled: bool },
        password: root.Bytes(255),
        revoke,
        /// Turns off another account's second factor and its recovery codes.
        factor,
    },
};

pub const Row = struct {
    id: u64 = 0,
    username: root.Bytes(64) = .{},
    role: root.Role = .viewer,
    revision: u64 = 0,
    disabled: bool = false,
    must_change: bool = false,
    totp_enabled: bool = false,
    password_expires: u64 = 0,
    last_login: ?u64 = null,

    pub fn jsonStringify(self: Row, writer: *std.json.Stringify) std.json.Stringify.Error!void {
        try writer.beginObject();
        inline for (@typeInfo(Row).@"struct".field_names) |field_name| {
            const FieldType = @FieldType(Row, field_name);
            try writer.objectField(field_name);
            if (FieldType == root.Bytes(64)) {
                try writer.write(@field(self, field_name).slice());
            } else if (FieldType == u64) {
                try root.writeCounter(writer, @field(self, field_name));
            } else if (FieldType == ?u64) {
                if (@field(self, field_name)) |value|
                    try root.writeCounter(writer, value)
                else
                    try writer.write(null);
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
        if (self.next) |value| try root.writeCounter(writer, value) else try writer.write(null);
        try writer.endObject();
    }
};

pub fn validateQuery(input: Query) error{InvalidLimit}!void {
    if (input.after > std.math.maxInt(i64) or input.limit == 0 or input.limit > page_rows)
        return error.InvalidLimit;
}

pub fn validateCreate(input: Create) error{ InvalidLimit, TooLarge }!void {
    if (input.username.len > 64 or input.password_hash.len > 255) return error.TooLarge;
    if (!root.validUsername(input.username.slice()) or input.password_hash.len == 0)
        return error.InvalidLimit;
}

pub fn validateChange(input: Change) error{ InvalidLimit, TooLarge }!void {
    if (input.target == 0 or input.target > std.math.maxInt(i64) or
        input.expected_revision == 0 or input.expected_revision >= std.math.maxInt(i64))
        return error.InvalidLimit;
    if (input.operation == .password) {
        if (input.operation.password.len > 255) return error.TooLarge;
        if (input.operation.password.len == 0) return error.InvalidLimit;
    }
}
