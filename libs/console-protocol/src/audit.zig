//! Bounded audit views contain only recorded metadata and redacted summaries.
const std = @import("std");
const p = @import("root.zig");
pub const page_rows = 8;
pub const last_id = std.math.maxInt(i64);
pub const Query = struct {
    auth: p.users.Auth,
    before: u64 = last_id,
    actor: ?u64 = null,
    action: p.Bytes(48) = .{},
    since: u64 = 0,
    until: u64 = last_id,
    export_page: bool = false,
};
pub const Read = struct { auth: p.users.Auth, id: u64 };
pub const Row = struct {
    id: u64 = 0,
    actor: u64 = 0,
    subject: u64 = 0,
    recorded_at: u64 = 0,
    action: p.Bytes(48) = .{},
    target: ?p.Bytes(64) = null,
    actor_role: ?p.Role = null,

    pub fn jsonStringify(self: Row, json: *std.json.Stringify) !void {
        try json.beginObject();
        inline for (@typeInfo(Row).@"struct".fields) |field| {
            try json.objectField(field.name);
            const value = @field(self, field.name);
            if (field.type == u64) {
                try p.writeCounter(json, value);
            } else if (field.type == p.Bytes(48)) {
                try json.write(value.slice());
            } else if (field.type == ?p.Bytes(64)) {
                if (value) |text| try json.write(text.slice()) else try json.write(null);
            } else try json.write(value);
        }
        try json.endObject();
    }
};
pub const Page = struct {
    rows: [page_rows]Row = @splat(.{}),
    count: usize = 0,
    next: ?u64 = null,

    pub fn jsonStringify(self: Page, json: *std.json.Stringify) !void {
        std.debug.assert(self.count <= self.rows.len);
        try json.beginObject();
        try json.objectField("version");
        try json.write(@as(u8, 1));
        try json.objectField("rows");
        try json.write(self.rows[0..self.count]);
        try json.objectField("next");
        if (self.next) |id| try p.writeCounter(json, id) else try json.write(null);
        try json.endObject();
    }
};
pub const Detail = struct {
    row: Row,
    before: ?p.Bytes(1024) = null,
    after: ?p.Bytes(1024) = null,
    before_truncated: bool = false,
    after_truncated: bool = false,
    before_redacted: bool = false,
    after_redacted: bool = false,

    pub fn jsonStringify(self: Detail, json: *std.json.Stringify) !void {
        try json.beginObject();
        try json.objectField("version");
        try json.write(@as(u8, 1));
        try json.objectField("row");
        try json.write(self.row);
        inline for (.{ "before", "after" }) |field| {
            try json.objectField(field);
            if (@field(self, field)) |value|
                try json.write(value.slice())
            else
                try json.write(null);
            try json.objectField(field ++ "_truncated");
            try json.write(@field(self, field ++ "_truncated"));
            try json.objectField(field ++ "_redacted");
            try json.write(@field(self, field ++ "_redacted"));
        }
        try json.endObject();
    }
};

pub fn validate(input: Query) error{InvalidLimit}!void {
    if (input.before > last_id or input.since > input.until or input.until > last_id or
        input.action.len > 48) return error.InvalidLimit;
    if (input.actor) |actor| if (actor > last_id) return error.InvalidLimit;
    for (input.action.slice()) |byte| {
        if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '.' and byte != '_')
            return error.InvalidLimit;
    }
}
