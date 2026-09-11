const std = @import("std");
const Bytes = @import("root.zig").Bytes;

pub const Query = struct {
    session_digest: [32]u8,
    require_totp: bool = false,
    offset: u8 = 0,
    applied: ?u64 = null,
};

pub const Test = struct {
    query: Query,
    path: Bytes(512),
    query_string: Bytes(512) = .{},
    ip: Bytes(48),
    user_agent: Bytes(256) = .{},
    body: Bytes(2048) = .{},
    headers: [8]Header = @splat(.{}),
    header_count: u8 = 0,
    draft: ?Bytes(4096) = null,
    committed: ?u64 = null,
};
pub const Header = struct { name: Bytes(64) = .{}, value: Bytes(256) = .{} };
pub const Edit = struct {
    session_digest: [32]u8,
    csrf_digest: [32]u8,
    require_totp: bool = false,
    expected_revision: u64,
    document: Bytes(4096),
    client: Bytes(48) = .{},
};
pub const Read = struct {
    session_digest: [32]u8,
    require_totp: bool = false,
    committed: ?u64 = null,
    selection: union(enum) {
        catalog: Bytes(128),
        /// With `previous`, the newest recorded revision below `revision` for this rule.
        document: struct { id: Bytes(128), revision: ?u64 = null, previous: bool = false },
        history: struct { id: Bytes(128), before: ?u64 = null },
    },
};
pub const Document = struct { revision: u64, document: Bytes(4096) };

pub fn validateRead(input: Read) error{InvalidLimit}!void {
    if ((input.committed orelse 0) > std.math.maxInt(i64)) return error.InvalidLimit;
    switch (input.selection) {
        .catalog => |after| if (after.len > 128) return error.InvalidLimit,
        .document => |document| {
            if (document.id.len == 0 or document.id.len > 128 or
                (document.revision orelse 0) > std.math.maxInt(i64)) return error.InvalidLimit;
        },
        .history => |history| {
            if (history.id.len == 0 or history.id.len > 128 or
                (history.before orelse 0) > std.math.maxInt(i64)) return error.InvalidLimit;
        },
    }
}

pub fn validate(query: Query) error{InvalidLimit}!void {
    if (query.offset > 128 or
        (query.applied orelse 0) > std.math.maxInt(i64)) return error.InvalidLimit;
}

pub fn validateTest(input: Test) error{InvalidLimit}!void {
    try validate(input.query);
    if (input.path.len == 0 or input.ip.len == 0 or input.header_count > input.headers.len)
        return error.InvalidLimit;
    if ((input.draft != null) != (input.committed != null)) return error.InvalidLimit;
    if ((input.committed orelse 0) > std.math.maxInt(i64)) return error.InvalidLimit;
    if (input.draft) |draft| if (draft.len == 0 or draft.len > draft.data.len)
        return error.InvalidLimit;
}
