const std = @import("std");
const Bytes = @import("root.zig").Bytes;

pub const Query = struct {
    session_digest: [32]u8,
    now: u64,
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
    now: u64,
    expected_revision: u64,
    document: Bytes(4096),
};

pub fn validate(query: Query) error{InvalidLimit}!void {
    if (query.offset > 128 or query.now > std.math.maxInt(i64) or
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
