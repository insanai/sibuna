//! Shared native/Wasm contracts. No networking, database or daemon dependencies.
const std = @import("std");

pub const version: u16 = 1;
pub const max_message = 4096;
pub const max_page_rows = 100;

pub const Role = enum(u8) {
    viewer,
    operator,
    admin,

    pub fn allows(self: Role, action: Action) bool {
        return switch (action) {
            .read => true,
            .manage_policy, .control_node => self != .viewer,
            .manage_users, .manage_settings => self == .admin,
        };
    }
};
pub const Action = enum { read, manage_policy, control_node, manage_users, manage_settings };
pub const Topic = enum(u8) { stats, events, nodes, challenges, audit };
pub const Cursor = struct { epoch: u64, sequence: u64 };
pub const Subscription = union(enum) {
    subscribe: struct { topic: Topic, after: ?Cursor = null },
    unsubscribe: Topic,
    acknowledge: struct { topic: Topic, cursor: Cursor },
};
pub const Coverage = struct {
    reporting: u16,
    expected: u16,
    lost_samples: u64,
    unknown_country: u64,
    incident_complete: bool,
    age_ms: u64,
};
pub const Revision = struct { committed: u64, applied: u64 };
pub const ControlRequest = struct {
    id: u64,
    actor: u64,
    authorization_revision: u64,
    node: u32,
    command: union(enum) { drain: bool, clear_local_bans },
};
pub const AuthUser = struct {
    id: u64,
    username: Bytes(64),
    password_hash: Bytes(255),
    role: Role,
    revision: u64,
    must_change: bool,
};
pub const Principal = struct {
    actor: u64,
    username: Bytes(64),
    role: Role,
    revision: u64,
    expires: u64,
    csrf_digest: [32]u8,
    must_change: bool,
};
pub const StorageRequest = union(enum) {
    setup_status,
    bootstrap: struct { username: Bytes(64), password_hash: Bytes(255), now: u64 },
    auth_user: Bytes(64),
    session_create: struct {
        user: u64,
        revision: u64,
        digest: [32]u8,
        csrf_digest: [32]u8,
        now: u64,
        expires: u64,
    },
    logout: [32]u8,
    password_change: struct {
        session_digest: [32]u8,
        csrf_digest: [32]u8,
        password_hash: Bytes(255),
        now: u64,
    },
    authorize: struct { session_digest: [32]u8, now: u64 },
    incidents: struct { before_id: ?u64, limit: u16 },
    policy_edit: struct {
        actor: u64,
        authorization_revision: u64,
        expected_revision: u64,
        document: Bytes(max_message),
    },
    control_intent: ControlRequest,
    control_complete: struct { id: u64, succeeded: bool },
};
pub const StorageResult = union(enum) {
    setup_required: bool,
    auth_user: AuthUser,
    authorized: Principal,
    page: Bytes(max_message),
    revision: Revision,
    command_recorded,
    failed: Failure,
};
pub const Failure = enum {
    unauthorized,
    forbidden,
    conflict,
    unavailable,
    capacity,
    invalid_input,
    cancelled,
};

/// Fixed buffers cross asynchronous boundaries by value. Length is checked on construction;
/// callers must not serialize the unused tail or rely on native struct layout as a wire format.
pub fn Bytes(comptime capacity: usize) type {
    return struct {
        data: [capacity]u8 = @splat(0),
        len: usize = 0,

        pub fn init(value: []const u8) error{TooLarge}!@This() {
            if (value.len > capacity) return error.TooLarge;
            var result: @This() = .{ .len = value.len };
            @memcpy(result.data[0..value.len], value);
            return result;
        }

        pub fn slice(self: *const @This()) []const u8 {
            std.debug.assert(self.len <= capacity);
            return self.data[0..self.len];
        }
    };
}

pub fn validate(request: StorageRequest) error{ InvalidLimit, TooLarge }!void {
    switch (request) {
        .incidents => |page| {
            if (page.limit == 0 or page.limit > max_page_rows) return error.InvalidLimit;
        },
        .policy_edit => |edit| {
            if (edit.document.len > max_message) return error.TooLarge;
        },
        else => {},
    }
}

test "owned payload boundaries and pagination reject unbounded input" {
    const t = std.testing;
    var source = [_]u8{ 1, 2, 3 };
    const owned = try Bytes(3).init(&source);
    source[0] = 9;
    try t.expectEqualSlices(u8, &.{ 1, 2, 3 }, owned.slice());
    try t.expectError(error.TooLarge, Bytes(2).init(&source));
    try t.expectError(error.InvalidLimit, validate(.{ .incidents = .{
        .before_id = null,
        .limit = 101,
    } }));
    try t.expect(!Role.viewer.allows(.control_node));
    try t.expect(!Role.operator.allows(.manage_users));
}
