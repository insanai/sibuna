//! Shared native/Wasm contracts. No networking, database or daemon dependencies.
const std = @import("std");

pub const similarity = @import("similarity.zig");
pub const policies = @import("policies.zig");
pub const challenges = @import("challenges.zig");
pub const rankings = @import("rankings.zig");
pub const events = @import("events.zig");
pub const auth = @import("auth.zig");
pub const geo = @import("geo.zig");
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
    totp_enabled: bool = false,
    password_expires: u64 = 0,
};
pub const Principal = struct {
    actor: u64,
    username: Bytes(64),
    role: Role,
    revision: u64,
    expires: u64,
    csrf_digest: [32]u8,
    must_change: bool,
    totp_enabled: bool = false,
};
pub const StorageRequest = union(enum) {
    setup_status,
    totp_read: u64,
    totp_begin: auth.Enrollment,
    totp_confirm: auth.Confirmation,
    geo_metadata,
    geo_prune: u64,
    geo_begin: geo.Begin,
    geo_batch: geo.Batch,
    geo_activate: geo.Activate,
    geo_read: geo.Read,
    bootstrap: struct {
        username: Bytes(64),
        password_hash: Bytes(255),
        now: u64,
        must_change: bool = false,
        password_expires: u64 = 0,
    },
    auth_user: Bytes(64),
    session_create: struct {
        factor: auth.Factor = .none,
        user: u64,
        revision: u64,
        digest: [32]u8,
        csrf_digest: [32]u8,
        now: u64,
        expires: u64,
    },
    logout: struct { digest: [32]u8, now: u64 },
    password_change: struct {
        expected_revision: u64,
        replacement_digest: [32]u8,
        replacement_csrf: [32]u8,
        session_digest: [32]u8,
        csrf_digest: [32]u8,
        password_hash: Bytes(255),
        now: u64,
    },
    authorize: struct { session_digest: [32]u8, now: u64, touch: bool = false },
    incidents: struct { before_id: ?u64, limit: u16 },
    events_query: events.Query,
    events_similar: similarity.Query,
    policies_query: policies.Query,
    policies_test: policies.Test,
    policy_edit: policies.Edit,
    policy_read: policies.Read,
    control_intent: ControlRequest,
    control_complete: struct { id: u64, succeeded: bool },
};
pub const StorageResult = union(enum) {
    policy_document: policies.Document,
    similarity: similarity.Part,
    setup_required: bool,
    geo_metadata: geo.Metadata,
    geo_bytes: Bytes(3400),
    auth_user: AuthUser,
    totp: auth.Totp,
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
            var result: @This() = undefined;
            @memset(&result.data, 0);
            result.len = value.len;
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
        .policy_read => |input| try policies.validateRead(input),
        .policies_query => |query| try policies.validate(query),
        .policies_test => |input| try policies.validateTest(input),
        .events_query => |query| try events.validate(query),
        .events_similar => |query| try similarity.validate(query),
        inline .geo_begin, .geo_activate, .totp_begin => |input| {
            if (input.expected_revision >= std.math.maxInt(i64)) return error.InvalidLimit;
        },
        .totp_confirm => |input| {
            if (input.expected_revision >= std.math.maxInt(i64) or
                input.step > std.math.maxInt(i64)) return error.InvalidLimit;
        },
        .incidents => |page| {
            if (page.limit == 0 or page.limit > max_page_rows) return error.InvalidLimit;
        },
        .policy_edit => |edit| {
            if (edit.document.len == 0 or edit.document.len > max_message) return error.TooLarge;
            if (edit.expected_revision >= std.math.maxInt(i64) or
                edit.now > std.math.maxInt(i64)) return error.InvalidLimit;
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

pub const CountryCount = struct { code: u16 = 0, samples: u64 = 0 };
pub const StatsSnapshot = struct {
    requests: u64,
    admitted: u64,
    challenged: u64,
    denied: u64,
    origin_4xx: u64,
    origin_5xx: u64,
    incidents: u64,
    incidents_dropped: u64,
    sample_loss: u64,
    sample_probability: []const u8 = "1/64",
    geoip_available: bool = false,
    countries: [32]CountryCount = @splat(.{}),
    other_country_samples: u64 = 0,
    unknown_samples: u64,
    timestamp: u64,
};

pub fn validUsername(username: []const u8) bool {
    if (username.len == 0 or username.len > 64) return false;
    for (username) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-' and byte != '.')
            return false;
    }
    return true;
}
