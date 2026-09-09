//! Shared native/Wasm contracts. No networking, database or daemon dependencies.
const std = @import("std");

pub const similarity = @import("similarity.zig");
pub const policies = @import("policies.zig");
pub const challenges = @import("challenges.zig");
pub const rankings = @import("rankings.zig");
pub const timeline = @import("timeline.zig");
pub const minutes = @import("minutes.zig");
pub const ranking_storage = @import("ranking_storage.zig");
pub const events = @import("events.zig");
pub const auth = @import("auth.zig");
pub const users = @import("users.zig");
pub const audit = @import("audit.zig");
pub const tokens = @import("tokens.zig");
pub const geo = @import("geo.zig");
pub const Location = @import("location.zig").Location;
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
            .manage_policy, .control_node, .open_kiosk => self != .viewer,
            .manage_users, .manage_settings => self == .admin,
        };
    }
};
pub const Action = enum {
    read,
    manage_policy,
    control_node,
    manage_users,
    manage_settings,
    open_kiosk,
};
pub const Topic = enum(u8) { stats, events, nodes, challenges, audit };
pub const ProxyMode = enum { reverse_proxy, forward_auth };
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
pub const nodes = @import("nodes.zig");
pub const ControlRequest = nodes.Command;
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
pub const CredentialKind = enum { session, bearer };
pub const Principal = struct {
    account_role: ?Role = null,
    token_id: ?u64 = null,
    scopes: u32 = tokens.known_scopes,
    actor: u64,
    username: Bytes(64),
    role: Role,
    revision: u64,
    expires: u64,
    csrf_digest: [32]u8,
    must_change: bool,
    totp_enabled: bool = false,
    /// A read-only wall-display session: viewer role, statistics scope, no mutations.
    kiosk: bool = false,
};
pub const retention = @import("retention.zig");
pub const kiosk = @import("kiosk.zig");
pub const notifications = @import("notifications.zig");
pub const pages = @import("pages.zig");
pub const workflows = @import("workflows.zig");
pub const AuthorizationCheck = struct {
    session_digest: [32]u8,
    touch: bool = false,
    kind: CredentialKind = .session,
};
pub const StorageRequest = union(enum) {
    audit_query: audit.Query,
    audit_read: audit.Read,
    tokens_query: tokens.Query,
    tokens_create: tokens.Create,
    tokens_revoke: tokens.Revoke,
    users_query: users.Query,
    users_create: users.Create,
    users_change: users.Change,
    retention_acquire: retention.Holder,
    retention_prune: retention.Prune,
    minutes_write: minutes.Write,
    minutes_query: minutes.Query,
    minutes_prune: u64,
    rankings_begin: ranking_storage.Begin,
    rankings_chunk: ranking_storage.Chunk,
    rankings_finish: ranking_storage.Finish,
    rankings_prune: u64,
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
    bootstrap: auth.Bootstrap,
    auth_user: Bytes(64),
    session_create: auth.Session,
    logout: auth.Logout,
    password_change: auth.PasswordChange,
    authorize: AuthorizationCheck,
    incidents: struct { before_id: ?u64, limit: u16 },
    events_query: events.Query,
    events_similar: similarity.Query,
    policies_query: policies.Query,
    policies_test: policies.Test,
    policy_edit: policies.Edit,
    inspection_edit: policies.Edit,
    policy_read: policies.Read,
    node_status: users.Auth,
    node_command: nodes.Command,
    node_command_read: nodes.Read,
    nodes_query: users.Auth,
    node_advertise: Bytes(nodes.max_url),
    kiosk_grant: kiosk.Grant,
    kiosk_exchange: kiosk.Exchange,
    settings_query: users.Auth,
    settings_change: notifications.SettingChange,
    notifications_query: notifications.Query,
    notifications_save: notifications.Save,
    notifications_remove: notifications.Remove,
    notifications_read: notifications.Read,
    notifier_acquire: retention.Holder,
    notifications_enqueue: notifications.Enqueue,
    notifications_claim: notifications.Claim,
    notifications_record: notifications.Record,
    notifications_test_audit: notifications.TestAudit,
    page_read: pages.Read,
    page_edit: pages.Edit,
    policy_order: workflows.Order,
    policy_replay: workflows.Replay,
    reputation_query: workflows.ReputationQuery,
    reputation_edit: workflows.ReputationEdit,
    reputation_remove: workflows.ReputationRemove,
    country_chunk: workflows.CountryChunk,
    country_preflight: workflows.CountryPreflight,
    country_apply: workflows.CountryApply,
    import_chunk: workflows.ImportChunk,
    import_commit: workflows.ImportCommit,
};
pub const StorageResult = union(enum) {
    node_status: nodes.Status,
    node_receipt: nodes.Receipt,
    nodes_page: nodes.Page,
    kiosk_granted: kiosk.Granted,
    kiosk_session: kiosk.Session,
    settings_page: notifications.SettingsPage,
    notifications_page: notifications.Page,
    notification_saved: u64,
    notification_secret: notifications.Secret,
    notifier_lease: retention.Lease,
    notification_claimed: ?notifications.Claimed,
    page_document: pages.Document,
    replay_summary: workflows.ReplaySummary,
    reputation_page: workflows.ReputationPage,
    country_summary: workflows.CountrySummary,
    audit_page: audit.Page,
    audit_detail: audit.Detail,
    tokens_page: tokens.Page,
    token_saved: u64,
    // Storage acknowledgement carries the exact durable activation timestamp.
    geo_activated: u64,
    users_saved: u64,
    users_page: users.Page,
    retention_lease: retention.Lease,
    minute_page: minutes.Page,
    ranking_inventory: rankings.Inventory,
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
        pub const byte_capacity = capacity;
        data: [capacity]u8 = @splat(0),
        len: usize = 0,

        pub fn init(value: []const u8) error{TooLarge}!@This() {
            var result: @This() = undefined;
            try result.set(value);
            return result;
        }

        /// Caller-owned outputs avoid large error-union copies. Oversize input leaves
        /// the previous value intact; overlapping slices are moved before tail erasure.
        pub fn set(self: *@This(), value: []const u8) error{TooLarge}!void {
            if (value.len > capacity) return error.TooLarge;
            const output = self.data[0..value.len];
            if (@intFromPtr(output.ptr) <= @intFromPtr(value.ptr)) {
                std.mem.copyForwards(u8, output, value);
            } else std.mem.copyBackwards(u8, output, value);
            @memset(self.data[value.len..], 0);
            self.len = value.len;
        }

        pub fn slice(self: *const @This()) []const u8 {
            std.debug.assert(self.len <= capacity);
            return self.data[0..self.len];
        }
    };
}

/// Frees the heap payload a request carries, if any. The mailbox owns a submitted request's
/// payload until the owner has executed it; a rejected submission stays with the caller.
pub fn releaseRequest(request: StorageRequest, gpa: std.mem.Allocator) void {
    switch (request) {
        .page_edit => |input| if (input.html) |html| gpa.destroy(html),
        else => {},
    }
}

/// Frees the heap payload a result carries, if any; the receiver of a polled result owns it.
pub fn releaseResult(result: StorageResult, gpa: std.mem.Allocator) void {
    switch (result) {
        .page_document => |document| gpa.destroy(document.html),
        else => {},
    }
}

pub fn validate(request: StorageRequest) error{ InvalidLimit, TooLarge }!void {
    switch (request) {
        .node_command => |input| try nodes.validate(input),
        .audit_query => |input| try audit.validate(input),
        .audit_read => |input| {
            if (input.id == 0 or input.id > audit.last_id) return error.InvalidLimit;
        },
        .tokens_query => |input| try users.validateQuery(.{
            .auth = input.auth,
            .after = input.after,
            .limit = input.limit,
        }),
        .tokens_create => |input| try tokens.validateCreate(input),
        .tokens_revoke => |input| try tokens.validateRevoke(input),
        .users_query => |input| try users.validateQuery(input),
        .users_create => |input| try users.validateCreate(input),
        .users_change => |input| try users.validateChange(input),
        .retention_acquire => |holder| holder.validate() catch return error.InvalidLimit,
        .retention_prune => |input| input.lease.validate() catch return error.InvalidLimit,
        .minutes_query => |query| try minutes.validate(query),
        .policy_read => |input| try policies.validateRead(input),
        .policies_query => |query| try policies.validate(query),
        .policies_test => |input| try policies.validateTest(input),
        .notifications_save => |input| try notifications.validateSave(input),
        .page_edit => |input| try pages.validateEdit(input),
        .policy_order => |input| try workflows.validateOrder(input),
        .policy_replay => |input| try workflows.validateReplay(input),
        .reputation_edit => |input| try workflows.validateReputationEdit(input),
        .reputation_remove => |input| if (input.prefix.len == 0 or
            input.expected_revision >= std.math.maxInt(i64)) return error.InvalidLimit,
        .country_chunk => |input| if (input.count == 0 or
            input.count > workflows.chunk_prefixes) return error.InvalidLimit,
        .country_preflight => |input| try workflows.validateCountry(
            input.count,
            input.expected_revision,
        ),
        .country_apply => |input| try workflows.validateCountry(
            input.count,
            input.expected_revision,
        ),
        .import_chunk => |input| if (input.document.len == 0 or
            input.ordinal >= 128) return error.InvalidLimit,
        .import_commit => |input| try workflows.validateImportCommit(input),
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
        .policy_edit, .inspection_edit => |edit| {
            if (edit.document.len == 0 or edit.document.len > max_message) return error.TooLarge;
            if (edit.expected_revision >= std.math.maxInt(i64)) return error.InvalidLimit;
        },
        else => {},
    }
}

test {
    _ = tokens;
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

pub const CountryCount = struct {
    code: u16 = 0,
    samples: u64 = 0,

    pub fn jsonStringify(
        self: CountryCount,
        writer: *std.json.Stringify,
    ) std.json.Stringify.Error!void {
        try writer.beginObject();
        try writer.objectField("code");
        try writer.write(self.code);
        try writer.objectField("samples");
        try writeCounter(writer, self.samples);
        try writer.endObject();
    }
};
pub const StatsSnapshot = struct {
    /// Absent on older snapshots. Authorization subrequests cannot observe origin replies.
    proxy_mode: ?ProxyMode = null,
    /// This console node's declared position, never a client IP or a cluster aggregate.
    server_location: ?Location = null,
    incident_geo: ?@import("incident_geo.zig").Snapshot = null,
    minute_history: minutes.Status = .{},
    /// Version zero denotes the older combined-denial counters and unknown boot identity.
    outcomes_version: u8 = 0,
    node: u32 = 0,
    boot: [16]u8 = @splat(0),
    uptime_ms: u64 = 0,
    requests: u64,
    admitted: u64,
    challenged: u64,
    denied: u64,
    banned: u64 = 0,
    rate_limited: u64 = 0,
    other: u64 = 0,
    origin_4xx: u64,
    origin_5xx: u64,
    incidents: u64,
    incidents_dropped: u64,
    sample_loss: u64,
    expired_samples: u64 = 0,
    future_samples: u64 = 0,
    geo_maintenance_failures: u64 = 0,
    retention_failures: ?u64 = null,
    sample_probability: []const u8 = "1/64",
    geoip_available: bool = false,
    /// Whether the active country provider's licence requires visible attribution.
    geoip_attribution: bool = false,
    countries: [32]CountryCount = @splat(.{}),
    other_country_samples: u64 = 0,
    unknown_samples: u64,
    timestamp: u64,

    pub fn jsonStringify(
        self: StatsSnapshot,
        writer: *std.json.Stringify,
    ) std.json.Stringify.Error!void {
        try writer.beginObject();
        inline for (@typeInfo(StatsSnapshot).@"struct".fields) |field| {
            try writer.objectField(field.name);
            if (comptime std.mem.eql(u8, field.name, "boot")) {
                // Random bytes can be valid UTF-8. Always emit an array, never an accidental
                // string selected by the standard serializer's byte-slice convenience rule.
                try writer.beginArray();
                for (self.boot) |byte| try writer.write(byte);
                try writer.endArray();
            } else if (field.type == u64) {
                try writeCounter(writer, @field(self, field.name));
            } else if (field.type == ?u64) {
                if (@field(self, field.name)) |value| {
                    try writeCounter(writer, value);
                } else try writer.write(null);
            } else try writer.write(@field(self, field.name));
        }
        try writer.endObject();
    }
};

pub const incident_geo = @import("incident_geo.zig");

pub fn writeCounter(writer: *std.json.Stringify, value: u64) std.json.Stringify.Error!void {
    if (value < (1 << 53)) return writer.write(value);
    // Fixed browser glue passes through JSON.parse; decimal strings preserve large counts.
    var buffer: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, "{d}", .{value}) catch unreachable;
    try writer.write(text);
}

pub const Counter = struct {
    value: u64,
    pub fn jsonStringify(
        self: Counter,
        writer: *std.json.Stringify,
    ) std.json.Stringify.Error!void {
        return writeCounter(writer, self.value);
    }
};

test "session account identifiers retain their complete range across browser JSON" {
    var buffer: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try std.json.Stringify.value(.{
        .small = Counter{ .value = 1 },
        .large = Counter{ .value = 9007199254740993 },
    }, .{}, &writer);
    try std.testing.expectEqualStrings(
        "{\"small\":1,\"large\":\"9007199254740993\"}",
        writer.buffered(),
    );
}

pub fn validUsername(username: []const u8) bool {
    if (username.len == 0 or username.len > 64) return false;
    for (username) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-' and byte != '.')
            return false;
    }
    return true;
}

test "owned byte updates preserve oversize state, support overlap and erase truncated tails" {
    const t = std.testing;
    var buffer = try Bytes(16).init("private value");
    try buffer.set(buffer.slice()[8..]);
    try t.expectEqualStrings("value", buffer.slice());
    try t.expect(std.mem.allEqual(u8, buffer.data[buffer.len..], 0));
    try t.expectError(error.TooLarge, buffer.set("x" ** 17));
    try t.expectEqualStrings("value", buffer.slice());
    try buffer.set("");
    try t.expectEqual(@as(usize, 0), buffer.len);
    try t.expect(std.mem.allEqual(u8, &buffer.data, 0));
}
