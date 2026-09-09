const p = @import("console_protocol");
pub const Phase = enum {
    loading,
    setup,
    login,
    password,
    dashboard,
    geoip,
    security,
    events,
    challenges,
    similarity,
    policies,
    users,
    tokens,
    audit,
    nodes,
    settings,
};

test "session reset wipes retained credentials and request bodies and restores defaults" {
    const t = @import("std").testing;
    var state: State = .{ .phase = .policies, .navigation_open = true, .reconnect_ms = 8000 };
    state.csrf = try p.Bytes(64).init("private csrf");
    state.totp_secret = try p.Bytes(32).init("private seed");
    state.recovery_codes[0] = try p.Bytes(32).init("private recovery");
    state.policies.body = try p.Bytes(2048).init("private request body");
    state.reset();
    try t.expectEqual(Phase.loading, state.phase);
    try t.expect(!state.navigation_open);
    try t.expectEqual(@as(u32, 1000), state.reconnect_ms);
    try t.expectEqual(@as(f64, 15), state.globe.lat);
    try t.expectEqualSlices(u8, &@as([64]u8, @splat(0)), &state.csrf.data);
    try t.expectEqualSlices(u8, &@as([32]u8, @splat(0)), &state.totp_secret.data);
    try t.expectEqualSlices(u8, &@as([32]u8, @splat(0)), &state.recovery_codes[0].data);
    try t.expectEqualSlices(u8, &@as([2048]u8, @splat(0)), &state.policies.body.data);
}
pub const State = struct {
    phase: Phase = .loading,
    navigation_open: bool = false,
    policies: @import("policies_page.zig").Model = .{},
    rankings: @import("rankings_panel.zig").Model = .{},
    similarity: @import("similarity_state.zig").Model = .{},
    challenges: @import("challenges_page.zig").Model = .{},
    events: @import("events_state.zig").Model = .{},
    message: p.Bytes(256) = .{},
    message_success: bool = false,
    username: p.Bytes(64) = .{},
    csrf: p.Bytes(64) = .{},
    role: p.Bytes(16) = .{},
    user_id: u64 = 0,
    users: @import("users_state.zig").Model = .{},
    tokens: @import("tokens_state.zig").Model = .{},
    settings: @import("settings_state.zig").Model = .{},
    audit: @import("audit_state.zig").Model = .{},
    nodes: @import("nodes_state.zig").Model = .{},
    busy: bool = false,
    must_change: bool = false,
    totp_required: bool = false,
    stats_busy: bool = false,
    epoch: p.Bytes(32) = .{},
    sequence: u64 = 0,
    reconnect_ms: u32 = 1000,
    paused: bool = false,
    hidden: bool = false,
    browser_time: u64 = 0,
    received_at: u64 = 0,
    stale: bool = false,
    dark: bool = false,
    geometry: ?[]const u8 = null,
    geometry_busy: bool = false,
    geometry_retry_at: u64 = 0,
    globe: @import("geography.zig").View = .{},
    globe_attacks: bool = false,
    globe_coverage: bool = false,
    motion: @import("globe_motion.zig").Motion = .{},
    geo: p.geo.Metadata = .{},
    geo_status: p.Bytes(16) = .{},
    geo_progress: u32 = 0,
    geo_importing: bool = false,
    totp_available: bool = false,
    totp_enabled: bool = false,
    totp_revision: u64 = 0,
    totp_secret: p.Bytes(32) = .{},
    totp_uri: p.Bytes(134) = .{},
    recovery_codes: [10]p.Bytes(32) = @splat(.{}),
    recovery_count: usize = 0,
    stats: ?p.StatsSnapshot = null,
    /// Wall-display session: read-only, statistics only, auto-cycling globe modes.
    kiosk: bool = false,
    kiosk_expires: u64 = 0,
    kiosk_cycled_at: u64 = 0,
    timeline_open: bool = false,
    history_minutes: bool = false,
    minute_history: @import("minute_panel.zig").Model = .{},
    timeline: @import("timeline_panel.zig").Model = .{},
    points: [60]@import("stats_series.zig").Point = @splat(.{}),

    /// Reset owned fields individually so the Wasm binary does not carry a second
    /// full initialized State image just to clear bounded page buffers on sign-out.
    pub fn reset(self: *State) void {
        inline for (@typeInfo(State).@"struct".fields) |field| {
            if (comptime @import("std").mem.eql(u8, field.name, "rankings")) {
                self.rankings.clear();
            } else if (comptime @import("std").mem.eql(u8, field.name, "timeline")) {
                self.timeline.clear();
            } else if (comptime @import("std").mem.eql(u8, field.name, "minute_history")) {
                self.minute_history.clear();
            } else if (comptime @import("std").mem.eql(u8, field.name, "events")) {
                self.events.clear();
            } else if (comptime @import("std").mem.eql(u8, field.name, "users")) {
                self.users.clear();
            } else if (comptime @import("std").mem.eql(u8, field.name, "tokens")) {
                self.tokens.clear();
            } else if (comptime @import("std").mem.eql(u8, field.name, "settings")) {
                self.settings.clear();
            } else if (comptime @import("std").mem.eql(u8, field.name, "audit")) {
                self.audit.clear();
            } else @field(self, field.name) = field.defaultValue().?;
        }
    }

    pub fn fullAccess(self: *const State) bool {
        return self.csrf.len != 0 and !self.must_change and !self.totp_required;
    }

    pub fn allows(self: *const State, action: p.Action) bool {
        if (!self.fullAccess()) return false;
        const role = @import("std").meta.stringToEnum(p.Role, self.role.slice()) orelse {
            return false;
        };
        return role.allows(action);
    }
};
