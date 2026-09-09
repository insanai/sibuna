//! Notification destinations, queued events and operator settings. Results stay within the
//! fixed storage envelope: destination pages carry four rows; claims own one delivery.
//! Secret values never cross this boundary in the clear except inside a sealed envelope.
const std = @import("std");
const p = @import("root.zig");
pub const Event = enum(u2) {
    denial_spike,
    ban,
    node_unhealthy,
    leader_change,

    pub fn bit(self: Event) u8 {
        return @as(u8, 1) << @intFromEnum(self);
    }
};
pub const all_events: u8 = 15;
pub const Kind = enum { webhook, syslog };
pub const Outcome = enum { delivered, failed };
pub const capacity = 8;
pub const page_rows = 4;
pub const queue_capacity = 256;
pub const max_attempts = 3;
pub const history_capacity = 4096;
pub const history_days = 7;
pub const claim_margin_seconds = 12;
pub const max_label = 64;
pub const max_target = 256;
pub const max_host = 128;
pub const max_detail = 96;
pub const max_secret = 64;
pub const max_envelope = 256;
pub const max_setting_key = 64;
pub const max_setting_value = 1024;
pub const known_settings = [_][]const u8{ "notify.spike_factor", "notify.spike_minimum" };

pub const Destination = struct {
    id: u64,
    revision: u64,
    kind: Kind,
    label: p.Bytes(max_label),
    target: p.Bytes(max_target),
    target_host: p.Bytes(max_host),
    secret_set: bool,
    events: u8,
    cooldown_seconds: u32,
    enabled: bool,
    last_attempt_at: ?u64,
    last_outcome: ?Outcome,
    last_detail: p.Bytes(max_detail),

    pub fn jsonStringify(self: Destination, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, w);
    }
};
pub const Page = struct {
    rows: [page_rows]Destination = undefined,
    count: u8 = 0,
    next: ?u64 = null,

    pub fn jsonStringify(self: Page, w: *std.json.Stringify) std.json.Stringify.Error!void {
        try w.beginObject();
        try w.objectField("rows");
        try w.beginArray();
        for (self.rows[0..self.count]) |row| try w.write(row);
        try w.endArray();
        try w.objectField("next");
        if (self.next) |next| try p.writeCounter(w, next) else try w.write(null);
        try w.endObject();
    }
};
/// Destination pages and sealed secrets are read by an administrator session or, for
/// deliveries, by the notifier under its fenced lease; `lease` takes precedence.
pub const Query = struct { auth: p.users.Auth, after: u64 = 0, lease: ?p.retention.Lease = null };
pub const Save = struct {
    auth: p.users.Auth,
    id: ?u64,
    expected_revision: u64,
    kind: Kind,
    label: p.Bytes(max_label),
    target: p.Bytes(max_target),
    target_host: p.Bytes(max_host),
    secret_envelope: ?p.Bytes(max_envelope),
    clear_secret: bool = false,
    events: u8,
    cooldown_seconds: u32,
    enabled: bool,
};
pub const Remove = struct { auth: p.users.Auth, id: u64, expected_revision: u64 };
pub const Read = struct {
    auth: p.users.Auth,
    id: u64,
    revision: u64,
    lease: ?p.retention.Lease = null,
};
pub const Secret = struct {
    kind: Kind,
    target: p.Bytes(max_target),
    envelope: ?p.Bytes(max_envelope),
};
pub const Enqueue = struct {
    node: u32,
    boot: [16]u8,
    sequence: u64,
    event: Event,
    raised_at: u64,
    detail: p.Bytes(max_detail),
};
pub const Pending = struct {
    id: u64,
    node: u32,
    event: Event,
    raised_at: u64,
    detail: p.Bytes(max_detail),
    attempts: u32,
};
/// A claim owns all inputs. Retargeting invalidates the revision before another attempt.
pub const Claimed = struct {
    delivery_id: u64,
    event: Pending,
    destination: Destination,
};
pub const Claim = struct { lease: p.retention.Lease };
pub const Record = struct {
    lease: p.retention.Lease,
    delivery_id: u64,
    attempt: u32,
    delivered: bool,
    detail: p.Bytes(max_detail),
};
pub const Setting = struct {
    key: p.Bytes(max_setting_key),
    value: p.Bytes(max_setting_value),
    revision: u64,
    updated_at: u64,
    updated_by: u64,

    pub fn jsonStringify(self: Setting, w: *std.json.Stringify) std.json.Stringify.Error!void {
        return fields(self, w);
    }
};
pub const SettingsPage = struct {
    rows: [known_settings.len]Setting = undefined,
    count: u8 = 0,

    pub fn jsonStringify(
        self: SettingsPage,
        w: *std.json.Stringify,
    ) std.json.Stringify.Error!void {
        try w.beginArray();
        for (self.rows[0..self.count]) |row| try w.write(row);
        try w.endArray();
    }
};
pub const SettingChange = struct {
    auth: p.users.Auth,
    key: p.Bytes(max_setting_key),
    value: p.Bytes(max_setting_value),
    expected_revision: u64,
};

pub fn knownSetting(key: []const u8) bool {
    for (known_settings) |name| if (std.mem.eql(u8, name, key)) return true;
    return false;
}

pub fn validateSave(input: Save) error{InvalidLimit}!void {
    if (input.events == 0 or input.events > all_events or input.cooldown_seconds > 86400 or
        input.label.len == 0 or input.target.len == 0 or
        input.expected_revision >= std.math.maxInt(i64)) return error.InvalidLimit;
    if (input.secret_envelope != null and input.clear_secret) return error.InvalidLimit;
}

fn fields(value: anytype, w: *std.json.Stringify) std.json.Stringify.Error!void {
    try w.beginObject();
    inline for (@typeInfo(@TypeOf(value)).@"struct".fields) |field| {
        try w.objectField(field.name);
        const item = @field(value, field.name);
        if (field.type == p.Bytes(max_label) or field.type == p.Bytes(max_target) or
            field.type == p.Bytes(max_host) or field.type == p.Bytes(max_detail) or
            field.type == p.Bytes(max_setting_key) or field.type == p.Bytes(max_setting_value))
        {
            try w.write(item.slice());
        } else if (field.type == u64) {
            try p.writeCounter(w, item);
        } else if (field.type == ?u64) {
            if (item) |number| try p.writeCounter(w, number) else try w.write(null);
        } else try w.write(item);
    }
    try w.endObject();
}

test "destination saves are bounded and secrets are either supplied or cleared" {
    const t = std.testing;
    var save: Save = .{
        .auth = .{ .session_digest = @splat(1) },
        .id = null,
        .expected_revision = 0,
        .kind = .webhook,
        .label = try p.Bytes(max_label).init("ops"),
        .target = try p.Bytes(max_target).init("https://hooks.example/x"),
        .target_host = try p.Bytes(max_host).init("hooks.example"),
        .secret_envelope = null,
        .events = Event.ban.bit() | Event.denial_spike.bit(),
        .cooldown_seconds = 60,
        .enabled = true,
    };
    try validateSave(save);
    save.events = 16;
    try t.expectError(error.InvalidLimit, validateSave(save));
    save.events = 1;
    save.clear_secret = true;
    save.secret_envelope = .{};
    try t.expectError(error.InvalidLimit, validateSave(save));
    try t.expect(knownSetting("notify.spike_factor") and !knownSetting("notify.other"));
}
