const std = @import("std");
const p = @import("console_protocol");
const n = p.notifications;
pub const Kind = enum { query, save, remove, testing, settings, setting_change, about };
const WireRow = struct {
    id: u64,
    revision: u64,
    kind: n.Kind,
    label: []const u8,
    target: []const u8,
    target_host: []const u8,
    secret_set: bool,
    events: u8,
    cooldown_seconds: u32,
    enabled: bool,
    last_attempt_at: ?u64,
    last_outcome: ?n.Outcome,
    last_detail: []const u8,
};
const WireSetting = struct {
    key: []const u8,
    value: []const u8,
    revision: u64,
    updated_at: u64,
    updated_by: u64,
};
pub const Row = struct {
    id: u64 = 0,
    revision: u64 = 0,
    kind: n.Kind = .webhook,
    label: p.Bytes(n.max_label) = .{},
    target: p.Bytes(n.max_target) = .{},
    secret_set: bool = false,
    events: u8 = 0,
    cooldown_seconds: u32 = 0,
    enabled: bool = true,
    last_attempt_at: ?u64 = null,
    last_outcome: ?n.Outcome = null,
    last_detail: p.Bytes(n.max_detail) = .{},
};
pub const Setting = struct {
    key: p.Bytes(n.max_setting_key) = .{},
    value: p.Bytes(n.max_setting_value) = .{},
    revision: u64 = 0,
};

pub const Model = struct {
    rows: [n.page_rows]Row = @splat(.{}),
    count: usize = 0,
    after: u64 = 0,
    next: ?u64 = null,
    settings: [n.known_settings.len]Setting = @splat(.{}),
    setting_count: usize = 0,
    selected: ?usize = null,
    busy: bool = false,
    loaded: bool = false,
    kind: Kind = .query,
    ticket: p.Bytes(40) = .{},
    result: p.Bytes(n.max_detail) = .{},
    result_ok: bool = false,
    about: p.Bytes(512) = .{},

    pub fn clear(self: *Model) void {
        @memset(std.mem.asBytes(self), 0);
        self.next = null;
        self.selected = null;
        self.kind = .query;
        for (&self.rows) |*row| row.* = .{};
        for (&self.settings) |*entry| entry.* = .{};
    }

    pub fn decode(self: *Model, value: std.json.Value, allocator: std.mem.Allocator) !void {
        const wire = try @import("json_value.zig").decode(struct {
            rows: []const WireRow,
            next: ?u64,
        }, value, allocator);
        if (wire.rows.len > self.rows.len) return error.InvalidResponse;
        var rows: [n.page_rows]Row = @splat(.{});
        for (wire.rows, 0..) |row, index| {
            if (row.events == 0 or row.events > n.all_events) return error.InvalidResponse;
            rows[index] = .{
                .id = row.id,
                .revision = row.revision,
                .kind = row.kind,
                .label = try p.Bytes(n.max_label).init(row.label),
                .target = try p.Bytes(n.max_target).init(row.target),
                .secret_set = row.secret_set,
                .events = row.events,
                .cooldown_seconds = row.cooldown_seconds,
                .enabled = row.enabled,
                .last_attempt_at = row.last_attempt_at,
                .last_outcome = row.last_outcome,
                .last_detail = try p.Bytes(n.max_detail).init(row.last_detail),
            };
        }
        self.rows = rows;
        self.count = wire.rows.len;
        self.next = wire.next;
        self.loaded = true;
        if (self.selected) |index| if (index >= self.count) {
            self.selected = null;
        };
    }

    pub fn decodeSettings(
        self: *Model,
        value: std.json.Value,
        allocator: std.mem.Allocator,
    ) !void {
        const wire = try @import("json_value.zig").decode([]const WireSetting, value, allocator);
        if (wire.len > self.settings.len) return error.InvalidResponse;
        var settings: [n.known_settings.len]Setting = @splat(.{});
        for (wire, 0..) |entry, index| settings[index] = .{
            .key = try p.Bytes(n.max_setting_key).init(entry.key),
            .value = try p.Bytes(n.max_setting_value).init(entry.value),
            .revision = entry.revision,
        };
        self.settings = settings;
        self.setting_count = wire.len;
    }

    pub fn setting(self: *const Model, key: []const u8) ?Setting {
        for (self.settings[0..self.setting_count]) |item| {
            if (std.mem.eql(u8, item.key.slice(), key)) return item;
        }
        return null;
    }
};
