//! Administrator settings: notification destinations and the two spike thresholds. Every
//! mutation carries an expected revision; delivery tests report their outcome inline.
const std = @import("std");
const p = @import("console_protocol");
const n = p.notifications;
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const Kind = @import("settings_state.zig").Kind;
const string = @import("events_state.zig").string;
const equal = std.mem.eql;
var generation: u64 = 0;

pub fn action(state: *State, name: []const u8, fields: std.json.Value, out: Outbox) !bool {
    if (equal(u8, name, "settings") and state.allows(.manage_settings)) {
        state.settings.clear();
        state.phase = .settings;
        state.message = .{};
        state.stats_busy = false;
        state.stale = true;
        try query(state, out, .query);
        state.pages.clear();
        try @import("pages_controller.zig").read(state, out);
        return true;
    }
    if (!std.mem.startsWith(u8, name, "settings-")) return false;
    if (!state.allows(.manage_settings) or state.phase != .settings) return true;
    const model = &state.settings;
    if (model.busy) return true;
    if (equal(u8, name, "settings-refresh")) {
        model.after = 0;
        try query(state, out, .query);
    } else if (equal(u8, name, "settings-next") and model.next != null) {
        model.after = model.next.?;
        try query(state, out, .query);
    } else if (equal(u8, name, "settings-new")) {
        model.selected = null;
        model.result = .{};
        try out.emit(.{ .op = "focus", .selector = "#destination-label" });
    } else if (std.mem.startsWith(u8, name, "settings-open-")) {
        const index = std.fmt.parseInt(usize, name[14..], 10) catch return true;
        if (index >= model.count) return true;
        model.selected = index;
        model.result = .{};
        try out.emit(.{ .op = "focus", .selector = "#destination-label" });
    } else if (equal(u8, name, "settings-save")) {
        try save(state, fields, out);
    } else if (equal(u8, name, "settings-remove") and model.selected != null) {
        const row = model.rows[model.selected.?];
        try ticket(state, .remove);
        errdefer model.busy = false;
        var revision: [20]u8 = undefined;
        try out.post(model.ticket.slice(), "/console/api/notifications/remove", .{
            .id = row.id,
            .expected_revision = try std.fmt.bufPrint(&revision, "{d}", .{row.revision}),
        });
    } else if (equal(u8, name, "settings-test") and model.selected != null) {
        try ticket(state, .testing);
        errdefer model.busy = false;
        try out.post(model.ticket.slice(), "/console/api/notifications/test", .{
            .id = model.rows[model.selected.?].id,
        });
    } else if (equal(u8, name, "settings-thresholds")) {
        try thresholds(state, fields, out);
    }
    return true;
}

fn ticket(state: *State, kind: Kind) !void {
    if (generation == std.math.maxInt(u64)) return error.Capacity;
    generation += 1;
    const model = &state.settings;
    const text = try std.fmt.bufPrint(&model.ticket.data, "settings-{d}", .{generation});
    model.ticket.len = text.len;
    model.busy = true;
    model.kind = kind;
    state.message = .{};
}

fn query(state: *State, out: Outbox, kind: Kind) !void {
    try ticket(state, kind);
    errdefer state.settings.busy = false;
    if (kind == .about) {
        try out.emit(.{
            .op = "request",
            .id = state.settings.ticket.slice(),
            .method = "GET",
            .path = "/console/api/about",
        });
    } else if (kind == .settings) {
        try out.post(state.settings.ticket.slice(), "/console/api/settings/query", .{});
    } else {
        try out.post(state.settings.ticket.slice(), "/console/api/notifications/query", .{
            .after = state.settings.after,
        });
    }
}

fn events(fields: std.json.Value) u8 {
    var mask: u8 = 0;
    inline for (@typeInfo(n.Event).@"enum".fields) |field| {
        if (equal(u8, string(fields, field.name), "on"))
            mask |= @as(n.Event, @enumFromInt(field.value)).bit();
    }
    return mask;
}

fn save(state: *State, fields: std.json.Value, out: Outbox) !void {
    const model = &state.settings;
    const cooldown = std.fmt.parseInt(u32, string(fields, "cooldown_seconds"), 10) catch {
        try state.message.set("Cooldown must be a whole number of seconds (0 to 86400).");
        return;
    };
    const mask = events(fields);
    if (mask == 0) {
        try state.message.set("Select at least one event for this destination.");
        return;
    }
    try ticket(state, .save);
    errdefer model.busy = false;
    var revision: [20]u8 = undefined;
    const selected = if (model.selected) |index| model.rows[index] else null;
    try out.post(model.ticket.slice(), "/console/api/notifications/save", .{
        .id = if (selected) |row| row.id else null,
        .expected_revision = if (selected) |row|
            try std.fmt.bufPrint(&revision, "{d}", .{row.revision})
        else
            "0",
        .kind = string(fields, "kind"),
        .transport = if (equal(u8, string(fields, "kind"), "syslog"))
            string(fields, "transport")
        else
            "udp",
        .label = string(fields, "label"),
        .target = string(fields, "target"),
        .secret = string(fields, "secret"),
        .clear_secret = equal(u8, string(fields, "clear_secret"), "on"),
        .events = mask,
        .cooldown_seconds = cooldown,
        .enabled = equal(u8, string(fields, "enabled"), "on"),
    });
}

fn thresholds(state: *State, fields: std.json.Value, out: Outbox) !void {
    const model = &state.settings;
    const key = string(fields, "key");
    if (!n.knownSetting(key)) return;
    const current = model.setting(key);
    try ticket(state, .setting_change);
    errdefer model.busy = false;
    var revision: [20]u8 = undefined;
    try out.post(model.ticket.slice(), "/console/api/settings/change", .{
        .key = key,
        .value = string(fields, "value"),
        .expected_revision = try std.fmt.bufPrint(&revision, "{d}", .{
            if (current) |item| item.revision else 0,
        }),
    });
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    alloc: std.mem.Allocator,
    out: Outbox,
) !void {
    const model = &state.settings;
    if (state.phase != .settings or !equal(u8, id, model.ticket.slice())) return;
    const kind = model.kind;
    model.busy = false;
    if (status == 401) {
        state.reset();
        state.phase = .login;
        try state.message.set("Your session ended. Sign in to continue.");
        return out.emit(.{ .op = "disconnect" });
    }
    if (status != 200) {
        try state.message.set(switch (status) {
            400 => "Destination rejected: use an HTTPS public webhook (HTTP only for " ++
                "loopback) or host:port for syslog, with a secret of at most 64 bytes.",
            409 => "Someone changed this entry first. Refresh and review before retrying.",
            403 => "Only an administrator can change settings.",
            else => "Settings request failed. Refresh and try again.",
        });
        return out.emit(.{ .op = "focus", .selector = "#console-message" });
    }
    switch (kind) {
        .query => {
            try model.decode(body, alloc);
            try query(state, out, .settings);
        },
        .settings => {
            try model.decodeSettings(body, alloc);
            if (model.about.len == 0) try query(state, out, .about);
        },
        .about => {
            var writer: std.Io.Writer = .fixed(&model.about.data);
            try std.json.Stringify.value(body, .{}, &writer);
            model.about.len = writer.buffered().len;
        },
        .testing => {
            const delivered = @import("events_state.zig").field(body, "delivered");
            model.result_ok = delivered != null and delivered.? == .bool and delivered.?.bool;
            const audited = @import("events_state.zig").field(body, "audit_recorded");
            if (audited != null and audited.? == .bool and audited.?.bool) {
                try model.result.set(string(body, "detail"));
            } else {
                try model.result.set(if (model.result_ok)
                    "Delivered; the audit completion is unconfirmed. Check Audit before retrying."
                else
                    "Delivery failed; the audit completion is unconfirmed.");
                model.result_ok = false;
            }
            try query(state, out, .query);
        },
        .save, .remove, .setting_change => {
            // A threshold save keeps the open destination; saves and removals close it.
            if (kind != .setting_change) model.selected = null;
            state.message_success = true;
            try state.message.set("Saved.");
            try query(state, out, .query);
        },
    }
}
