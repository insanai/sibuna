//! Browser state machine. JavaScript transports commands and DOM events only.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const render = @import("render.zig");
var state: State = .{};
var input: [16 * 1024]u8 = undefined;
var html: [512 * 1024]u8 = undefined;
var geometry: [@import("geography.zig").max_bytes]u8 = undefined;
var html_length: usize = 0;
var commands: [16 * 1024]u8 = undefined;
var command_writer: std.Io.Writer = undefined;
var command_count: usize = 0;
var commands_length: usize = 0;

export fn sb_input() [*]u8 {
    return &input;
}
export fn sb_input_capacity() usize {
    return input.len;
}
export fn sb_html() [*]const u8 {
    return &html;
}
export fn sb_html_length() usize {
    return html_length;
}
export fn sb_commands() [*]const u8 {
    return &commands;
}
export fn sb_commands_length() usize {
    return commands_length;
}

export fn sb_geometry_input() [*]u8 {
    return &geometry;
}
export fn sb_geometry_capacity() usize {
    return geometry.len;
}
export fn sb_geometry_loaded(length: usize) void {
    begin();
    state.geometry_busy = false;
    if (state.phase != .dashboard or state.must_change or length > geometry.len) {
        finish();
        return;
    }
    if (@import("geography.zig").validate(geometry[0..length])) |_| {
        state.geometry = geometry[0..length];
    } else |_| {
        setMessage("World boundaries are unavailable. Country totals remain available below.");
    }
    finish();
}

export fn sb_init() void {
    state = .{};
    begin();
    get("session", "/console/api/session") catch unreachable;
    finish();
}

export fn sb_event(kind: u32, length: usize) void {
    if (length > input.len) return;
    begin();
    var memory: [64 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &memory);
    defer std.crypto.secureZero(u8, input[0..length]);
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    if (kind == 2 and (boundedEnvelope(input[0..length], fixed.allocator()) catch false)) {
        finish();
        return;
    }
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        fixed.allocator(),
        input[0..length],
        .{},
    ) catch {
        setMessage("Could not read the response. Please reconnect.");
        finish();
        return;
    };
    defer parsed.deinit();
    const previous_phase = state.phase;
    dispatch(kind, parsed.value, fixed.allocator()) catch {
        setMessage("Could not complete the action. Please try again.");
        state.busy = false;
    };
    if (state.phase != previous_phase)
        command(.{ .op = "focus", .selector = "main h1", .top = true }) catch unreachable;
    finish();
}

fn begin() void {
    std.crypto.secureZero(u8, &commands);
    command_writer = .fixed(&commands);
    command_count = 0;
    command_writer.writeByte('[') catch unreachable;
}

fn finish() void {
    if ((state.phase == .dashboard or state.phase == .challenges) and !state.hidden)
        command(.{ .op = "timer", .id = "age", .delay_ms = 1000 }) catch unreachable;
    command_writer.writeByte(']') catch unreachable;
    commands_length = command_writer.buffered().len;
    // Enrollment markup contains a seed or recovery values; erase its old buffer tail.
    std.crypto.secureZero(u8, html[0..html_length]);
    var writer: std.Io.Writer = .fixed(&html);
    render.render(&state, &writer) catch {
        html_length = 0;
        return;
    };
    html_length = writer.buffered().len;
}

fn command(value: anytype) !void {
    if (command_count > 0) try command_writer.writeByte(',');
    try std.json.Stringify.value(value, .{}, &command_writer);
    command_count += 1;
}

fn get(id: []const u8, path: []const u8) !void {
    try command(.{ .op = "request", .id = id, .method = "GET", .path = path });
}

fn post(id: []const u8, path: []const u8, body: anytype) !void {
    try command(.{
        .op = "request",
        .id = id,
        .method = "POST",
        .path = path,
        .body = body,
        .csrf = state.csrf.slice(),
    });
}

fn dispatch(kind: u32, value: std.json.Value, alloc: std.mem.Allocator) !void {
    state.browser_time = number(value, "browser_time");
    switch (kind) {
        1 => try action(value),
        2 => try response(value, alloc),
        3 => {
            if (equal(string(value, "id"), "age") or state.hidden) return;
            if (state.phase == .dashboard and !state.paused) try refresh();
            if (state.phase == .geoip) try get("geoip", "/console/api/geoip");
        },
        4 => try streamEvent(value, alloc),
        5 => {
            const hidden = field(value, "hidden") orelse return;
            if (hidden != .bool) return;
            state.hidden = hidden.bool;
            state.stats_busy = false;
            if (state.hidden) {
                try command(.{ .op = "disconnect" });
            } else if (state.phase == .dashboard and !state.paused) {
                try refresh();
            } else if (state.phase == .geoip) {
                try get("geoip", "/console/api/geoip");
            }
        },
        else => {},
    }
}

fn action(value: std.json.Value) !void {
    const name = string(value, "action");
    const fields = field(value, "fields") orelse .null;
    if (try challengeAction(name, fields)) return;
    if (try eventAction(name, fields)) return;
    if (try securityAction(name, fields)) return;
    if (try geographicAction(name, fields)) return;
    if (equal(name, "theme")) {
        state.dark = !state.dark;
        return command(.{ .op = "theme", .value = if (state.dark) "dark" else "light" });
    }
    if (equal(name, "pause")) {
        state.paused = !state.paused;
        if (state.paused) {
            state.stats_busy = false;
            try command(.{ .op = "disconnect" });
        } else try refresh();
        return;
    }
    if (equal(name, "dashboard") and state.fullAccess()) {
        state.phase = .dashboard;
        state.message = .{};
        return refresh();
    }
    if (equal(name, "account")) {
        state.totp_secret = .{};
        state.totp_uri = .{};
        state.phase = .password;
        state.stats_busy = false;
        try command(.{ .op = "disconnect" });
        return;
    }
    if (state.busy) return;
    state.message = .{};
    state.busy = true;
    if (equal(name, "login")) {
        state.username = try p.Bytes(64).init(string(fields, "username"));
        return post(
            name,
            "/console/api/login",
            fields,
        );
    }
    if (equal(name, "change-password")) return post("password", "/console/api/password", fields);
    if (equal(name, "logout")) {
        try command(.{ .op = "disconnect" });
        return post(name, "/console/api/logout", .null);
    }
    state.busy = false;
}

fn response(value: std.json.Value, alloc: std.mem.Allocator) !void {
    const id = string(value, "id");
    const status_value = field(value, "status") orelse return;
    if (status_value != .integer) return;
    const status = status_value.integer;
    const body = field(value, "body") orelse return;
    if (std.mem.startsWith(u8, id, "totp")) return securityResponse(id, status, body);
    if (equal(id, "stats")) return statsResponse(status, body, alloc);
    if (equal(id, "events-export")) return eventExportResponse(status);
    if (equal(id, "geoip") or equal(id, "geo-import"))
        return geoResponse(id, status, body);
    state.busy = false;
    if (equal(id, "session") and status == 401) return get("setup", "/console/api/setup");
    if (status != 200) {
        state.stale = status == 0;
        if (state.phase == .loading) state.phase = .login;
        const message = switch (status) {
            429 => "Too many attempts. Please wait a minute.",
            401 => "Sign-in failed. Check your credentials.",
            else => "Could not complete this action. Check your connection and try again.",
        };
        setMessage(message);
        return;
    }
    if (equal(id, "setup")) {
        const required = field(body, "setup_required");
        state.phase = if (required != null and required.? == .bool and required.?.bool)
            .setup
        else
            .login;
        return;
    }
    if (equal(id, "session") or equal(id, "login") or equal(id, "password")) {
        state.csrf = try p.Bytes(64).init(string(body, "csrf"));
        state.role = try p.Bytes(16).init(string(body, "role"));
        const change = field(body, "must_change");
        state.must_change = change != null and change.? == .bool and change.?.bool;
        const totp_required = field(body, "totp_required") orelse .null;
        state.totp_required = totp_required == .bool and totp_required.bool;
        state.phase = if (state.must_change) .password else if (state.totp_required)
            .security
        else
            .dashboard;
        state.message = .{};
        if (state.phase == .dashboard) try refresh();
        if (state.phase == .security) try get("totp", "/console/api/totp");
        return;
    }
    if (equal(id, "logout")) {
        state.phase = .login;
        state.stats_busy = false;
        state.stats = null;
        state.geometry = null;
        state.csrf = .{};
        try command(.{ .op = "disconnect" });
    }
}

fn refresh() !void {
    if (state.stats_busy or state.paused or state.hidden or state.totp_required) return;
    state.stats_busy = true;
    state.epoch = .{};
    try command(.{ .op = "connect", .path = "/console/stream" });
}

fn streamEvent(value: std.json.Value, alloc: std.mem.Allocator) !void {
    if (state.phase != .dashboard or state.paused) return;
    const event = string(value, "state");
    if (equal(event, "open")) return command(.{
        .op = "send",
        .body = .{ .op = "subscribe", .topics = .{"stats"} },
    });
    if (equal(event, "message")) {
        const body = field(value, "body") orelse return error.InvalidMessage;
        const op = string(body, "op");
        const epoch = string(body, "epoch");
        const seq = field(body, "seq") orelse return error.InvalidMessage;
        if (seq != .integer or seq.integer < 0) return error.InvalidMessage;
        const sequence: u64 = @intCast(seq.integer);
        const snapshot = equal(op, "snapshot") and sequence == 0 and epoch.len == 32;
        const delta = equal(op, "delta") and equal(epoch, state.epoch.slice()) and
            sequence == state.sequence + 1;
        if ((!snapshot and !delta) or !equal(string(body, "topic"), "stats")) {
            try command(.{ .op = "disconnect" });
            return reconnect();
        }
        if (snapshot) {
            state.epoch = try p.Bytes(32).init(epoch);
            state.points = @splat(.{});
            state.stats = null;
        }
        state.sequence = sequence;
        state.reconnect_ms = 1000;
        try statsResponse(200, field(body, "data") orelse return error.InvalidMessage, alloc);
        state.stats_busy = true;
        return;
    }
    if (equal(event, "closed")) {
        const code = field(value, "code");
        if (code != null and code.? == .integer and code.?.integer == 1008)
            return statsResponse(401, .null, alloc);
    }
    try command(.{ .op = "disconnect" });
    try reconnect();
}

fn reconnect() !void {
    state.stats_busy = false;
    state.stale = true;
    setMessage("Connection lost. Showing the last received values while reconnecting.");
    try command(.{ .op = "timer", .id = "stats", .delay_ms = state.reconnect_ms });
    state.reconnect_ms = @min(30000, state.reconnect_ms * 2);
}

fn statsResponse(status: i64, body: std.json.Value, alloc: std.mem.Allocator) !void {
    state.stats_busy = false;
    if (state.phase != .dashboard) return;
    if (status == 401 or status == 403) {
        state.phase = .login;
        state.stats_busy = false;
        state.stats = null;
        state.geometry = null;
        state.csrf = .{};
        setMessage("Your session ended. Sign in to continue.");
        return command(.{ .op = "disconnect" });
    }
    state.stale = status != 200;
    if (state.stale) {
        setMessage("Connection lost. Showing the last received values.");
        return;
    }
    const parsed = try std.json.parseFromValue(p.StatsSnapshot, alloc, body, .{});
    defer parsed.deinit();
    var snapshot = parsed.value;
    snapshot.sample_probability = "1/64";
    if (state.stats) |previous| {
        if (snapshot.timestamp > previous.timestamp and snapshot.requests >= previous.requests)
            state.points[@intCast(snapshot.timestamp % 60)] = .{
                .second = snapshot.timestamp,
                .count = snapshot.requests - previous.requests,
            };
    }
    state.stats = snapshot;
    state.received_at = state.browser_time;
    if (snapshot.geoip_available and state.geometry == null and !state.geometry_busy) {
        state.geometry_busy = true;
        try command(.{ .op = "geometry", .path = "/console/assets/world-110m.bin" });
    }
    state.message = .{};
}

fn geographicAction(name: []const u8, fields: std.json.Value) !bool {
    if (equal(name, "geoip") and state.fullAccess()) {
        state.phase = .geoip;
        state.stats_busy = false;
        try command(.{ .op = "disconnect" });
        try get("geoip", "/console/api/geoip");
        return true;
    }
    if (equal(name, "geo-import") and state.phase == .geoip and !state.geo_importing) {
        state.geo_importing = true;
        try post("geo-import", "/console/api/geoip", .{
            .source_version = string(fields, "source_version"),
            .expected_revision = state.geo.revision,
            .checksum = string(fields, "checksum"),
            .csv = string(fields, "csv"),
        });
        return true;
    }
    if (state.phase != .dashboard) return false;
    if (equal(name, "rotate-left")) {
        state.globe.lon -= 20;
    } else if (equal(name, "rotate-right")) {
        state.globe.lon += 20;
    } else if (equal(name, "reset-globe")) {
        state.globe = .{};
    } else if (equal(name, "flat-map")) {
        state.globe.flat = !state.globe.flat;
    } else if (std.mem.startsWith(u8, name, "country-")) {
        const code = std.fmt.parseInt(u16, name[8..], 10) catch return false;
        if (state.geometry) |bytes| {
            if (@import("geography.zig").center(bytes, code)) |position|
                state.globe = .{ .lon = position.lon, .lat = position.lat };
        }
    } else return false;
    if (state.globe.lon > 180) state.globe.lon -= 360;
    if (state.globe.lon < -180) state.globe.lon += 360;
    return true;
}

fn geoResponse(id: []const u8, status: i64, body: std.json.Value) !void {
    state.geo_importing = false;
    if (state.phase != .geoip) return;
    if (status == 401 or status == 403) {
        state.phase = .login;
        state.csrf = .{};
        state.geometry = null;
        return;
    }
    if (status == 0) {
        setMessage("Connection lost. Import status is unknown; reconnecting.");
        state.geo_importing = true;
        return command(.{ .op = "timer", .id = "geoip", .delay_ms = 5000 });
    }
    if (status != 200) {
        setMessage("Import could not start. Check the source month, checksum, and revision.");
        return;
    }
    if (equal(id, "geo-import")) return get("geoip", "/console/api/geoip");
    state.message = .{};
    state.geo = .{
        .revision = number(body, "revision"),
        .digest = try p.Bytes(64).init(string(body, "digest")),
        .source_version = try p.Bytes(7).init(string(body, "source_version")),
        .ranges = @intCast(number(body, "ranges")),
        .loaded_at = number(body, "loaded_at"),
    };
    state.geo_status = try p.Bytes(16).init(string(body, "status"));
    state.geo_progress = @intCast(number(body, "processed_ranges"));
    const active = equal(state.geo_status.slice(), "downloading") or
        equal(state.geo_status.slice(), "validating") or
        equal(state.geo_status.slice(), "storing");
    state.geo_importing = active;
    if (active) try command(.{ .op = "timer", .id = "geoip", .delay_ms = 1000 });
}

fn number(value: std.json.Value, key: []const u8) u64 {
    const item = field(value, key) orelse return 0;
    return if (item == .integer and item.integer >= 0) @intCast(item.integer) else 0;
}

fn field(value: std.json.Value, key: []const u8) ?std.json.Value {
    return if (value == .object) value.object.get(key) else null;
}
fn string(value: std.json.Value, key: []const u8) []const u8 {
    const item = field(value, key) orelse return "";
    return if (item == .string) item.string else "";
}
fn equal(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
fn setMessage(message: []const u8) void {
    state.message = p.Bytes(256).init(message) catch unreachable;
}

test {
    _ = @import("render.zig");
    _ = @import("geography.zig");
    _ = @import("qr.zig");
}

test "required password changes cannot open subscriptions through navigation" {
    sb_init();
    const login =
        \\{"id":"session","status":200,"body":{"csrf":"test","role":"admin",
        \\"must_change":true}}
    ;
    @memcpy(input[0..login.len], login);
    sb_event(2, login.len);
    try std.testing.expectEqual(.password, state.phase);
    try std.testing.expect(std.mem.indexOf(u8, commands[0..commands_length], "connect") == null);
    const action_json = "{\"action\":\"dashboard\",\"fields\":{}}";
    @memcpy(input[0..action_json.len], action_json);
    sb_event(1, action_json.len);
    try std.testing.expectEqual(.password, state.phase);
    try std.testing.expect(std.mem.indexOf(u8, html[0..html_length], "<svg") == null);
}

fn securityAction(name: []const u8, fields: std.json.Value) !bool {
    if (equal(name, "recovery-saved")) {
        state.totp_secret = .{};
        state.totp_uri = .{};
        state.recovery_codes = @splat(.{});
        state.recovery_count = 0;
        state.csrf = .{};
        state.phase = .login;
        return true;
    }
    if (equal(name, "security") and state.csrf.len != 0) {
        state.phase = .security;
        state.message = .{};
        state.totp_secret = .{};
        state.totp_uri = .{};
        state.stats_busy = false;
        try command(.{ .op = "disconnect" });
        try get("totp", "/console/api/totp");
        return true;
    }
    if (state.phase != .security or state.busy) return false;
    if (!equal(name, "totp-enroll") and !equal(name, "totp-confirm")) return false;
    state.busy = true;
    state.message = .{};
    const enroll = equal(name, "totp-enroll");
    try post(
        name,
        if (enroll) "/console/api/totp/enroll" else "/console/api/totp/confirm",
        .{
            .password = string(fields, "password"),
            .code = string(fields, "code"),
            .revision = state.totp_revision,
        },
    );
    return true;
}

fn securityResponse(id: []const u8, status: i64, body: std.json.Value) !void {
    state.busy = false;
    if (state.phase != .security) return;
    if (status != 200) {
        const message = switch (status) {
            429 => "Too many attempts. Wait a minute and try again.",
            else => "Could not update authentication. Check your password, code and session.",
        };
        setMessage(message);
        return;
    }
    if (equal(id, "totp")) {
        const available = field(body, "available") orelse .null;
        const enabled = field(body, "enabled") orelse .null;
        state.totp_available = available == .bool and available.bool;
        state.totp_enabled = enabled == .bool and enabled.bool;
        state.totp_revision = number(body, "revision");
    } else if (equal(id, "totp-enroll")) {
        state.totp_secret = try p.Bytes(32).init(string(body, "secret"));
        state.totp_uri = try p.Bytes(134).init(string(body, "uri"));
        state.totp_revision = number(body, "revision");
    } else if (equal(id, "totp-confirm")) {
        const codes = field(body, "recovery_codes") orelse return error.InvalidResponse;
        if (codes != .array or codes.array.items.len != 10) return error.InvalidResponse;
        for (codes.array.items, &state.recovery_codes) |code, *dest| {
            if (code != .string or code.string.len != 32) return error.InvalidResponse;
            dest.* = try p.Bytes(32).init(code.string);
        }
        state.recovery_count = 10;
        state.totp_secret = .{};
        state.totp_uri = .{};
        state.csrf = .{};
        state.geometry = null;
        state.stats = null;
    }
}

test "required authenticator enrollment cannot open dashboard data or geometry" {
    sb_init();
    const login =
        \\{"id":"login","status":200,"body":{"csrf":"test","role":"admin",
        \\"must_change":false,"totp_required":true}}
    ;
    @memcpy(input[0..login.len], login);
    sb_event(2, login.len);
    try std.testing.expectEqual(.security, state.phase);
    const navigation = "{\"action\":\"dashboard\",\"fields\":{}}";
    @memcpy(input[0..navigation.len], navigation);
    sb_event(1, navigation.len);
    try std.testing.expectEqual(.security, state.phase);
    try std.testing.expect(std.mem.indexOf(u8, commands[0..commands_length], "connect") == null);
    try std.testing.expect(std.mem.indexOf(u8, html[0..html_length], "<svg") == null);
}

fn eventQuery(export_page: bool, csv: bool) !void {
    try command(.{ .op = "disconnect" });
    const model = &state.events;
    var id: [20]u8 = undefined;
    var campaign_id: [20]u8 = undefined;
    const campaign = switch (model.campaign) {
        0 => "",
        else => try std.fmt.bufPrint(&campaign_id, "{d}", .{model.campaign}),
    };
    const before: ?struct { time: u64, id: []const u8 } = if (model.cursors[model.page]) |cursor|
        .{ .time = cursor.time, .id = try std.fmt.bufPrint(&id, "{d}", .{cursor.id}) }
    else
        null;
    try command(.{
        .op = if (export_page) "download" else "request",
        .id = if (export_page) "events-export" else "events",
        .method = "POST",
        .filename = if (csv) "sibuna-events.csv" else "sibuna-events.json",
        .path = if (export_page) "/console/api/events/export" else "/console/api/events/query",
        .csrf = state.csrf.slice(),
        .body = .{
            .format = if (csv) "csv" else "json",
            .view = if (model.grouped) "source" else "raw",
            .node = model.node,
            .campaign = campaign,
            .before = before,
            .category = model.category.slice(),
            .ip = model.ip.slice(),
            .path_prefix = model.path.slice(),
            .until = model.until,
            .from = if (model.hours == 0) @as(u64, 0) else model.until -| model.hours * 3600,
        },
    });
}

fn eventResponse(status: i64, body: ?@import("events_state.zig").WirePage) !void {
    if (state.phase != .events) return;
    state.events.busy = false;
    if (status == 401 or status == 403) {
        state.events = .{};
        state.csrf = .{};
        state.phase = .login;
        setMessage("Your access changed. Sign in again to view incidents.");
        return;
    }
    if (status == 429) {
        setMessage("The query allowance is used. Wait a minute before trying again.");
        return;
    }
    if (status != 200) {
        setMessage("Could not load incidents. Check your connection or narrow the filters.");
        return;
    }
    try state.events.decode(body orelse return error.InvalidResponse);
    if (state.events.focus_results) try command(.{
        .op = "focus",
        .selector = "[aria-label=\"Incident results\"]",
    });
}

fn eventAction(name: []const u8, fields: std.json.Value) !bool {
    const exporting = equal(name, "events-export") or equal(name, "events-export-csv");
    if (exporting and state.phase == .events and state.fullAccess()) {
        if (state.events.busy or state.events.exporting or state.events.count == 0) return true;
        state.events.exporting = true;
        state.events.export_ready = false;
        state.message = .{};
        try eventQuery(true, equal(name, "events-export-csv"));
        return true;
    }
    if (!try @import("events_actions.zig").act(&state, name, fields)) return false;
    try eventQuery(false, false);
    return true;
}

fn eventExportResponse(status: i64) !void {
    state.events.exporting = false;
    state.events.export_ready = status == 200;
    if (state.phase != .events) return;
    if (status == 401 or status == 403) return eventResponse(status, null);
    setMessage(switch (status) {
        200 => "Your page export is ready. It contains records matching this view.",
        429 => "The export allowance is used. Wait a minute before exporting again.",
        else => "Could not prepare the export. Check your connection and retry.",
    });
}

fn challengeAction(name: []const u8, fields: std.json.Value) !bool {
    if (!state.fullAccess()) return false;
    if (equal(name, "challenges")) {
        state.phase = .challenges;
        state.challenges = .{};
    } else {
        if (state.phase != .challenges or state.challenges.busy) return false;
        if (equal(name, "challenges-bin")) {
            state.challenges.selected = try std.fmt.parseInt(u8, string(fields, "bin"), 10);
        } else if (!equal(name, "challenges-refresh")) return false;
    }
    state.message = .{};
    state.challenges.busy = true;
    state.stats_busy = false;
    try command(.{ .op = "disconnect" });
    try post("challenges", "/console/api/challenges", .{ .bin = state.challenges.selected });
    return true;
}

fn challengeResponse(status: i64, snapshot: p.challenges.Snapshot) void {
    if (state.phase != .challenges) return;
    state.challenges.busy = false;
    if (status == 401 or status == 403) {
        state = .{ .phase = .login, .dark = state.dark };
        setMessage("Your access changed. Sign in again to view challenges.");
        return;
    }
    if (status != 200) {
        state.challenges.stale = true;
        setMessage("Could not refresh challenges. Check your connection and try again.");
        return;
    }
    state.challenges.snapshot = snapshot;
    state.challenges.selected = snapshot.selected;
    state.challenges.received_at = state.browser_time;
    state.challenges.stale = false;
}

/// Large fixed arrays bypass the generic Value tree, whose growth would consume the
/// event arena despite a small wire response. Unknown fields are skipped without a tree.
fn boundedEnvelope(bytes: []const u8, alloc: std.mem.Allocator) !bool {
    const header = try std.json.parseFromSlice(
        struct { id: []const u8 = "" },
        alloc,
        bytes,
        .{ .ignore_unknown_fields = true },
    );
    defer header.deinit();
    if (equal(header.value.id, "events")) return eventEnvelope(bytes, alloc);
    if (!equal(header.value.id, "challenges")) return false;
    if (state.phase != .challenges) return true;
    const Envelope = struct {
        id: []const u8,
        status: i64,
        body: p.challenges.Snapshot,
        browser_time: u64 = 0,
    };
    const parsed = std.json.parseFromSlice(
        Envelope,
        alloc,
        bytes,
        .{ .ignore_unknown_fields = true },
    ) catch {
        state.challenges.busy = false;
        state.challenges.stale = true;
        setMessage("Could not read challenge observations. Try refreshing.");
        return true;
    };
    defer parsed.deinit();
    state.browser_time = parsed.value.browser_time;
    const previous = state.phase;
    challengeResponse(parsed.value.status, parsed.value.body);
    if (state.phase != previous) try command(.{
        .op = "focus",
        .selector = "main h1",
        .top = true,
    });
    return true;
}

test "complete challenge browser response fits the fixed event arena and releases refresh" {
    sb_init();
    state.phase = .challenges;
    state.challenges.busy = true;
    var writer: std.Io.Writer = .fixed(&input);
    try std.json.Stringify.value(.{
        .id = "challenges",
        .status = 200,
        .browser_time = 100,
        .body = p.challenges.Snapshot{ .submitted = 123, .bin_accepted = @splat(1) },
    }, .{}, &writer);
    sb_event(2, writer.buffered().len);
    try std.testing.expect(!state.challenges.busy);
    try std.testing.expectEqual(@as(u64, 123), state.challenges.snapshot.?.submitted);
    try std.testing.expectEqual(@as(u64, 100), state.challenges.received_at);
}

fn eventEnvelope(bytes: []const u8, alloc: std.mem.Allocator) !bool {
    if (state.phase != .events) return true;
    const Envelope = struct {
        id: []const u8,
        status: i64,
        body: @import("events_state.zig").WirePage,
        browser_time: u64 = 0,
    };
    const parsed = std.json.parseFromSlice(
        Envelope,
        alloc,
        bytes,
        .{ .ignore_unknown_fields = true },
    ) catch {
        state.events.busy = false;
        setMessage("Could not read incidents. Narrow the filters and try again.");
        return true;
    };
    defer parsed.deinit();
    state.browser_time = parsed.value.browser_time;
    const previous = state.phase;
    eventResponse(parsed.value.status, parsed.value.body) catch {
        state.events.busy = false;
        setMessage("Could not read incident fields. Please try again.");
    };
    if (state.phase != previous) try command(.{
        .op = "focus",
        .selector = "main h1",
        .top = true,
    });
    return true;
}

test "full incident browser envelope fits fixed arena and retains exact candidate IDs" {
    sb_init();
    state.phase = .events;
    state.events.busy = true;
    var writer: std.Io.Writer = .fixed(&input);
    const row: @import("events_state.zig").WireRow = .{
        .id = "9007199254740993",
        .campaign = "9007199254740993",
        .capture = .{
            .selected_status = 403,
            .query_bytes = 20,
            .body_bytes = 30,
            .declared_body_bytes = 40,
            .truncated = 64,
        },
    };
    try std.json.Stringify.value(.{
        .id = "events",
        .status = 200,
        .browser_time = 100,
        .body = .{ .rows = @as([10]@TypeOf(row), @splat(row)), .next = null },
    }, .{}, &writer);
    sb_event(2, writer.buffered().len);
    try std.testing.expect(!state.events.busy);
    try std.testing.expectEqual(@as(usize, 10), state.events.count);
    try std.testing.expectEqual(@as(u64, 9007199254740993), state.events.rows[0].campaign.?);
}
