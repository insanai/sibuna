//! Browser state machine. JavaScript transports commands and DOM events only.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const render = @import("render.zig");
const live = @import("live_controller.zig");
const policy_controller = @import("policy_controller.zig");
const routing = @import("routing.zig");
// Startup initializes every owned field; avoid shipping a duplicate state image in Wasm data.
var state: State = undefined;
var initialized: bool = false;
var similarity_generation: u32 = 0;
var policy_generation: u32 = 0;
var input: [p.ranking_history.event_bytes]u8 = undefined;
// Browser events execute serially. A fixed scratch region keeps large JSON arrays
// off the Wasm stack and is erased after every event, including parser failures.
var event_memory: [512 * 1024]u8 = undefined;
var html: [512 * 1024]u8 = undefined;
var geometry: [@import("geography.zig").max_bytes]u8 = undefined;
var html_length: usize = 0;
var commands: [16 * 1024]u8 = undefined;
var command_writer: std.Io.Writer = undefined;
var command_count: usize = 0;
var commands_length: usize = 0;

export fn sb_frame(milliseconds: f64) usize {
    if (!initialized) return 0;
    return @import("globe_motion.zig").frame(&state, milliseconds);
}

export fn sb_frame_html() [*]const u8 {
    return &@import("globe_motion.zig").output;
}

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
    if (!initialized) return;
    begin();
    state.geometry_busy = false;
    if (state.phase != .dashboard or !state.fullAccess() or length > geometry.len) {
        finish();
        return;
    }
    if (@import("geography.zig").validate(geometry[0..length])) |_| {
        state.geometry = geometry[0..length];
        state.geometry_retry_at = 0;
    } else |_| {
        state.geometry_retry_at = state.browser_time +| 30;
    }
    finish();
}

export fn sb_init() void {
    live.init();
    state.reset();
    initialized = true;
    begin();
    get("session", "/console/api/session") catch unreachable;
    finish();
}

export fn sb_event(kind: u32, length: usize) void {
    if (!initialized or length > input.len) return;
    begin();
    defer std.crypto.secureZero(u8, &event_memory);
    defer std.crypto.secureZero(u8, input[0..length]);
    var fixed = std.heap.FixedBufferAllocator.init(&event_memory);
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
    if (kind == 2 and (boundedEnvelope(parsed.value, fixed.allocator()) catch false)) {
        finish();
        return;
    }
    const previous_phase = state.phase;
    dispatch(kind, parsed.value, fixed.allocator()) catch {
        setMessage("Could not complete the action. Please try again.");
        state.busy = false;
    };
    if (routing.take(&state)) |name| actionName(name, .null) catch {
        setMessage("Could not open this page. Please try again.");
    };
    if (state.phase != previous_phase) {
        if (previous_phase == .users) state.users.clearSecret();
        if (previous_phase == .tokens) state.tokens.clearSecret();
        state.navigation_open = false;
        command(.{ .op = "focus", .selector = "main h1", .top = true }) catch unreachable;
    }
    finish();
}

fn begin() void {
    std.crypto.secureZero(u8, &commands);
    command_writer = .fixed(&commands);
    command_count = 0;
    command_writer.writeByte('[') catch unreachable;
}

fn finish() void {
    @import("kiosk_grant.zig").retain(&state);
    routing.sync(&state, outbox()) catch unreachable;
    live.sync(&state, outbox()) catch setMessage("Live connection unavailable. Reload to retry.");
    if (state.fullAccess() and !state.hidden)
        command(.{ .op = "timer", .id = "age", .delay_ms = 1000 }) catch unreachable;
    @import("traffic_period_controller.zig").sync(&state, outbox()) catch
        state.traffic_period.message.set("TRAFFIC001: Retained window unavailable. " ++
            "Refresh the period after observations recover.") catch unreachable;
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
    if (equal(value.op, "disconnect")) {
        try live.stop(outbox());
    } else try outbox().emit(value);
    // Every navigation path that closes transport must release its subscription guard.
    // Keep the old snapshot visibly stale until a new subscription supplies fresh data.
    if (equal(value.op, "disconnect")) {
        state.stats_busy = false;
        state.stale = true;
    }
}

fn get(id: []const u8, path: []const u8) !void {
    try command(.{ .op = "request", .id = id, .method = "GET", .path = path });
}

fn post(id: []const u8, path: []const u8, body: anytype) !void {
    try outbox().post(id, path, body);
}

fn requestPrefix(id: []const u8, path: []const u8) !std.json.Stringify {
    return outbox().prefix(id, path);
}

fn outbox() @import("transport.zig").Outbox {
    return .{ .writer = &command_writer, .count = &command_count, .csrf = state.csrf.slice() };
}

fn dispatch(kind: u32, value: std.json.Value, alloc: std.mem.Allocator) !void {
    state.browser_time = number(value, "browser_time");
    switch (kind) {
        1 => try actionName(string(value, "action"), field(value, "fields") orelse .null),
        8 => routing.request(&state.route, string(value, "route")),
        9, 10 => try @import("appearance.zig").environment(
            &state.appearance,
            value,
            kind == 9,
            outbox(),
        ),
        2 => try response(value, alloc),
        3 => {
            if (state.hidden) return;
            if (equal(string(value, "id"), "live-retry")) live.timer();
            const previous_phase = state.phase;
            @import("kiosk_page.zig").cycle(&state);
            if (state.kiosk and state.phase == .security_overview and !state.paused and
                (previous_phase != state.phase or
                    (!state.security_overview.busy[0] and
                        state.browser_time -| state.security_overview.request.until >= 60)))
                try @import("security_overview_controller.zig").refresh(&state, outbox());
            if (state.phase == .nodes)
                return @import("nodes_controller.zig").tick(&state, outbox());
            if (equal(string(value, "id"), "age")) return;
            if (equal(string(value, "id"), "reputation-undo"))
                return @import("reputation_controller.zig").tick(&state);
            if (state.phase == .dashboard and !state.paused) try refresh();
            if (state.phase == .geoip) try get("geoip", "/console/api/geoip");
            if (state.phase == .similarity) try similarityQuery();
        },
        4 => try streamEvent(value, alloc),
        7 => {
            const reduced = field(value, "reduced_motion") orelse return;
            if (reduced == .bool) state.motion.reduced = reduced.bool;
        },
        5 => {
            const hidden = field(value, "hidden") orelse return;
            if (hidden != .bool) return;
            state.hidden = hidden.bool;
            state.stats_busy = false;
            if (state.hidden) {
                try command(.{ .op = "disconnect" });
            } else if (state.phase == .dashboard and !state.paused) {
                try refresh();
            } else if (state.phase == .similarity) {
                try similarityQuery();
            } else if (state.phase == .geoip) {
                try get("geoip", "/console/api/geoip");
            }
        },
        else => {},
    }
}

fn actionName(name: []const u8, fields: std.json.Value) !void {
    if (@import("kiosk_page.zig").action(&state, name)) return;
    if (equal(name, "navigation-toggle") and state.fullAccess()) {
        state.navigation_open = !state.navigation_open;
        return;
    }
    if (state.navigation_open and @import("shell.zig").destination(name)) {
        state.navigation_open = false;
        try command(.{ .op = "focus", .selector = "main h1", .top = true });
    }
    if (equal(name, "dashboard-node") and state.fullAccess()) {
        try @import("dashboard_scope.zig").select(&state, string(fields, "node"));
        if (state.phase == .security_overview)
            return @import("security_overview_controller.zig").refresh(&state, outbox());
        return refresh();
    }
    const management = @import("management_controller.zig");
    if (try managed().fromAudit(name)) return;
    if (try management.action(&state, name, fields, outbox())) return;
    if (try managed().transfer(name, fields)) return;
    if (try managed().inspection(name, fields)) return;
    if (try managed().action(name, fields)) return;
    if (try addressAction(name)) return;
    if (try policy_controller.action(managed(), name, fields)) return;
    if (try similarityAction(name)) return;
    if (try challengeAction(name, fields)) return;
    if (try eventAction(name, fields)) return;
    if (try accountSecurity().action(name, fields)) return;
    if (try geographicAction(name, fields)) return;
    if (try @import("appearance.zig").action(&state.appearance, name, outbox())) return;
    if (equal(name, "pause")) {
        state.paused = !state.paused;
        if (state.paused) {
            state.stats_busy = false;
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
    if (equal(name, "kiosk-exchange")) return post(name, "/console/api/kiosk/exchange", .{
        .code = string(fields, "code"),
    });
    if (equal(name, "change-password")) return post("password", "/console/api/password", fields);
    if (equal(name, "logout")) {
        try live.signOut(outbox());
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
    const management = @import("management_controller.zig");
    if (try management.response(&state, id, status, body, alloc, outbox())) return;
    if (std.mem.startsWith(u8, id, "rankings-") or std.mem.startsWith(u8, id, "timeline-") or
        std.mem.startsWith(u8, id, "minutes-"))
        return observationResponse(id, status, body, alloc);
    if (std.mem.startsWith(u8, id, "policies-") or
        std.mem.startsWith(u8, id, "policy-test-") or std.mem.startsWith(u8, id, "managed-"))
        return policy_controller.response(managed(), id, status, body);
    if (std.mem.startsWith(u8, id, "totp")) return accountSecurity().response(id, status, body);
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
    if (equal(id, "setup")) return setupResponse(body);
    if (equal(id, "kiosk-exchange")) return kioskOpened(body);
    if (equal(id, "session") or equal(id, "login") or equal(id, "password")) {
        live.authenticated();
        kioskFlag(body);
        state.user_id = try @import("json_value.zig").decode(
            u64,
            field(body, "user") orelse return error.InvalidResponse,
            alloc,
        );
        state.csrf = try p.Bytes(64).init(string(body, "csrf"));
        state.console_node = std.math.cast(u32, number(body, "node"));
        if (state.console_node == 0) state.console_node = null;
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
        if (state.phase == .security) try accountSecurity().refresh();
        return;
    }
    if (equal(id, "logout")) {
        resetState(.login);
        try command(.{ .op = "disconnect" });
    }
}

fn setupResponse(body: std.json.Value) void {
    const required = field(body, "setup_required");
    state.phase = if (required != null and required.? == .bool and required.?.bool)
        .setup
    else
        .login;
}

/// A wall display signs in with a one-time code: viewer role, statistics only, no shell.
fn kioskOpened(body: std.json.Value) !void {
    // A code exchange changes principal; no account queries or retained private rows survive.
    const browser_time = state.browser_time;
    const motion = state.motion;
    const hidden = state.hidden;
    resetState(.dashboard);
    state.browser_time = browser_time;
    state.motion = motion;
    state.hidden = hidden;
    state.csrf = try p.Bytes(64).init(string(body, "csrf"));
    state.role = try p.Bytes(16).init("viewer");
    state.kiosk = true;
    state.kiosk_expires = number(body, "expires");
    state.kiosk_cycled_at = state.browser_time;
    state.must_change = false;
    state.totp_required = false;
    state.phase = .dashboard;
    state.message = .{};
    return refresh();
}

fn kioskFlag(body: std.json.Value) void {
    const kiosk = field(body, "kiosk");
    state.kiosk = kiosk != null and kiosk.? == .bool and kiosk.?.bool;
    state.kiosk_expires = if (state.kiosk) number(body, "expires") else 0;
}

test "kiosk exchange clears account history and requests only display-scoped observations" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    sb_init();
    state.browser_time = 100;
    state.history_minutes = true;
    state.rankings.busy = true;
    const grant = try std.json.parseFromSliceLeaky(
        std.json.Value,
        alloc,
        "{\"csrf\":\"display-session\",\"expires\":43300}",
        .{},
    );
    begin();
    try kioskOpened(grant);
    try t.expect(state.kiosk and !state.history_minutes and !state.rankings.busy);
    try t.expectEqual(@as(u64, 100), state.browser_time);
    state.timeline_open = true;
    const snapshot = try std.json.parseFromSliceLeaky(std.json.Value, alloc,
        \\{"timestamp":100,"requests":1,"admitted":1,"challenged":0,"denied":0,
        \\ "origin_4xx":0,"origin_5xx":0,"incidents":0,"incidents_dropped":0,
        \\ "sample_loss":0,"unknown_samples":0}
    , .{});
    begin();
    try statsResponse(200, snapshot, alloc);
    const emitted = command_writer.buffered();
    try t.expect(state.phase == .dashboard and state.stats != null);
    try t.expect(std.mem.indexOf(u8, emitted, "/console/api/rankings") == null);
    try t.expect(std.mem.indexOf(u8, emitted, "/console/api/minutes") == null);
    try t.expect(std.mem.indexOf(u8, emitted, "/console/api/timeline") != null);
    state.history_minutes = true;
    state.stats.?.minute_history.available = true;
    try t.expect(@import("minute_panel.zig").request(&state, true) == null);
    state.history_minutes = false;
    var markup: [16384]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&markup);
    try @import("timeline_panel.zig").table(&state, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "Minute history") == null);
}

fn refresh() !void {
    try live.sync(&state, outbox());
}

fn streamEvent(value: std.json.Value, alloc: std.mem.Allocator) !void {
    if (try live.event(&state, value, alloc, outbox())) |body|
        statsResponse(200, body, alloc) catch try live.failed(&state, value, outbox());
}

fn statsResponse(status: i64, body: std.json.Value, alloc: std.mem.Allocator) !void {
    state.stats_busy = false;
    if (state.phase != .dashboard and state.phase != .security_overview) return;
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
    var snapshot: p.StatsSnapshot = undefined;
    try @import("json_value.zig").into(&snapshot, body, alloc);
    if (snapshot.outcomes_version > 1) {
        state.stale = true;
        setMessage("This statistics format needs a newer interface. Reload after upgrading.");
        return;
    }
    snapshot.sample_probability = "1/64";
    if (snapshot.server_location) |location| {
        if (!location.valid()) snapshot.server_location = null;
    }
    if (state.stats == null and state.geometry == null) {
        if (snapshot.server_location) |location|
            state.globe = .{ .lat = location.lat, .lon = location.lon };
    }
    @import("stats_series.zig").accept(&state, snapshot);
    state.stats = snapshot;
    if (state.dashboard_scope) |scope| state.stale = scope.stale;
    state.received_at = state.browser_time;
    if (state.phase == .security_overview) return;
    try refreshRankings();
    try refreshTimeline(false);
    if (state.fullAccess() and state.geometry == null and !state.geometry_busy and
        state.browser_time >= state.geometry_retry_at)
    {
        state.geometry_busy = true;
        try command(.{ .op = "geometry", .path = "/console/assets/world-110m.bin" });
    }
    state.message = .{};
}

fn refreshRankings() !void {
    const id = @import("rankings_controller.zig").request(&state) orelse return;
    try post(id.slice(), "/console/api/rankings/query", p.rankings.Query{
        .node = @import("dashboard_scope.zig").selectedNode(&state),
    });
}

fn refreshTimeline(force: bool) !void {
    if (state.history_minutes) {
        const request = @import("minute_panel.zig").request(&state, force) orelse return;
        return post(request.id.slice(), "/console/api/minutes", request.body);
    }
    const request = @import("timeline_panel.zig").request(&state, force) orelse return;
    try post(request.id.slice(), "/console/api/timeline", request.body);
}

fn observationResponse(
    id: []const u8,
    status: i64,
    body: std.json.Value,
    alloc: std.mem.Allocator,
) !void {
    const expired = if (std.mem.startsWith(u8, id, "minutes-"))
        @import("minute_panel.zig").response(&state, id, status, body, alloc)
    else if (std.mem.startsWith(u8, id, "timeline-"))
        @import("timeline_panel.zig").response(&state, id, status, body, alloc)
    else
        @import("rankings_controller.zig").response(&state, id, status, body, alloc) == .expired;
    if (!expired) return;
    resetState(.login);
    setMessage("Your session ended. Sign in to continue.");
    try command(.{ .op = "disconnect" });
}

fn geographicAction(name: []const u8, fields: std.json.Value) !bool {
    if (equal(name, "geoip") and state.fullAccess()) {
        state.phase = .geoip;
        state.stats_busy = false;
        try get("geoip", "/console/api/geoip");
        return true;
    }
    if (equal(name, "geo-import") and state.phase == .geoip and !state.geo_importing) {
        state.geo_importing = true;
        try post("geo-import", "/console/api/geoip", .{
            .provider = string(fields, "provider"),
            .source_version = string(fields, "source_version"),
            .expected_revision = state.geo.revision,
            .checksum = string(fields, "checksum"),
            .csv = string(fields, "csv"),
        });
        return true;
    }
    if (state.phase != .dashboard) return false;
    switch (try @import("history_controls.zig").action(&state, name, fields)) {
        .none => return @import("globe_motion.zig").action(&state, name),
        .changed => {},
        .query => try refreshTimeline(true),
    }
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
        .provider = try p.Bytes(12).init(string(body, "provider")),
        .source_version = try p.Bytes(10).init(string(body, "source_version")),
        .source_digests = try p.Bytes(129).init(string(body, "source_digests")),
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

const number = @import("json_value.zig").unsignedOrZero;

const field = @import("events_state.zig").field;
const string = @import("events_state.zig").string;
fn equal(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
fn setMessage(message: []const u8) void {
    state.message_success = false;
    state.message = p.Bytes(256).init(message) catch unreachable;
}

test {
    _ = @import("golden.zig");
    _ = @import("render.zig");
    _ = @import("geography.zig");
    _ = @import("qr.zig");
}

test "authenticated earth remains bounded without a GeoIP provider" {
    const world = @embedFile("console_world");
    try @import("geography.zig").validate(world);
    var model: State = .{ .phase = .dashboard, .geometry = world };
    model.csrf = try p.Bytes(64).init("test");
    model.stats = std.mem.zeroes(p.StatsSnapshot);
    const buffer = try std.testing.allocator.alloc(u8, 512 * 1024);
    defer std.testing.allocator.free(buffer);
    for (0..5) |view| {
        model.globe = .{ .lon = @as(f64, @floatFromInt(view)) * 90, .flat = view == 4 };
        var writer: std.Io.Writer = .fixed(buffer);
        try render.render(&model, &writer);
        const output = writer.buffered();
        try std.testing.expect(std.mem.indexOf(u8, output, "GeoIP unavailable") != null);
        try std.testing.expect(std.mem.indexOf(u8, output, "Rotate left") != null);
        const unavailable = std.mem.indexOf(u8, output, "World boundaries unavailable");
        try std.testing.expect(unavailable == null);
    }
}

test "geometry failures delay retries and cannot publish after revocation" {
    sb_init();
    state = .{ .phase = .dashboard, .browser_time = 100 };
    state.csrf = try p.Bytes(64).init("test");
    sb_geometry_loaded(0);
    try std.testing.expectEqual(@as(u64, 130), state.geometry_retry_at);
    const world = @embedFile("console_world");
    @memcpy(geometry[0..world.len], world);
    state.csrf = .{};
    sb_geometry_loaded(world.len);
    try std.testing.expect(state.geometry == null);
    state.csrf = try p.Bytes(64).init("test");
    sb_geometry_loaded(world.len);
    try std.testing.expect(state.geometry != null);
    try std.testing.expectEqual(@as(u64, 0), state.geometry_retry_at);
}

test "required password changes cannot open subscriptions through navigation" {
    sb_init();
    const login =
        \\{"id":"session","status":200,"body":{"user":1,"csrf":"test","role":"admin",
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

test "policy navigation retains the authenticated connection when returning to the dashboard" {
    sb_init();
    state.phase = .dashboard;
    state.csrf = try p.Bytes(64).init("test");
    begin();
    try refresh();
    const opened = "{\"state\":\"open\"}";
    @memcpy(input[0..opened.len], opened);
    sb_event(4, opened.len);
    const policies = "{\"action\":\"policies\",\"fields\":{}}";
    @memcpy(input[0..policies.len], policies);
    sb_event(1, policies.len);
    try std.testing.expectEqual(.policies, state.phase);
    try std.testing.expect(std.mem.indexOf(
        u8,
        commands[0..commands_length],
        "connect",
    ) == null);
    const dashboard = "{\"action\":\"dashboard\",\"fields\":{}}";
    @memcpy(input[0..dashboard.len], dashboard);
    sb_event(1, dashboard.len);
    try std.testing.expectEqual(.dashboard, state.phase);
    try std.testing.expect(std.mem.indexOf(
        u8,
        commands[0..commands_length],
        "connect",
    ) == null);
}

test "required authenticator enrollment cannot open dashboard data or geometry" {
    sb_init();
    const login =
        \\{"id":"login","status":200,"body":{"user":1,"csrf":"test","role":"admin",
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
    const model = &state.events;
    var id: [20]u8 = undefined;
    var campaign_id: [20]u8 = undefined;
    var incident_id: [20]u8 = undefined;
    const incident = switch (model.incident) {
        0 => "",
        else => try std.fmt.bufPrint(&incident_id, "{d}", .{model.incident}),
    };
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
            .incident = incident,
            .before = before,
            .category = model.category.slice(),
            .module = model.module,
            .country = model.country.slice(),
            .ip = model.ip.slice(),
            .path_prefix = model.path.slice(),
            .until = model.until,
            .from = model.from orelse
                if (model.hours == 0) @as(u64, 0) else model.until -| model.hours * 3600,
        },
    });
}

fn eventResponse(status: i64, body: ?@import("events_state.zig").WirePage) !void {
    if (state.phase != .events) return;
    state.events.busy = false;
    if (status == 401 or status == 403) {
        state.events.clear();
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

/// An incident's address opens the IP groups form prefilled; nothing is submitted until
/// the operator chooses a duration and saves.
fn addressAction(name: []const u8) !bool {
    const deny = std.mem.startsWith(u8, name, "events-deny-");
    const allow = std.mem.startsWith(u8, name, "events-allow-");
    if (!(deny or allow)) return false;
    if (state.kiosk or !state.allows(.manage_policy)) return true;
    const address = name[if (deny) "events-deny-".len else "events-allow-".len..];
    if (address.len == 0 or address.len > 48) return error.InvalidRequest;
    const draft = try p.Bytes(48).init(address);
    _ = try policy_controller.action(managed(), "policies", .null);
    state.reputation.draft_prefix = draft;
    state.reputation.draft_deny = deny;
    try command(.{ .op = "focus", .selector = "#reputation-prefix" });
    return true;
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
    try post("challenges", "/console/api/challenges", .{ .bin = state.challenges.selected });
    return true;
}

fn challengeResponse(status: i64, snapshot: p.challenges.Snapshot) void {
    if (state.phase != .challenges) return;
    state.challenges.busy = false;
    if (status == 401 or status == 403) {
        resetState(.login);
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
    state.challenges.timing_received_at = state.browser_time;
    state.challenges.stale = false;
}

/// Decode one shared JSON tree, then validate bounded response types from that tree.
/// This avoids duplicating scanner/parser machinery for every management response.
fn boundedEnvelope(value: std.json.Value, alloc: std.mem.Allocator) !bool {
    const id = string(value, "id");
    if (std.mem.startsWith(u8, id, "similarity-")) return similarityEnvelope(value, id, alloc);
    if (equal(id, "events")) return eventEnvelope(value, alloc);
    if (!equal(id, "challenges")) return false;
    if (state.phase != .challenges) return true;
    const Envelope = struct {
        id: []const u8,
        status: i64,
        body: p.challenges.Snapshot,
        browser_time: u64 = 0,
    };
    const parsed = @import("json_value.zig").decode(Envelope, value, alloc) catch {
        state.challenges.busy = false;
        state.challenges.stale = true;
        setMessage("Could not read challenge observations. Try refreshing.");
        return true;
    };
    state.browser_time = parsed.browser_time;
    const previous = state.phase;
    challengeResponse(parsed.status, parsed.body);
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

fn eventEnvelope(value: std.json.Value, alloc: std.mem.Allocator) !bool {
    if (state.phase != .events) return true;
    const Envelope = struct {
        id: []const u8,
        status: i64,
        body: @import("events_state.zig").WirePage,
        browser_time: u64 = 0,
    };
    const parsed = @import("json_value.zig").decode(Envelope, value, alloc) catch {
        state.events.busy = false;
        setMessage("Could not read incidents. Narrow the filters and try again.");
        return true;
    };
    state.browser_time = parsed.browser_time;
    const previous = state.phase;
    eventResponse(parsed.status, parsed.body) catch {
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

fn similarityAction(name: []const u8) !bool {
    if (!state.fullAccess()) return false;
    if (equal(name, "similarity-return") and state.similarity.source != 0) {
        state.phase = .similarity;
        state.message = .{};
        return true;
    }
    const prefix = "events-similar-";
    if (std.mem.startsWith(u8, name, prefix)) {
        const source = try std.fmt.parseInt(u64, name[prefix.len..], 10);
        if (source == 0 or source > std.math.maxInt(i64)) return error.InvalidRequest;
        state.similarity = .{
            .source = source,
            .until = state.events.until,
            .from = switch (state.events.hours) {
                0 => 0,
                else => state.events.until -| state.events.hours * 3600,
            },
            .running = true,
        };
        state.phase = .similarity;
    } else {
        if (state.phase != .similarity or state.similarity.complete) return false;
        if (equal(name, "similarity-pause")) {
            state.similarity.running = false;
        } else if (equal(name, "similarity-resume")) {
            state.similarity.running = true;
        } else return false;
    }
    similarity_generation +%= 1;
    state.similarity.generation = similarity_generation;
    state.similarity.busy = false;
    state.message = .{};
    try similarityQuery();
    return true;
}

fn similarityQuery() !void {
    const model = &state.similarity;
    if (!model.running or model.busy or state.hidden or !state.fullAccess()) return;
    var source: [20]u8 = undefined;
    var cursor_id: [20]u8 = undefined;
    var request_id: [32]u8 = undefined;
    const before: ?struct { time: u64, id: []const u8 } = if (model.next) |cursor| .{
        .time = cursor.time,
        .id = try std.fmt.bufPrint(&cursor_id, "{d}", .{cursor.id}),
    } else null;
    model.busy = true;
    try post(
        try std.fmt.bufPrint(&request_id, "similarity-{d}", .{model.generation}),
        "/console/api/events/similar",
        .{
            .source = try std.fmt.bufPrint(&source, "{d}", .{model.source}),
            .generation = model.generation,
            .before = before,
            .from = model.from,
            .until = model.until,
        },
    );
}

fn similarityEnvelope(value: std.json.Value, id: []const u8, alloc: std.mem.Allocator) !bool {
    const generation = try std.fmt.parseInt(u32, id["similarity-".len..], 10);
    if (state.phase != .similarity or generation != state.similarity.generation or
        !state.similarity.running) return true;
    const Envelope = struct {
        id: []const u8,
        status: i64,
        body: @import("similarity_state.zig").WirePart,
        browser_time: u64 = 0,
    };
    const parsed = @import("json_value.zig").decode(Envelope, value, alloc) catch {
        state.similarity.busy = false;
        state.similarity.running = false;
        setMessage("Could not read similarity results. Resume to retry this part.");
        return true;
    };
    state.browser_time = parsed.browser_time;
    try similarityResponse(parsed.status, parsed.body);
    return true;
}

fn similarityResponse(status: i64, part: @import("similarity_state.zig").WirePart) !void {
    const model = &state.similarity;
    model.busy = false;
    if (status == 401 or status == 403) {
        resetState(.login);
        setMessage("Your access changed. Sign in again to investigate incidents.");
        return command(.{ .op = "focus", .selector = "main h1", .top = true });
    }
    if (status == 429) {
        setMessage("Query allowance reached. Search resumes in one minute; you can pause it.");
        return command(.{ .op = "timer", .id = "similarity", .delay_ms = 60000 });
    }
    if (status != 200) {
        model.running = false;
        setMessage("Search interrupted. Partial results are retained; resume to retry.");
        return;
    }
    if (part.generation != model.generation) return error.InvalidResponse;
    model.accept(part) catch {
        model.running = false;
        setMessage("Invalid similarity response. Partial results are retained.");
        return;
    };
    model.received_at = state.browser_time;
    state.message = .{};
    if (model.running and !state.hidden) try command(.{
        .op = "timer",
        .id = "similarity",
        .delay_ms = 250,
    });
}

test "an incident address opens the prefix form drafted, never submitted" {
    sb_init();
    state.phase = .events;
    state.csrf = try p.Bytes(64).init("test");
    state.role = try p.Bytes(16).init("operator");
    const open = "{\"action\":\"events-deny-203.0.113.9\",\"browser_time\":200}";
    @memcpy(input[0..open.len], open);
    sb_event(1, open.len);
    try std.testing.expectEqual(.policies, state.phase);
    try std.testing.expectEqualStrings("203.0.113.9", state.reputation.draft_prefix.slice());
    try std.testing.expect(state.reputation.draft_deny);
    try std.testing.expect(!state.reputation.busy or state.reputation.kind == .query);
    state.kiosk = true;
    const allow = "{\"action\":\"events-allow-203.0.113.9\",\"browser_time\":200}";
    @memcpy(input[0..allow.len], allow);
    sb_event(1, allow.len);
    try std.testing.expect(state.reputation.draft_deny);
}

test "paused similarity rejects delayed parts and resumes with a fresh generation" {
    sb_init();
    state.phase = .events;
    state.csrf = try p.Bytes(64).init("test");
    state.events.until = 200;
    const start = "{\"action\":\"events-similar-9007199254740993\",\"browser_time\":200}";
    @memcpy(input[0..start.len], start);
    sb_event(1, start.len);
    try std.testing.expectEqual(.similarity, state.phase);
    const old_generation = state.similarity.generation;
    const pause = "{\"action\":\"similarity-pause\",\"browser_time\":200}";
    @memcpy(input[0..pause.len], pause);
    sb_event(1, pause.len);
    try std.testing.expect(!state.similarity.running);
    var id: [32]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&input);
    try std.json.Stringify.value(.{
        .id = try std.fmt.bufPrint(&id, "similarity-{d}", .{old_generation}),
        .status = 200,
        .body = .{ .generation = old_generation, .scanned = 64 },
    }, .{}, &writer);
    sb_event(2, writer.buffered().len);
    try std.testing.expectEqual(@as(u64, 0), state.similarity.scanned);
    const resume_search = "{\"action\":\"similarity-resume\",\"browser_time\":200}";
    @memcpy(input[0..resume_search.len], resume_search);
    sb_event(1, resume_search.len);
    try std.testing.expect(state.similarity.running and state.similarity.busy);
    try std.testing.expect(state.similarity.generation != old_generation);
}

test "inspecting a match preserves similarity results for return navigation" {
    sb_init();
    state.phase = .similarity;
    state.csrf = try p.Bytes(64).init("test");
    state.similarity = .{ .source = 1, .complete = true };
    state.similarity.best.add(.{ .id = 2, .distance = 0.1 });
    const inspect = "{\"action\":\"events-incident-2\",\"browser_time\":200}";
    @memcpy(input[0..inspect.len], inspect);
    sb_event(1, inspect.len);
    try std.testing.expectEqual(.events, state.phase);
    try std.testing.expectEqual(@as(u64, 2), state.events.incident);
    const back = "{\"action\":\"similarity-return\",\"browser_time\":200}";
    @memcpy(input[0..back.len], back);
    sb_event(1, back.len);
    try std.testing.expectEqual(.similarity, state.phase);
    try std.testing.expectEqual(@as(u8, 1), state.similarity.best.count);
    try std.testing.expect(state.similarity.complete);
}

test "policy navigation ignores superseded responses and retains a revision conflict" {
    sb_init();
    state = .{};
    state.csrf = try p.Bytes(64).init("test");
    begin();
    try std.testing.expect(try policy_controller.action(managed(), "policies", .null));
    try std.testing.expect(std.mem.indexOf(
        u8,
        command_writer.buffered(),
        "\"body\":{\"offset\":0}",
    ) != null);
    var old_buffer: [32]u8 = undefined;
    const old_id = try std.fmt.bufPrint(&old_buffer, "policies-{d}", .{policy_generation});
    state.phase = .events;
    try std.testing.expect(try policy_controller.action(managed(), "policies", .null));
    try policy_controller.response(managed(), old_id, 401, .null);
    try std.testing.expectEqual(.policies, state.phase);
    try std.testing.expect(state.policies.busy);
    var current_buffer: [32]u8 = undefined;
    const current_id = try std.fmt.bufPrint(
        &current_buffer,
        "policies-{d}",
        .{policy_generation},
    );
    try policy_controller.response(managed(), current_id, 409, .null);
    try std.testing.expect(!state.policies.busy and state.policies.stale);
    try std.testing.expect(std.mem.indexOf(u8, state.message.slice(), "changed") != null);
}

fn resetState(phase: @import("state.zig").Phase) void {
    const appearance = state.appearance;
    state.reset();
    state.phase = phase;
    state.appearance = appearance;
}

test "browser callbacks cannot read application state before explicit startup" {
    initialized = false;
    state = undefined;
    sb_event(1, 0);
    sb_geometry_loaded(0);
    try std.testing.expect(!initialized);
    sb_init();
    try std.testing.expect(initialized);
    try std.testing.expectEqual(.loading, state.phase);
    try std.testing.expectEqual(@as(usize, 0), state.csrf.len);
    try std.testing.expect(!state.policies.manager.active);
}

fn managed() @import("managed_controller.zig").Controller {
    return .{ .state = &state, .out = outbox(), .generation = &policy_generation };
}

test "successful sign-out erases retained management drafts and one-time credentials" {
    sb_init();
    state.phase = .policies;
    try state.csrf.set("test");
    try state.policies.body.set("private draft");
    try state.users.temporary.set("private one-time password");
    const reply = "{\"id\":\"logout\",\"status\":200,\"body\":{}}";
    @memcpy(input[0..reply.len], reply);
    sb_event(2, reply.len);
    try std.testing.expectEqual(.login, state.phase);
    try std.testing.expectEqual(@as(usize, 0), state.csrf.len);
    try std.testing.expect(std.mem.allEqual(u8, &state.policies.body.data, 0));
    try std.testing.expect(std.mem.allEqual(u8, &state.users.temporary.data, 0));
}

test "a bookmarked page dispatches only after the session completes authentication" {
    const t = std.testing;
    sb_init();
    const route = "{\"route\":\"nodes\"}";
    @memcpy(input[0..route.len], route);
    sb_event(8, route.len);
    try t.expectEqual(.loading, state.phase);
    const required =
        \\{"id":"login","status":200,"body":{"user":1,"csrf":"test","role":"admin",
        \\ "must_change":true}}
    ;
    @memcpy(input[0..required.len], required);
    sb_event(2, required.len);
    try t.expectEqual(.password, state.phase);
    try t.expect(std.mem.indexOf(u8, commands[0..commands_length], "connect") == null);
    try t.expect(std.mem.indexOf(u8, commands[0..commands_length], "/console/api/nodes") == null);
    const admitted =
        \\{"id":"password","status":200,"body":{"user":1,"csrf":"test","role":"admin",
        \\ "must_change":false}}
    ;
    @memcpy(input[0..admitted.len], admitted);
    sb_event(2, admitted.len);
    try t.expectEqual(.nodes, state.phase);
    try t.expect(std.mem.indexOf(u8, commands[0..commands_length], "/console/api/nodes") != null);
    try t.expect(std.mem.indexOf(u8, commands[0..commands_length], "\"replace\":true") != null);
}

fn accountSecurity() @import("account_security_controller.zig").Controller {
    return .{ .state = &state, .out = outbox() };
}
