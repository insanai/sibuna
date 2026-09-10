const html = @import("html");
const std = @import("std");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const shell = @import("shell.zig");
    if (!state.fullAccess()) switch (state.phase) {
        .loading, .setup, .login, .password => {},
        .security => if (state.csrf.len == 0) return authentication(state, w),
        else => return authentication(state, w),
    };
    if (state.kiosk and state.fullAccess()) return @import("kiosk_page.zig").render(state, w);
    const authenticated = state.fullAccess();
    if (authenticated) try shell.begin(state, w);
    try page(state, w);
    if (authenticated) try shell.end(w);
}

fn page(state: *const State, w: *Writer) Writer.Error!void {
    if (state.phase == .security_overview)
        return @import("security_overview_page.zig").render(state, w);
    if (state.phase == .nodes) return @import("nodes_page.zig").render(state, w);
    if (state.phase == .settings) return @import("settings_page.zig").render(state, w);
    if (state.phase == .audit) return @import("audit_page.zig").render(state, w);
    if (state.phase == .tokens) return @import("tokens_page.zig").render(state, w);
    if (state.phase == .users) return @import("users_page.zig").render(state, w);
    if (state.phase == .policies) return @import("policies_page.zig").render(state, w);
    if (state.phase == .similarity) return @import("similarity_page.zig").render(state, w);
    if (state.phase == .challenges) return @import("challenges_page.zig").render(state, w);
    if (state.phase == .events) return @import("events_page.zig").render(state, w);
    if (state.phase == .security) return @import("security.zig").page(state, w);
    if (state.phase == .geoip) return @import("geoip_page.zig").render(state, w);
    if (state.phase != .dashboard) return authentication(state, w);
    try html.render(w, "<main class=\"sb-main\"><header class=\"sb-header\"><div>" ++
        "<p class=\"sb-subtitle\">TRAFFIC / STATISTICS</p>" ++
        "<h1 id=\"page-heading\" tabindex=\"-1\">Traffic overview</h1>" ++
        "<p class=\"sb-subtitle\">Know what is reaching your applications.</p></div>" ++
        "<div class=\"sb-status\"><span class=\"badge badge-outline\">", .{});
    try w.writeAll(@import("dashboard_scope.zig").status(state));
    try html.render(w, "</span><button class=\"btn btn-sm\" data-action=\"pause\">", .{});
    try w.writeAll(if (state.paused) "Resume" else "Pause");
    try html.render(
        w,
        "</button><button class=\"btn btn-sm\" " ++
            "data-action=\"theme\">Theme</button>" ++
            "</div></header>",
        .{},
    );
    try @import("statistics_tabs.zig").render(false, w);
    try message(state, w);
    if (state.stats != null and (state.stale or state.paused)) {
        try html.render(
            w,
            "<p class=\"sb-note\" role=\"status\">Last update {{ v0 }} " ++
                "seconds ago.</p>",
            .{
                .v0 = state.browser_time -| state.received_at,
            },
        );
    }
    try @import("dashboard_scope.zig").render(state, w);
    try @import("traffic_period_page.zig").controls(state, w);
    try tiles(state, w);
    try @import("comparison_page.zig").render(state, w);
    try html.render(w, "<section class=\"sb-panels\"><article class=\"sb-panel\">", .{});
    try @import("globe.zig").render(state, w);
    try html.render(w, "</article><article class=\"sb-panel\"><h2>Request timeline</h2>", .{});
    try timeline(state, w);
    try html.render(w, "<p class=\"sb-note\">External requests per second, using observed " ++
        "monotonic elapsed time. Restarts, clock changes and gaps remain unobserved.</p>", .{});
    try @import("timeline_panel.zig").table(state, w);
    try html.render(w, "<h2 class=\"mt-6\">Coverage</h2><table class=\"table\"><tbody>", .{});
    try coverage(state, w);
    try html.render(w, "</tbody></table></article></section>", .{});
    try @import("rankings_controller.zig").render(state, w);
    try @import("ranking_history_page.zig").render(state, w);
    try html.render(w, "<footer class=\"sb-footer sb-note\">" ++
        "<span>Sibuna Console · selected live view</span>" ++
        "<span>Each panel states its observation window</span>" ++
        "</footer></main>", .{});
}

fn authentication(state: *const State, w: *Writer) Writer.Error!void {
    try html.render(w, "<main class=\"sb-auth\"><section class=\"sb-auth-card\">" ++
        "<a class=\"sb-brand\" href=\"/console/\">SIBUNA</a>", .{});
    const title = switch (state.phase) {
        .loading => "Connecting securely",
        .setup => "Initialize your console",
        .password => "Change your password",
        else => "Welcome back",
    };
    try html.render(w, "<h1 id=\"page-heading\" tabindex=\"-1\">{{ v0 }}</h1>", .{
        .v0 = title,
    });
    try html.render(w, "<p class=\"sb-subtitle\">Your firewall. Your infrastructure.</p>", .{});
    try message(state, w);
    if (state.phase == .loading) {
        try html.render(w, "<p role=\"status\" class=\"mt-6\">Checking your session…</p>" ++
            "</section></main>", .{});
        return;
    }
    if (state.phase == .setup) {
        try html.render(w, "<p class=\"mt-6\">Stop Sibuna and create the first administrator " ++
            "on the server:</p><code class=\"block mt-4 break-all\">" ++
            "sibuna init-admin admin --data-dir /path/to/data</code>" ++
            "<p class=\"sb-note mt-4\">Restart Sibuna, then sign in with the temporary " ++
            "password printed by the command. You must replace it before using the console.</p>" ++
            "<a class=\"btn btn-primary mt-6\" href=\"/console/\">Check again</a>" ++
            "</section></main>", .{});
        return;
    }
    const form = switch (state.phase) {
        .password => "change-password",
        else => "login",
    };
    try html.render(w, "<form id=\"{{ v0 }}\">", .{
        .v0 = form,
    });
    try authenticationFields(state, w);
    try html.render(w, "<button class=\"btn btn-primary\" type=\"submit\"", .{});
    if (state.busy) try w.writeAll(" disabled aria-busy=\"true\"");
    try html.render(w, "> {{ v0 }}</button></form>", .{
        .v0 = if (state.busy) "Please wait…" else switch (state.phase) {
            .password => "Update password",
            else => "Sign in",
        },
    });
    if (state.phase == .password) try w.writeAll(
        "<button class=\"btn btn-ghost\" data-action=\"security\">" ++
            "Two-factor authentication</button>",
    );
    if (state.phase == .password and state.fullAccess()) {
        try html.render(w, "<button class=\"btn btn-ghost\" " ++
            "data-action=\"dashboard\">Back to dashboard</button>", .{});
        try @import("kiosk_grant.zig").render(state, w);
    }
    if (state.phase == .login) try html.render(w, "<form id=\"kiosk-exchange\" " ++
        "class=\"mt-6\"><h2>Wall display</h2><p class=\"sb-note\">Paste the one-time code " ++
        "an operator minted. The display becomes read-only and shows statistics only.</p>" ++
        "<label for=\"kiosk-code\">Kiosk code</label><input id=\"kiosk-code\" name=\"code\" " ++
        "class=\"input input-bordered\" autocomplete=\"off\" maxlength=\"64\" " ++
        "pattern=\"[0-9a-f]{64}\" required><button class=\"btn\" type=\"submit\"{{ busy }}>" ++
        "Open wall display</button></form>", .{ .busy = if (state.busy) " disabled" else "" });
    try html.render(
        w,
        "<p class=\"sb-note mt-6\">Protected with Argon2id and secure " ++
            "sessions.</p>" ++
            "</section></main>",
        .{},
    );
}

pub fn tilesPublic(state: *const State, w: *Writer) Writer.Error!void {
    return tiles(state, w);
}

pub fn messagePublic(state: *const State, w: *Writer) Writer.Error!void {
    return message(state, w);
}

fn authenticationFields(state: *const State, w: *Writer) Writer.Error!void {
    if (state.phase != .password) {
        try field(
            w,
            "username",
            "Username",
            "text",
            state.username.slice(),
            "username",
        );
    } else try field(
        w,
        "old_password",
        "Current password",
        "password",
        "",
        "current-password",
    );
    try field(
        w,
        "password",
        if (state.phase == .password) "New password (12+ characters)" else "Password",
        "password",
        "",
        if (state.phase == .password) "new-password" else "current-password",
    );
    if (state.phase == .login) try w.writeAll(
        "<label for=\"code\">Authenticator or recovery code (if enabled)</label>" ++
            "<input class=\"input input-bordered\" id=\"code\" name=\"code\" " ++
            "autocomplete=\"one-time-code\" maxlength=\"32\">",
    );
}

pub fn field(
    w: *Writer,
    id: []const u8,
    label: []const u8,
    kind: []const u8,
    value: []const u8,
    autocomplete: []const u8,
) Writer.Error!void {
    try html.render(w, @embedFile("snippets/field.html"), .{
        .id = id,
        .label = label,
        .kind = kind,
        .value = value,
        .autocomplete = autocomplete,
    });
}

pub fn message(state: *const State, w: *Writer) Writer.Error!void {
    if (state.message.len == 0) return;
    try html.render(w, @embedFile("snippets/message.html"), .{
        .message = state.message.slice(),
        .tone = if (state.message_success) "alert alert-success mb-4" else "sb-error",
    });
}

fn tiles(state: *const State, w: *Writer) Writer.Error!void {
    return @import("traffic_tiles.zig").render(state, w);
}

fn coverage(state: *const State, w: *Writer) Writer.Error!void {
    const stats = state.stats orelse {
        try html.render(w, "<tr><td>Waiting for a snapshot</td></tr>", .{});
        return;
    };
    try html.render(w, "<tr><th>Unknown country samples / 60 s</th><td>{{ v0 }}</td></tr>" ++
        "<tr><th>Sample probability</th><td>1/64</td></tr>" ++
        "<tr><th>Lost samples</th><td>{{ v1 }}</td></tr>" ++
        "<tr><th>Recorded incidents</th><td>{{ v2 }}</td></tr>" ++
        "<tr><th>Dropped incidents</th><td>{{ v3 }}</td></tr>", .{
        .v0 = stats.unknown_samples,
        .v1 = stats.sample_loss,
        .v2 = stats.incidents,
        .v3 = stats.incidents_dropped,
    });
    if (stats.outcomes_version == 1) try html.render(
        w,
        "<tr><th>Expired samples discarded</th><td>{{ v0 }}</td></tr>" ++
            "<tr><th>Future-dated samples discarded</th><td>{{ v1 }}</td></tr>" ++
            "<tr><th>GeoIP cleanup attempts failed or unconfirmed</th><td>{{ v2 }}</td></tr>",
        .{
            .v0 = stats.expired_samples,
            .v1 = stats.future_samples,
            .v2 = stats.geo_maintenance_failures,
        },
    );
    if (stats.retention_failures) |failures| try html.render(
        w,
        "<tr><th>Retention attempts failed or unconfirmed</th><td>{{ v0 " ++
            "}}</td></tr>",
        .{
            .v0 = failures,
        },
    );
    const minutes = stats.minute_history;
    if (minutes.available) try html.render(
        w,
        "<tr><th>Minute snapshots confirmed / unconfirmed</th><td>{{ v0 " ++
            "}} / {{ v1 }}</td></tr>" ++
            "<tr><th>Minute snapshots pending</th><td>{{ v2 }}</td></tr>" ++
            "<tr><th>Minute retention attempts failed or unconfirmed</th><td>{{ v3 }}</td></tr>",
        .{
            .v0 = minutes.saved_snapshots,
            .v1 = minutes.unconfirmed_snapshots,
            .v2 = minutes.pending,
            .v3 = minutes.retention_failures,
        },
    );
}

const series = @import("stats_series.zig");
const sparkline = @import("outcome_sparkline.zig");
const outcomes = [_]sparkline.Metric{
    .admitted, .challenged, .denied, .banned, .rate_limited, .other,
};

pub fn timeline(state: *const State, w: *Writer) Writer.Error!void {
    try w.writeAll(
        "<svg viewBox=\"0 0 480 180\" role=\"img\" aria-label=\"Request timeline\">" ++
            "<path d=\"M0 150H480 M0 100H480 M0 50H480\" fill=\"none\" stroke=\"#d7e3ee\"/>",
    );
    if (state.stats) |stats| {
        var maximum: f64 = 1;
        for (state.points) |point| {
            if (point.second > stats.timestamp or stats.timestamp - point.second >= 60) continue;
            maximum = @max(maximum, series.rate(point));
        }
        for (0..60) |i| {
            const second = stats.timestamp -| (59 - i);
            const point = state.points[@intCast(second % 60)];
            if (point.second != second or point.duration_ms == 0) continue;
            try bar(w, i * 8, point, maximum);
        }
    }
    try w.writeAll("</svg><p class=\"sb-note\">Stacked by outcome:");
    for (outcomes) |key| try html.render(w, " <span class=\"sb-legend {{ tone }}\">" ++
        "{{ label }}</span>", .{ .tone = sparkline.tone(key), .label = sparkline.name(key) });
    try w.writeAll(".</p>");
}

/// Disjoint outcomes stack from the baseline in decision colours (R8); an interval
/// without an outcome split draws its combined rate in the informational tone.
fn bar(w: *Writer, x: usize, point: series.Point, maximum: f64) Writer.Error!void {
    const rates = point.outcome_rates orelse {
        const height = series.rate(point) / maximum * 140;
        return segment(w, x, 150 - height, height, sparkline.tone(.requests));
    };
    var top: f64 = 150;
    for (outcomes) |key| {
        const rate = switch (key) {
            inline else => |tag| @field(rates, @tagName(tag)),
        };
        const height = rate / maximum * 140;
        if (!(height > 0)) continue;
        top -= height;
        try segment(w, x, top, height, sparkline.tone(key));
    }
}

fn segment(w: *Writer, x: usize, y: f64, height: f64, tone: []const u8) Writer.Error!void {
    try w.print(
        "<rect class=\"sb-outcome-chart {s}\" x=\"{d}\" y=\"{d:.1}\" width=\"5\" " ++
            "height=\"{d:.1}\" fill=\"currentColor\"/>",
        .{ tone, x, y, height },
    );
}

pub const escape = @import("html").escape;

test "forward auth and older snapshots never present unobserved origin errors as zero" {
    const t = std.testing;
    const state = try t.allocator.create(State);
    defer t.allocator.destroy(state);
    state.* = .{ .phase = .dashboard };
    state.stats = std.mem.zeroes(@import("console_protocol").StatsSnapshot);
    state.traffic_period.hours = 0;
    state.stats.?.origin_4xx = 4;
    state.stats.?.origin_5xx = 9;
    var buffer: [8192]u8 = undefined;
    for ([_]?@import("console_protocol").ProxyMode{ .forward_auth, null, .reverse_proxy }) |mode| {
        state.stats.?.proxy_mode = mode;
        var writer: Writer = .fixed(&buffer);
        try tiles(state, &writer);
        const output = writer.buffered();
        const missing: usize = if (mode == .reverse_proxy) 0 else 2;
        try t.expectEqual(missing, std.mem.count(u8, output, "Not observed"));
        if (mode == .forward_auth)
            try t.expect(std.mem.indexOf(u8, output, "authorization approvals") != null);
    }
}

test "authentication renders no geographic or telemetry element and escapes input" {
    var state: State = .{ .phase = .login };
    state.username = try @import("console_protocol").Bytes(64).init("<script>\"");
    var buffer: [8192]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&state, &writer);
    const output_html = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output_html, "<svg") == null);
    try std.testing.expect(std.mem.indexOf(u8, output_html, "world-110m") == null);
    try std.testing.expect(std.mem.indexOf(u8, output_html, "&lt;script&gt;&quot;") != null);
}

test "the renderer gates retained management state when authentication is no longer complete" {
    const t = std.testing;
    var state: State = .{ .phase = .security_overview };
    state.security_overview.categories[0] = .{
        .label = try @import("console_protocol").Bytes(96).init("private finding"),
    };
    state.security_overview.loaded = @splat(true);
    var buffer: [8192]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&state, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "private finding") == null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "<svg") == null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "Welcome back") != null);
}

test "authenticated pages share one navigation landmark with the correct active section" {
    const phases = [_]@import("state.zig").Phase{
        .dashboard,         .events, .similarity, .challenges, .geoip, .password,
        .security,          .users,  .tokens,     .audit,      .nodes, .policies,
        .security_overview,
    };
    const actions = [_][]const u8{
        "dashboard", "events", "events", "challenges", "geoip",     "account", "account", "users",
        "tokens",    "audit",  "nodes",  "policies",   "dashboard",
    };
    for (phases, 0..) |phase, i| {
        var state: State = .{ .phase = phase };
        state.csrf = try @import("console_protocol").Bytes(64).init("test");
        try state.role.set("admin");
        var buffer: [64 * 1024]u8 = undefined;
        var writer: Writer = .fixed(&buffer);
        try render(&state, &writer);
        const output = writer.buffered();
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output, "<nav "));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, output, "<main "));
        const active = actions[i];
        var expected_buffer: [128]u8 = undefined;
        const expected = try std.fmt.bufPrint(
            &expected_buffer,
            "data-action=\"{s}\"\n            aria-current=\"page\"",
            .{active},
        );
        try std.testing.expect(std.mem.indexOf(u8, output, expected) != null);
        state.must_change = true;
        writer = .fixed(&buffer);
        try render(&state, &writer);
        try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "<nav ") == null);
    }
}
