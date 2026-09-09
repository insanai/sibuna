const html = @import("html");
const std = @import("std");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const shell = @import("shell.zig");
    if (state.kiosk and state.fullAccess()) return @import("kiosk_page.zig").render(state, w);
    const authenticated = state.fullAccess();
    if (authenticated) try shell.begin(state, w);
    try page(state, w);
    if (authenticated) try shell.end(w);
}

fn page(state: *const State, w: *Writer) Writer.Error!void {
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
        "<p class=\"sb-subtitle\">SINGLE NODE / STATISTICS</p>" ++
        "<h1 id=\"page-heading\" tabindex=\"-1\">Traffic overview</h1>" ++
        "<p class=\"sb-subtitle\">Know what is reaching your applications.</p></div>" ++
        "<div class=\"sb-status\"><span class=\"badge badge-outline\">", .{});
    const status = if (state.paused) "Paused" else if (state.stale)
        "Disconnected"
    else if (state.stats == null) "Connecting" else "Live";
    try w.writeAll(status);
    try html.render(w, "</span><button class=\"btn btn-sm\" data-action=\"pause\">", .{});
    try w.writeAll(if (state.paused) "Resume" else "Pause");
    try html.render(
        w,
        "</button><button class=\"btn btn-sm\" " ++
            "data-action=\"theme\">Theme</button>" ++
            "</div></header>",
        .{},
    );
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
    try tiles(state, w);
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
    try @import("rankings_panel.zig").render(
        &state.rankings,
        w,
        state.browser_time,
        state.paused or state.stale,
    );
    try html.render(w, "<footer class=\"sb-footer sb-note\">" ++
        "<span>Sibuna Console · single-node view</span>" ++
        "<span>All-time totals since this boot</span>" ++
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
    }
    if (state.phase == .login) try html.render(w, "</form><form id=\"kiosk-exchange\" " ++
        "class=\"mt-6\"><h2>Wall display</h2><p class=\"sb-note\">Paste the one-time code " ++
        "an operator minted. The display becomes read-only and shows statistics only.</p>" ++
        "<label for=\"kiosk-code\">Kiosk code</label><input id=\"kiosk-code\" name=\"code\" " ++
        "class=\"input input-bordered\" autocomplete=\"off\" maxlength=\"64\" " ++
        "pattern=\"[0-9a-f]{64}\" required><button class=\"btn\" type=\"submit\"{{ busy }}>" ++
        "Open wall display</button>", .{ .busy = if (state.busy) " disabled" else "" });
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
        if (state.phase == .login) "Password" else "New password (12+ characters)",
        "password",
        "",
        if (state.phase == .login) "current-password" else "new-password",
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
    try html.render(w, "<section class=\"sb-tiles\" aria-label=\"Request summary\">", .{});
    const labels = [_][]const u8{
        "Requests", "Admitted",   "Challenged", "Policy denied", "Banned", "Rate limited",
        "Other",    "Origin 4xx", "Origin 5xx",
    };
    const keys = .{
        "requests",   "admitted",   "challenged", "denied", "banned", "rate_limited", "other",
        "origin_4xx", "origin_5xx",
    };
    inline for (keys, labels) |key, label| {
        try html.render(
            w,
            "<article class=\"sb-tile\"><span class=\"sb-subtitle\">{{ v0 " ++
                "}}</span><strong>",
            .{
                .v0 = label,
            },
        );
        if (state.stats) |stats| {
            const separated = comptime std.mem.eql(u8, key, "denied") or
                std.mem.eql(u8, key, "banned") or std.mem.eql(u8, key, "rate_limited") or
                std.mem.eql(u8, key, "other");
            if (separated and stats.outcomes_version != 1)
                try w.writeAll("Not recorded")
            else
                try w.print("{d}", .{@field(stats, key)});
        } else try w.writeAll("—");
        try html.render(w, "</strong></article>", .{});
    }
    try html.render(w, "</section>", .{});
    try html.render(w, "<p class=\"sb-note\">Outcomes count parsed external requests once. " ++
        "Banned counts requests, not distinct addresses. Origin 4xx/5xx overlap admitted " ++
        "traffic. Counter loads are not simultaneous.</p>", .{});
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

fn timeline(state: *const State, w: *Writer) Writer.Error!void {
    try w.writeAll("<svg viewBox=\"0 0 480 180\" role=\"img\" aria-label=\"Request timeline\">" ++
        "<path d=\"M0 150H480 M0 100H480 M0 50H480\" fill=\"none\" stroke=\"#d7e3ee\"/>");
    if (state.stats) |stats| {
        var maximum: f64 = 1;
        for (state.points) |point| {
            if (point.second > stats.timestamp or stats.timestamp - point.second >= 60) continue;
            maximum = @max(maximum, @import("stats_series.zig").rate(point));
        }
        for (0..60) |i| {
            const second = stats.timestamp -| (59 - i);
            const point = state.points[@intCast(second % 60)];
            if (point.second != second or point.duration_ms == 0) continue;
            const height = @import("stats_series.zig").rate(point) / maximum * 140;
            try w.print(
                "<rect x=\"{d}\" y=\"{d:.1}\" width=\"5\" height=\"{d:.1}\" " ++
                    "fill=\"#0284c7\"/>",
                .{ i * 8, 150 - height, height },
            );
        }
    }
    try w.writeAll("</svg>");
}

pub const escape = @import("html").escape;

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

test "authenticated pages share one navigation landmark with the correct active section" {
    const phases = [_]@import("state.zig").Phase{
        .dashboard, .events, .similarity, .challenges, .geoip, .password, .security, .users,
        .tokens,    .audit,  .nodes,      .policies,
    };
    const actions = [_][]const u8{
        "dashboard", "events", "events", "challenges", "geoip", "account", "account", "users",
        "tokens",    "audit",  "nodes",  "policies",
    };
    for (phases, 0..) |phase, i| {
        var state: State = .{ .phase = phase };
        state.csrf = try @import("console_protocol").Bytes(64).init("test");
        try state.role.set("admin");
        var buffer: [32 * 1024]u8 = undefined;
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
