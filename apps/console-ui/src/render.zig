const std = @import("std");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    if (state.phase == .challenges) return @import("challenges_page.zig").render(state, w);
    if (state.phase == .events) return @import("events_page.zig").render(state, w);
    if (state.phase == .security) return @import("security.zig").page(state, w);
    if (state.phase == .geoip) return @import("geoip_page.zig").render(state, w);
    if (state.phase != .dashboard) return authentication(state, w);
    try w.writeAll("<div class=\"sb-shell\">" ++
        "<nav class=\"sb-nav\" aria-label=\"Main navigation\">" ++
        "<div><a class=\"sb-brand\" href=\"/console/\">SIBUNA</a>" ++
        "<p class=\"sb-caption\">SECURITY CONSOLE</p></div>" ++
        "<button class=\"btn btn-ghost\" aria-current=\"page\">Statistics</button>" ++
        "<button class=\"btn btn-ghost\" data-action=\"events\">Events</button>" ++
        "<button class=\"btn btn-ghost\" data-action=\"challenges\">Challenges</button>" ++
        "<button class=\"btn btn-ghost\" data-action=\"geoip\">GeoIP</button>" ++
        "<button class=\"btn btn-ghost\" data-action=\"account\">Account</button>" ++
        "<button class=\"btn btn-ghost\" data-action=\"logout\">Sign out</button></nav>" ++
        "<main class=\"sb-main\"><header class=\"sb-header\"><div>" ++
        "<p class=\"sb-subtitle\">SINGLE NODE / STATISTICS</p>" ++
        "<h1 id=\"page-heading\" tabindex=\"-1\">Traffic overview</h1>" ++
        "<p class=\"sb-subtitle\">Know what is reaching your applications.</p></div>" ++
        "<div class=\"sb-status\"><span class=\"badge badge-outline\">");
    const status = if (state.paused) "Paused" else if (state.stale)
        "Disconnected"
    else if (state.stats == null) "Connecting" else "Live";
    try w.writeAll(status);
    try w.writeAll("</span><button class=\"btn btn-sm\" data-action=\"pause\">");
    try w.writeAll(if (state.paused) "Resume" else "Pause");
    try w.writeAll("</button><button class=\"btn btn-sm\" data-action=\"theme\">Theme</button>" ++
        "</div></header>");
    try message(state, w);
    if (state.stats != null and (state.stale or state.paused)) {
        try w.print("<p class=\"sb-note\" role=\"status\">Last update {d} seconds ago.</p>", .{
            state.browser_time -| state.received_at,
        });
    }
    try tiles(state, w);
    try w.writeAll("<section class=\"sb-panels\"><article class=\"sb-panel\">");
    try @import("globe.zig").render(state, w);
    try w.writeAll("</article><article class=\"sb-panel\"><h2>Request timeline</h2>");
    try timeline(state, w);
    try w.writeAll("<p class=\"sb-note\">External request outcomes per observed interval. " ++
        "Internal endpoints are excluded. Gaps remain unobserved.</p>" ++
        "<h2 class=\"mt-6\">Coverage</h2><table class=\"table\"><tbody>");
    try coverage(state, w);
    try w.writeAll("</tbody></table></article></section><footer class=\"sb-footer sb-note\">" ++
        "<span>Sibuna Console · single-node view</span>" ++
        "<span>All-time totals since this boot</span>" ++
        "</footer></main></div>");
}

fn authentication(state: *const State, w: *Writer) Writer.Error!void {
    try w.writeAll("<main class=\"sb-auth\"><section class=\"sb-auth-card\">" ++
        "<a class=\"sb-brand\" href=\"/console/\">SIBUNA</a>");
    const title = switch (state.phase) {
        .loading => "Connecting securely",
        .setup => "Initialize your console",
        .password => "Change your password",
        else => "Welcome back",
    };
    try w.print("<h1 id=\"page-heading\" tabindex=\"-1\">{s}</h1>", .{title});
    try w.writeAll("<p class=\"sb-subtitle\">Your firewall. Your infrastructure.</p>");
    try message(state, w);
    if (state.phase == .loading) {
        try w.writeAll("<p role=\"status\" class=\"mt-6\">Checking your session…</p>" ++
            "</section></main>");
        return;
    }
    if (state.phase == .setup) {
        try w.writeAll("<p class=\"mt-6\">Stop Sibuna and create the first administrator " ++
            "on the server:</p><code class=\"block mt-4 break-all\">" ++
            "sibuna init-admin admin --data-dir /path/to/data</code>" ++
            "<p class=\"sb-note mt-4\">Restart Sibuna, then sign in with the temporary " ++
            "password printed by the command. You must replace it before using the console.</p>" ++
            "<a class=\"btn btn-primary mt-6\" href=\"/console/\">Check again</a>" ++
            "</section></main>");
        return;
    }
    const form = switch (state.phase) {
        .password => "change-password",
        else => "login",
    };
    try w.print("<form id=\"{s}\">", .{form});
    try authenticationFields(state, w);
    try w.writeAll("<button class=\"btn btn-primary\" type=\"submit\"");
    if (state.busy) try w.writeAll(" disabled aria-busy=\"true\"");
    try w.print(
        "> {s}</button></form>",
        .{if (state.busy) "Please wait…" else switch (state.phase) {
            .password => "Update password",
            else => "Sign in",
        }},
    );
    if (state.phase == .password) try w.writeAll(
        "<button class=\"btn btn-ghost\" data-action=\"security\">" ++
            "Two-factor authentication</button>",
    );
    if (state.phase == .password and state.fullAccess()) {
        try w.writeAll("<button class=\"btn btn-ghost\" " ++
            "data-action=\"dashboard\">Back to dashboard</button>");
    }
    try w.writeAll("<p class=\"sb-note mt-6\">Protected with Argon2id and secure sessions.</p>" ++
        "</section></main>");
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
    try w.print(
        "<label for=\"{s}\">{s}</label><input class=\"input input-bordered\" " ++
            "id=\"{s}\" name=\"{s}\" type=\"{s}\" autocomplete=\"{s}\" required value=\"",
        .{ id, label, id, id, kind, autocomplete },
    );
    try escape(w, value);
    try w.writeAll("\">");
}

pub fn message(state: *const State, w: *Writer) Writer.Error!void {
    if (state.message.len == 0) return;
    try w.writeAll("<p class=\"sb-error\" role=\"status\">");
    try escape(w, state.message.slice());
    try w.writeAll("</p>");
}

fn tiles(state: *const State, w: *Writer) Writer.Error!void {
    try w.writeAll("<section class=\"sb-tiles\" aria-label=\"Request summary\">");
    const labels = [_][]const u8{
        "Requests", "Admitted", "Challenged", "Denied", "Origin 4xx", "Origin 5xx",
    };
    const keys = .{ "requests", "admitted", "challenged", "denied", "origin_4xx", "origin_5xx" };
    inline for (keys, labels) |key, label| {
        try w.print(
            "<article class=\"sb-tile\"><span class=\"sb-subtitle\">{s}</span><strong>",
            .{label},
        );
        if (state.stats) |stats| {
            try w.print("{d}", .{@field(stats, key)});
        } else try w.writeAll("—");
        try w.writeAll("</strong></article>");
    }
    try w.writeAll("</section>");
}

fn coverage(state: *const State, w: *Writer) Writer.Error!void {
    const stats = state.stats orelse {
        try w.writeAll("<tr><td>Waiting for a snapshot</td></tr>");
        return;
    };
    try w.print(
        "<tr><th>Unknown country samples / 60 s</th><td>{d}</td></tr>" ++
            "<tr><th>Sample probability</th><td>1/64</td></tr>" ++
            "<tr><th>Lost samples</th><td>{d}</td></tr>" ++
            "<tr><th>Recorded incidents</th><td>{d}</td></tr>" ++
            "<tr><th>Dropped incidents</th><td>{d}</td></tr>",
        .{ stats.unknown_samples, stats.sample_loss, stats.incidents, stats.incidents_dropped },
    );
}

fn timeline(state: *const State, w: *Writer) Writer.Error!void {
    try w.writeAll("<svg viewBox=\"0 0 480 180\" role=\"img\" aria-label=\"Request timeline\">" ++
        "<path d=\"M0 150H480 M0 100H480 M0 50H480\" fill=\"none\" stroke=\"#d7e3ee\"/>");
    if (state.stats) |stats| {
        var maximum: u64 = 1;
        for (state.points) |point| maximum = @max(maximum, point.count);
        for (0..60) |i| {
            const second = stats.timestamp -| (59 - i);
            const point = state.points[@intCast(second % 60)];
            if (point.second != second) continue;
            const height = @as(f64, @floatFromInt(point.count)) /
                @as(f64, @floatFromInt(maximum)) * 140;
            try w.print(
                "<rect x=\"{d}\" y=\"{d:.1}\" width=\"5\" height=\"{d:.1}\" " ++
                    "fill=\"#0284c7\"/>",
                .{ i * 8, 150 - height, height },
            );
        }
    }
    try w.writeAll("</svg>");
}

pub fn escape(w: *Writer, value: []const u8) Writer.Error!void {
    for (value) |byte| switch (byte) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        '"' => try w.writeAll("&quot;"),
        '\'' => try w.writeAll("&#39;"),
        else => try w.writeByte(byte),
    };
}

test "authentication renders no geographic or telemetry element and escapes input" {
    var state: State = .{ .phase = .login };
    state.username = try @import("console_protocol").Bytes(64).init("<script>\"");
    var buffer: [8192]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&state, &writer);
    const html = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, html, "<svg") == null);
    try std.testing.expect(std.mem.indexOf(u8, html, "world-110m") == null);
    try std.testing.expect(std.mem.indexOf(u8, html, "&lt;script&gt;&quot;") != null);
}
