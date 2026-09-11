//! Reviewed full-page output from the native renderer. The browser patches these same
//! trees; fixtures freeze time and contain no live credentials or collected evidence.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Phase = @import("state.zig").Phase;

test "reviewed native page and authentication-state HTML" {
    const update = try std.testing.environ.containsUnempty(
        std.testing.allocator,
        "SIBUNA_UPDATE_CONSOLE_GOLDENS",
    );
    try run(std.testing.io, std.testing.allocator, update);
}

fn run(io: std.Io, alloc: std.mem.Allocator, update: bool) !void {
    var state: State = .{};
    for (std.enums.values(Phase)) |phase| {
        configure(&state, phase);
        try check(io, alloc, @tagName(phase), &state, update);
    }
    const variants = .{
        "traffic-live",
        "traffic-stale",
        "traffic-comparison",
        "kiosk-traffic",
        "kiosk-security",
        "required-password",
        "required-totp",
        "security-recorded",
        "kiosk-security-recorded",
        "traffic-period",
        "traffic-period-partial",
        "ranking-history",
        "rule-hit-history",
        "rule-hit-history-partial",
        "audit-detail",
    };
    inline for (variants, 0..) |name, i| {
        configure(&state, .dashboard);
        state.stats = std.mem.zeroes(p.StatsSnapshot);
        state.stats.?.node = 1;
        state.stats.?.timestamp = 172800;
        state.stats.?.requests = 12345;
        state.stats.?.admitted = 12345;
        state.stats.?.outcomes_version = 1;
        state.stats.?.proxy_mode = .reverse_proxy;
        state.stats.?.active_bans = 12;
        state.stats.?.cluster_health = .{ .healthy = 2, .unknown = 1 };
        state.points[0] = .{
            .second = 172800,
            .outcome_rates = .{ .admitted = 3 },
            .active_bans = 12,
            .nodes_healthy = 2,
        };
        variant(&state, i);
        try check(io, alloc, name, &state, update);
    }
}

fn configure(state: *State, phase: Phase) void {
    state.reset();
    state.phase = phase;
    state.browser_time = 172800;
    state.received_at = 172799;
    switch (phase) {
        .loading, .setup, .login, .password => {},
        else => {
            state.csrf.set("fixture-only-csrf") catch unreachable;
            state.console_node = 1;
            state.role.set("admin") catch unreachable;
        },
    }
}

/// An opened policy record with the revert confirmation shown (R18: typed confirmation).
fn auditDetail(state: *State) void {
    state.phase = .audit;
    const model = &state.audit;
    model.clear();
    model.loaded = true;
    model.count = 1;
    model.since = 0;
    model.until = 172800;
    model.rows[0] = .{
        .id = 41,
        .actor = 1,
        .subject = 18,
        .recorded_at = 172700,
        .actor_role = .admin,
        .client_ip = p.Bytes(48).init("198.51.100.7") catch unreachable,
    };
    model.rows[0].action.set("policy.edit") catch unreachable;
    model.rows[0].target = p.Bytes(128).init("api-rate") catch unreachable;
    model.selected = 41;
    model.detail = .{ .row = model.rows[0], .after_redacted = true };
    model.detail.before = p.Bytes(1024).init("{\"action\":\"allow\"}") catch unreachable;
    model.detail.after = p.Bytes(1024).init("{\"action\":\"deny\"}") catch unreachable;
    model.has_detail = true;
    model.revert_open = true;
}

fn variant(state: *State, index: usize) void {
    switch (index) {
        0 => state.traffic_period.hours = 0,
        1 => {
            state.traffic_period.hours = 0;
            state.stale = true;
            state.received_at = 172770;
        },
        2 => {
            state.comparison = .{ .open = true, .started = true };
            for (&state.comparison.windows, 0..) |*window, i| window.* = .{
                .node = 1,
                .from = if (i == 0) 2875 else 1435,
                .until = if (i == 0) 2879 else 1439,
                .rows = 5,
                .complete_rows = 5,
                .observed_ms = 300000,
                .finished = true,
                .counts = .{ .admitted = if (i == 0) 1200 else 1000 },
            };
        },
        9, 10 => period(state, index == 10),
        12, 13 => ruleHistory(state, index == 13),
        14 => auditDetail(state),
        3, 4 => {
            state.kiosk = true;
            state.kiosk_expires = 176400;
            if (index == 4) state.phase = .security_overview;
        },
        5 => {
            state.phase = .password;
            state.must_change = true;
        },
        6 => {
            state.phase = .security;
            state.totp_required = true;
        },
        7, 8 => {
            state.phase = .security_overview;
            state.kiosk = index == 8;
            state.kiosk_expires = 176400;
            state.security_overview.loaded[0] = true;
            state.security_overview.observed_at[0] = state.browser_time - 1;
            state.security_overview.request = .{ .from = 169200, .until = 172800 };
            state.security_overview.modules[0].trend[0] = 1234;
            state.security_overview.modules[0].total = 1234;
        },
        11 => {
            state.ranking_history = .{ .open = true, .started = true };
            for (&state.ranking_history.windows, 0..) |*window, side| {
                window.query = .{
                    .from_minute = 2800 - side * 60,
                    .until_minute = 2859 - side * 60,
                    .node = 1,
                };
                window.finished = true;
                window.archives = 1;
                window.summary.add("/search?<&>") catch unreachable;
            }
        },
        else => {},
    }
}

fn ruleHistory(state: *State, partial: bool) void {
    state.phase = .policies;
    const model = &state.rule_history;
    model.open = true;
    model.started = true;
    model.inputs.key.set("m:operator-rule") catch unreachable;
    model.inputs.node = 1;
    model.inputs.minutes = 5;
    for (&model.windows, 0..) |*window, side| {
        const from: u64 = 2870 + side * 5;
        window.* = .{ .request = .{
            .key = model.inputs.key,
            .node = 1,
            .from_minute = from,
            .until_minute = from + 4,
        }, .retention_days = 90, .finished = true };
        for (0..5) |offset| {
            const minute = from + 4 - offset;
            window.add(.{ .hits = if (side == 0) 100 else 125, .span = .{
                .node = 1,
                .boot = @splat(1),
                .sequence = minute,
                .generation = side + 1,
                .revision = side + 1,
                .minute = minute,
                .utc_start = minute * 60 - 1,
                .utc_end = minute * 60 + 59,
                .start_ms = minute * 60000 - 1000,
                .end_ms = minute * 60000 + 59000,
                .observed_ms = 60000,
                .observations = 60,
                .complete = !partial,
                .gap = partial,
            } }) catch unreachable;
        }
    }
}

fn check(
    io: std.Io,
    alloc: std.mem.Allocator,
    name: []const u8,
    state: *const State,
    update: bool,
) !void {
    var buffer: [512 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try @import("render.zig").render(state, &writer);
    try principles(name, writer.buffered());
    var path_buffer: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "apps/console-ui/golden/{s}.html", .{name});
    if (update) return std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = writer.buffered(),
    });
    const expected = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(buffer.len));
    defer alloc.free(expected);
    if (!std.mem.eql(u8, expected, writer.buffered())) {
        std.log.err(
            "console golden changed: {s}; review `zig build console-golden -- --update`",
            .{path},
        );
        return error.GoldenMismatch;
    }
}

fn period(state: *State, partial: bool) void {
    state.stats.?.minute_history.available = true;
    const model = &state.traffic_period;
    model.configure(&.{1}, 2879) catch unreachable;
    for (&model.windows[0], 0..) |*window, side| {
        window.rows = 1440;
        window.complete_rows = 1440;
        window.observed_ms = 86400000;
        window.finished = true;
        window.counts.admitted = if (side == 0) 12345 else 8230;
    }
    if (partial) model.windows[0][1].complete_rows -= 1;
    model.published = .{
        .totals = .{ model.totals(0) catch unreachable, model.totals(1) catch unreachable },
        .until = model.until,
        .completed_at = state.browser_time - 1,
    };
    model.completed_at = state.browser_time - 1;
}

/// The mechanical half of the principle audit: rules a renderer can violate silently.
/// Judgement rules (R1, R5, R7) remain a human review of the same reviewed HTML.
fn principles(name: []const u8, html: []const u8) !void {
    const t = std.testing;
    const count = std.mem.count;
    const has = struct {
        fn f(haystack: []const u8, needle: []const u8) bool {
            return std.mem.indexOf(u8, haystack, needle) != null;
        }
    }.f;
    errdefer std.log.err("principle check failed for {s}", .{name});
    // R2 trunk test: product, node, page heading, active section and the way back are
    // present on every authenticated page.
    if (has(html, "<nav ")) {
        try t.expect(has(html, "SIBUNA"));
        try t.expect(has(html, "Console node ") or has(html, "Node not reported"));
        try t.expect(has(html, "id=\"page-heading\""));
        try t.expect(has(html, "aria-current=\"page\""));
        try t.expect(has(html, "href=\"/console/\""));
    }
    // R8: decision colours reach markup only through the semantic classes; series never
    // carry literal fills.
    try t.expectEqual(@as(usize, 0), count(u8, html, "fill=\"#"));
    var rest = html;
    while (std.mem.indexOf(u8, rest, "sb-decision-")) |index| {
        rest = rest[index + "sb-decision-".len ..];
        const names = [_][]const u8{ "admitted", "challenged", "denied", "banned", "info" };
        var known = false;
        for (names) |tone| known = known or std.mem.startsWith(u8, rest, tone);
        try t.expect(known);
    }
    // R9 and R11: every traffic tile carries a sparkline, and a retained window carries a
    // deviation marker per tile.
    const traffic = [_][]const u8{ "dashboard", "traffic-period", "traffic-comparison" };
    for (traffic) |traffic_name| if (std.mem.eql(u8, name, traffic_name)) {
        const tiles = count(u8, html, "<article class=\"sb-tile ");
        try t.expectEqual(@as(usize, 11), tiles);
        try t.expectEqual(tiles, count(u8, html, "class=\"sb-sparkline\""));
        try t.expectEqual(tiles, count(u8, html, "<p class=\"sb-note\">Yesterday: "));
    };
    if (std.mem.eql(u8, name, "traffic-live")) {
        try t.expectEqual(@as(usize, 11), count(u8, html, "class=\"sb-sparkline\""));
        // R12: counts render with thousands separators.
        try t.expect(has(html, "12,345"));
    }
    // R18: permanent deletion needs an explicit acknowledgement per retention window.
    if (std.mem.eql(u8, name, "settings"))
        try t.expectEqual(@as(usize, 4), count(u8, html, "name=\"confirmed\" required"));
}
