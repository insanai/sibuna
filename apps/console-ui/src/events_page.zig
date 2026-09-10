const html = @import("html");
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const escape = @import("render.zig").escape;
const Model = @import("events_state.zig").Model;
const Writer = std.Io.Writer;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.events;
    try html.render(w, "<main class=\"sb-main min-h-screen\"><header class=\"sb-header\"><div>" ++
        "<p class=\"sb-subtitle\">INVESTIGATION / RECORDED INCIDENTS</p>" ++
        "<h1 id=\"page-heading\" tabindex=\"-1\">Events</h1>" ++
        "<p class=\"sb-subtitle\">Inspect what your firewall recorded.</p></div>" ++
        "<button class=\"btn\" data-action=\"dashboard\">Back to " ++
        "dashboard</button></header>", .{});
    if (state.message.len != 0) {
        try html.render(w, "<p class=\"{{ v0 }}\" role=\"status\">", .{
            .v0 = if (model.export_ready) "sb-note" else "sb-error",
        });
        try escape(w, state.message.slice());
        try html.render(w, "</p>", .{});
    }
    try html.render(
        w,
        "<div class=\"flex flex-wrap gap-3 mt-6\" aria-label=\"Incident " ++
            "view\">",
        .{},
    );
    try button(w, "events-raw", "Raw incidents", model.busy or !model.grouped);
    try button(w, "events-source", "By source address", model.busy or model.grouped);
    try html.render(w, "</div>", .{});
    if (model.incident != 0) {
        try html.render(w, "<p class=\"sb-note mt-4\">Incident #{{ v0 }}</p>", .{
            .v0 = model.incident,
        });
        try button(w, "events-clear-incident", "Clear incident filter", model.busy);
        if (state.similarity.source != 0)
            try button(w, "similarity-return", "Back to similarity results", model.busy);
    }
    if (model.campaign != 0) {
        try html.render(w, "<p class=\"sb-note mt-4\">Campaign candidate #{{ v0 }}. " ++
            "Automated similarity grouping is not attribution or proof of a common attacker. " ++
            "Membership uses the selected time range.</p>", .{
            .v0 = model.campaign,
        });
        try button(w, "events-clear-campaign", "Clear campaign filter", model.busy);
    }
    try @import("live_status.zig").render(state, .events, w);
    try filters(model, w);
    try html.render(w, "<section id=\"incident-results\" tabindex=\"-1\" " ++
        "class=\"sb-panel mt-6\" aria-label=\"Incident results\">", .{});
    if (model.busy) try html.render(w, "<p role=\"status\">Loading incidents…</p>", .{});
    if (!model.busy and model.loaded and model.count == 0)
        try html.render(w, "<p>No recorded incidents match these filters.</p>", .{});
    for (model.rows[0..model.count]) |*row| try incident(row, w);
    try footer(model, w);
}

fn footer(model: *const Model, w: *Writer) Writer.Error!void {
    try html.render(w, "<div class=\"flex flex-wrap gap-3 mt-6\"><span>Page {{ v0 }}</span>", .{
        .v0 = model.page + 1,
    });
    try button(w, "events-prev", "Previous", model.busy or model.page == 0);
    try button(w, "events-next", "Next", model.busy or model.next == null or
        model.page + 1 == model.cursors.len);
    try button(w, "events-refresh", "Latest results", model.busy);
    const export_disabled = model.busy or model.exporting or model.count == 0;
    try button(w, "events-export", "Export this page (JSON)", export_disabled);
    try button(w, "events-export-csv", "Export this page (CSV)", export_disabled);
    if (model.page + 1 == model.cursors.len and model.next != null)
        try html.render(w, "<p>Narrow the time range or filters to browse more records.</p>", .{});
    try html.render(
        w,
        "</div><p class=\"sb-note mt-4\">Records are ordered by capture " ++
            "time (UTC). " ++
            "Pages retain the selected time boundary; " ++
            "use Latest results to include new incidents. " ++
            "Missing historical evidence and capture coverage are not inferred.</p>" ++
            "<p class=\"sb-note\">CSV prefixes formula-like text with “Text: ”. " ++
            "JSON preserves string values and exact identifiers.</p></section></main>",
        .{},
    );
}

fn filters(model: *const Model, w: *Writer) Writer.Error!void {
    try html.render(w, "<section class=\"sb-panel mt-6\"><h2>Filter incidents</h2>" ++
        "<form id=\"events-filter\" class=\"grid gap-3 sm:grid-cols-2 lg:grid-cols-6\">", .{});
    try @import("security_investigation.zig").filter(model, w);
    try input(w, "category", "Category (exact)", model.category.slice(), 32);
    try input(w, "country", "Country code, unknown or not_recorded", model.country.slice(), 12);
    try input(w, "ip", "Client address (exact)", model.ip.slice(), 48);
    try input(w, "path_prefix", "Path starts with", model.path.slice(), 256);
    var node: [10]u8 = undefined;
    const node_text = switch (model.node) {
        0 => "",
        else => std.fmt.bufPrint(&node, "{d}", .{model.node}) catch unreachable,
    };
    try input(w, "node", "Node ID (optional)", node_text, 10);
    try html.render(
        w,
        "<div class=\"grid gap-2 min-w-0\"><label for=\"hours\">Time " ++
            "range</label>" ++
            "<select id=\"hours\" name=\"hours\" class=\"select select-bordered w-full\">",
        .{},
    );
    inline for (.{
        .{ 0, "All recorded time" },
        .{ 1, "Last hour" },
        .{ 24, "Last 24 hours" },
        .{ 168, "Last 7 days" },
        .{ 720, "Last 30 days" },
    }) |option| {
        try html.render(w, "<option value=\"{{ v0 }}\"{{ v1 }}>{{ v2 }}</option>", .{
            .v0 = option[0],
            .v1 = if (model.hours == option[0]) " selected" else "",
            .v2 = option[1],
        });
    }
    try html.render(w, "</select></div><button type=\"submit\" " ++
        "class=\"btn btn-primary self-end sm:col-span-2 lg:col-span-1\"", .{});
    if (model.busy) try w.writeAll(" disabled");
    try html.render(w, ">Apply filters</button></form></section>", .{});
}

fn incident(row: *const p.events.Row, w: *Writer) Writer.Error!void {
    if (row.grouped) return source(row, w);
    try html.render(w, "<article class=\"border-b border-base-300 py-4\"><h2>", .{});
    try escape(w, row.category.slice());
    try html.render(w, " <span class=\"sb-note\">#{{ v0 }}</span></h2><p>", .{
        .v0 = row.id,
    });
    try timestamp(w, row.time);
    try html.render(w, " · Node {{ v0 }}</p><p class=\"break-all\">", .{
        .v0 = row.node,
    });
    try escape(w, row.ip.slice());
    try w.writeAll(" · ");
    try escape(w, row.method.slice());
    try w.writeAll(" ");
    try escape(w, row.path.slice());
    try html.render(w, "</p><details class=\"mt-3\"><summary>Incident details</summary>" ++
        "<dl class=\"grid gap-2 mt-3\"><dt>User agent</dt><dd class=\"break-all\">", .{});
    try escape(w, row.user_agent.slice());
    try html.render(w, "</dd><dt>Campaign candidate</dt><dd>", .{});
    if (row.campaign) |id| {
        try html.render(w, "{{ v0 }} (automated similarity grouping) " ++
            "<button class=\"btn btn-sm\" data-action=\"events-campaign-{{ v1 }}\">" ++
            "Inspect candidate</button>", .{
            .v0 = id,
            .v1 = id,
        });
    } else try w.writeAll("Not recorded");
    try html.render(w, "</dd><dt>Country at persistence</dt><dd>", .{});
    try geography(&row.geography, w);
    try html.render(w, "</dd><dt>Delivered response status and matched rule</dt>" ++
        "<dd>Not recorded</dd></dl>", .{});
    try evidence(row, w);
    try html.render(w, "<button class=\"btn mt-3\" data-action=\"events-similar-{{ v0 }}\">" ++
        "Find similar incidents</button>", .{
        .v0 = row.id,
    });
    if (row.query_redacted) try html.render(
        w,
        "<p class=\"sb-note\">Query string removed.</p>",
        .{},
    );
    if (row.display_truncated) try html.render(
        w,
        "<p class=\"sb-note\">Display text truncated.</p>",
        .{},
    );
    try html.render(w, "</details></article>", .{});
}

fn source(row: *const p.events.Row, w: *Writer) Writer.Error!void {
    try html.render(w, "<article class=\"border-b border-base-300 py-4\"><h2>", .{});
    try escape(w, row.ip.slice());
    try html.render(
        w,
        "</h2><p>{{ v0 }} recorded incident{{ v1 }} · Node {{ v2 " ++
            "}}</p><p>First seen: ",
        .{
            .v0 = row.count,
            .v1 = if (row.count == 1) "" else "s",
            .v2 = row.node,
        },
    );
    try timestamp(w, row.first_seen);
    try html.render(w, "</p><p>Last seen: ", .{});
    try timestamp(w, row.time);
    try html.render(w, "</p><p class=\"sb-note\">Country at persistence: ", .{});
    try geography(&row.geography, w);
    try html.render(w, "</p>" ++
        "<button class=\"btn mt-3\" data-action=\"events-source-", .{});
    try w.print("{d}/", .{row.node});
    try escape(w, row.ip.slice());
    try html.render(w, "\">Inspect source incidents</button></article>", .{});
}

fn geography(value: *const p.events.country.Mapping, w: *Writer) Writer.Error!void {
    if (value.mixed) return w.writeAll("Mixed recorded countries or mapping coverage");
    if (value.code.len != 0) {
        try escape(w, value.code.slice());
    } else if (value.recorded) {
        try w.writeAll("Unknown (address not mapped)");
    } else return w.writeAll("Not recorded");
    if (value.generation.len != 0) {
        try html.render(w, " <span class=\"break-all\">· GeoIP generation {{ v0 }}</span>", .{
            .v0 = value.generation.slice(),
        });
    } else try w.writeAll(" · Multiple GeoIP generations");
}

fn input(
    w: *Writer,
    name: []const u8,
    label: []const u8,
    value: []const u8,
    limit: usize,
) Writer.Error!void {
    try html.render(w, "<div class=\"grid gap-2 min-w-0\">", .{});
    try html.render(
        w,
        "<label for=\"{{ v0 }}\">{{ v1 }}</label><input id=\"{{ v2 }}\" " ++
            "name=\"{{ v3 }}\" " ++
            "class=\"input input-bordered w-full\" maxlength=\"{{ v4 }}\" value=\"",
        .{
            .v0 = name,
            .v1 = label,
            .v2 = name,
            .v3 = name,
            .v4 = limit,
        },
    );
    try escape(w, value);
    try html.render(w, "\"></div>", .{});
}

fn button(w: *Writer, action: []const u8, label: []const u8, disabled: bool) Writer.Error!void {
    try html.render(
        w,
        "<button class=\"btn\" data-action=\"{{ v0 }}\"{{ v1 }}>{{ v2 " ++
            "}}</button>",
        .{
            .v0 = action,
            .v1 = if (disabled) " disabled" else "",
            .v2 = label,
        },
    );
}

pub fn timestamp(w: *Writer, value: u64) Writer.Error!void {
    if (value > 253402300799) return w.writeAll("Time unavailable");
    const seconds: std.time.epoch.EpochSeconds = .{ .secs = value };
    const day = seconds.getEpochDay().calculateYearDay();
    const date = day.calculateMonthDay();
    const time = seconds.getDaySeconds();
    try w.print("{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} UTC", .{
        day.year,               @intFromEnum(date.month),  @as(u8, date.day_index) + 1,
        time.getHoursIntoDay(), time.getMinutesIntoHour(), time.getSecondsIntoMinute(),
    });
}

test "historical incident rendering escapes stored markup and names absent fields" {
    var state: State = .{ .phase = .events };
    state.events.loaded = true;
    state.events.count = 1;
    state.events.rows[0] = .{
        .id = 9007199254740993,
        .time = 0,
        .user_agent = try p.Bytes(128).init("<script>alert(1)</script>"),
        .path = try p.Bytes(256).init("/\"quoted\""),
    };
    var buffer: [16384]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&state, &writer);
    const output = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, output, "<script>") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "&lt;script&gt;") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "9007199254740993") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Not recorded") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "1970-01-01 00:00:00 UTC") != null);
}

fn evidence(row: *const p.events.Row, w: *Writer) Writer.Error!void {
    const capture = row.capture orelse {
        try html.render(
            w,
            "<p class=\"sb-note mt-3\">Versioned evidence and capture " ++
                "truncation: " ++
                "Not recorded. Historical payloads are withheld because they lack " ++
                "redaction metadata.</p>",
            .{},
        );
        return;
    };
    try html.render(
        w,
        "<h3 class=\"mt-4\">Evidence metadata v{{ v0 }}</h3>" ++
            "<p>Firewall response selected: {{ v1 }}. Delivery is not recorded.</p>" ++
            "<p>Query: {{ v2 }} bytes. Received body: {{ v3 }} bytes. " ++
            "Declared body: {{ v4 }} bytes.</p>" ++
            "<p class=\"sb-note\">Query values, body contents, cookies and other headers " ++
            "are omitted " ++
            "from this evidence view. This is not a reconstructed request.</p>",
        .{
            .v0 = capture.version,
            .v1 = capture.selected_status,
            .v2 = capture.query_bytes,
            .v3 = capture.body_bytes,
            .v4 = capture.declared_body_bytes,
        },
    );
    if (capture.truncated == 0) {
        try html.render(w, "<p class=\"sb-note\">No capture truncation recorded.</p>", .{});
        return;
    }
    try html.render(w, "<p class=\"sb-note\">Capture limits: ", .{});
    const names = [_][]const u8{
        "client address",
        "user agent",
        "method",
        "path",
        "category",
        "forensic payload",
        "body incomplete",
        "byte length saturated (shown as a lower bound)",
    };
    var separator = false;
    for (names, 0..) |name, bit| {
        if (capture.truncated & (@as(u16, 1) << @intCast(bit)) == 0) continue;
        if (separator) try w.writeAll(", ");
        try w.writeAll(name);
        separator = true;
    }
    try html.render(w, ".</p>", .{});
}
