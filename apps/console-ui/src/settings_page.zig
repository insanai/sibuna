const std = @import("std");
const p = @import("console_protocol");
const n = p.notifications;
const State = @import("state.zig").State;
const html = @import("html");
const Writer = std.Io.Writer;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.settings;
    try html.render(w, @embedFile("snippets/settings-header.html"), .{
        .busy = if (model.busy) " disabled" else "",
    });
    if (!state.allows(.manage_settings)) return html.render(w, "<p>An administrator " ++
        "manages notifications and thresholds.</p></main>", .{});
    if (state.message.len != 0) try html.render(
        w,
        "<p id=\"console-message\" tabindex=\"-1\" role=\"status\">{{ message }}</p>",
        .{ .message = state.message.slice() },
    );
    try html.render(w, "<section class=\"sb-panel\"><h2>Notification destinations</h2>" ++
        "<p class=\"sb-note\">At most eight destinations. Webhooks receive a JSON body " ++
        "with an HMAC-SHA256 signature when a secret is set; syslog receives RFC 5424 lines " ++
        "over UDP or framed TCP, selected explicitly below. Secrets are stored sealed " ++
        "and never shown again.</p>" ++
        "<div class=\"overflow-x-auto\"><table class=\"table\"><thead><tr><th>Label</th>" ++
        "<th>Kind</th><th>Target</th><th>Events</th><th>Last outcome</th><th></th></tr>" ++
        "</thead><tbody>", .{});
    for (model.rows[0..model.count], 0..) |row, index| try html.render(
        w,
        @embedFile("snippets/notification-row.html"),
        .{
            .label = row.label.slice(),
            .kind = kindLabel(row.kind, row.transport),
            .target = row.target.slice(),
            .events = eventsText(row.events),
            .outcome = if (row.last_outcome) |outcome| @tagName(outcome) else "never",
            .detail = row.last_detail.slice(),
            .enabled = if (row.enabled) "" else " (disabled)",
            .index = index,
        },
    );
    try html.render(w, "</tbody></table></div><div class=\"flex flex-wrap gap-2 mt-3\">" ++
        "<button class=\"btn btn-sm\" data-action=\"settings-new\"{{ busy }}>New " ++
        "destination</button><button class=\"btn btn-sm\" data-action=\"settings-next\"" ++
        "{{ next }}>Next page</button></div>", .{
        .busy = if (model.busy) " disabled" else "",
        .next = if (model.busy or model.next == null) " disabled" else "",
    });
    try form(state, w);
    try thresholds(state, w);
    try pages(state, w);
    try about(state, w);
    try html.render(w, "</main>", .{});
}

fn about(state: *const State, w: *Writer) Writer.Error!void {
    const source = state.settings.about.slice();
    if (source.len == 0) return;
    var memory: [8192]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        source,
        .{},
    ) catch return;
    const string = @import("events_state.zig").string;
    const field = @import("events_state.zig").field;
    const flag = struct {
        fn of(value: std.json.Value, key: []const u8) []const u8 {
            const item = field(value, key) orelse return "no";
            return if (item == .bool and item.bool) "yes" else "no";
        }
    };
    const number = struct {
        fn of(value: std.json.Value, key: []const u8) i64 {
            const item = field(value, key) orelse return 0;
            return if (item == .integer) item.integer else 0;
        }
    };
    try html.render(w, "<section class=\"sb-panel\"><h2>About</h2><dl class=\"sb-facts\">" ++
        "<dt>Version</dt><dd>{{ version }}</dd><dt>Node</dt><dd>{{ node }}</dd>" ++
        "<dt>Console schema</dt><dd>{{ schema }}</dd><dt>Origin</dt><dd>{{ origin }}</dd>" ++
        "<dt>Advertised console</dt><dd>{{ advertise }}</dd>" ++
        "<dt>Behind a trusted proxy</dt><dd>{{ proxy }} ({{ proxies }} trusted ranges)</dd>" ++
        "<dt>Secure cookies</dt><dd>{{ secure }}</dd>" ++
        "<dt>Console key file</dt><dd>{{ key }}</dd>" ++
        "<dt>Configured peer probes</dt><dd>{{ probes }}</dd></dl></section>", .{
        .version = string(parsed, "version"),
        .node = number.of(parsed, "node"),
        .schema = number.of(parsed, "schema"),
        .origin = string(parsed, "origin"),
        .advertise = if (string(parsed, "advertise").len == 0)
            "same as origin"
        else
            string(parsed, "advertise"),
        .proxy = flag.of(parsed, "behind_proxy"),
        .proxies = number.of(parsed, "trusted_proxies"),
        .secure = flag.of(parsed, "cookie_secure"),
        .key = flag.of(parsed, "key_file"),
        .probes = number.of(parsed, "probes"),
    });
}

fn kindLabel(kind: n.Kind, transport: n.Transport) []const u8 {
    if (kind == .webhook) return "webhook";
    return if (transport == .tcp) "syslog / TCP" else "syslog / UDP";
}

fn eventsText(mask: u8) []const u8 {
    return switch (mask) {
        n.all_events => "all",
        1 => "denial spike",
        2 => "ban",
        4 => "node unhealthy",
        8 => "leader change",
        else => "several",
    };
}

fn form(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.settings;
    const row: @import("settings_state.zig").Row = if (model.selected) |index|
        model.rows[index]
    else
        .{};
    var cooldown: [12]u8 = undefined;
    try html.render(w, @embedFile("snippets/notification-form.html"), .{
        .heading = if (model.selected == null) "New destination" else "Edit destination",
        .webhook = if (row.kind == .webhook) " selected" else "",
        .syslog = if (row.kind == .syslog) " selected" else "",
        .udp = if (row.transport == .udp) " selected" else "",
        .tcp = if (row.transport == .tcp) " selected" else "",
        .label = row.label.slice(),
        .target = row.target.slice(),
        .secret_note = if (row.secret_set)
            "A secret is stored. Leave blank to keep it or tick clear to remove it."
        else
            "Optional shared secret for the webhook signature (at most 64 bytes).",
        .spike = checked(row.events, .denial_spike),
        .ban = checked(row.events, .ban),
        .unhealthy = checked(row.events, .node_unhealthy),
        .leader = checked(row.events, .leader_change),
        .cooldown = std.fmt.bufPrint(&cooldown, "{d}", .{row.cooldown_seconds}) catch "0",
        .enabled = if (row.enabled) " checked" else "",
        .busy = if (model.busy) " disabled" else "",
        .existing = if (model.selected == null) " disabled" else "",
    });
    if (model.result.len != 0) try html.render(
        w,
        "<p role=\"status\" class=\"{{ class }}\">Test delivery: {{ text }}</p>",
        .{
            .class = if (model.result_ok) "sb-success" else "sb-error",
            .text = model.result.slice(),
        },
    );
    try html.render(w, "</section>", .{});
}

fn checked(mask: u8, event: n.Event) []const u8 {
    return if (mask == 0 or mask & event.bit() != 0) " checked" else "";
}

fn thresholds(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.settings;
    try html.render(w, "<section class=\"sb-panel\"><h2>Denial spike thresholds</h2>" ++
        "<p class=\"sb-note\">A spike is raised when denials in the last 60 seconds exceed " ++
        "both the minimum and the factor times the previous 60 seconds; it re-arms below " ++
        "that threshold.</p>", .{});
    for (n.known_settings) |key| {
        const current = model.setting(key);
        try html.render(w, @embedFile("snippets/setting-row.html"), .{
            .key = key,
            .value = if (current) |item| item.value.slice() else defaultValue(key),
            .revision = if (current) |item| item.revision else 0,
            .busy = if (model.busy) " disabled" else "",
        });
    }
    try html.render(w, "</section>", .{});
}

fn defaultValue(key: []const u8) []const u8 {
    return if (std.mem.eql(u8, key, "notify.spike_factor")) "3" else "100";
}

fn pages(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.pages;
    const busy = if (model.busy or !model.loaded) " disabled" else "";
    try html.render(w, "<section class=\"sb-panel\"><h2>Response pages</h2>" ++
        "<p class=\"sb-note\">" ++
        "Bounded HTML served to browsers for challenges, denials, rate limits, bans and " ++
        "overload. Placeholders: {{ placeholders }}. Scripts, external resources, forms and " ++
        "event handlers are refused; the challenge page must contain the solver slot exactly " ++
        "once.</p><div class=\"flex flex-wrap gap-2\" role=\"tablist\">", .{
        .placeholders = "{{ status }}, {{ reason }}, {{ retry_after }}, {{ request_id }}, " ++
            "{{ node }} and, for the challenge page only, {{ challenge }}",
    });
    inline for (@typeInfo(p.pages.Kind).@"enum".fields) |field| {
        const active = std.mem.eql(u8, field.name, @tagName(model.kind));
        try html.render(w, "<button class=\"btn btn-sm{{ active }}\" role=\"tab\" " ++
            "aria-selected=\"{{ selected }}\" data-action=\"pages-open-{{ name }}\"{{ busy }}>" ++
            "{{ name }}</button>", .{
            .active = if (active) " btn-active" else "",
            .selected = if (active) "true" else "false",
            .name = field.name,
            .busy = busy,
        });
    }
    try html.render(w, "</div>", .{});
    try html.render(w, @embedFile("snippets/page-editor.html"), .{
        .kind = @tagName(model.kind),
        .revision = model.revision,
        .state = if (!model.loaded)
            "loading"
        else if (model.customized)
            "customized"
        else
            "default",
        .html = model.html(),
        .busy = busy,
        .reset = if (model.customized) "" else " disabled",
    });
    if (model.preview_path.len != 0) try html.render(w, "<a class=\"btn btn-outline\" " ++
        "href=\"{{ path }}\" target=\"_blank\" rel=\"noopener\">Open preview</a>", .{
        .path = model.preview_path.slice(),
    });
    try html.render(w, "</div>", .{});
    if (model.result.len != 0) try html.render(w, "<p role=\"status\" class=\"{{ tone }}\">" ++
        "{{ text }}</p>", .{
        .tone = if (model.result_ok) "alert alert-success mt-3" else "sb-error",
        .text = model.result.slice(),
    });
    try html.render(w, "</form></section>", .{});
}
