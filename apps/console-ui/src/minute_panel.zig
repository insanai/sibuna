//! Historical rows remain separate by node and boot. Missing intervals never become zero traffic.
const html = @import("html");
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
var generation: u32 = 0;
pub const Model = struct {
    const Row = struct {
        minute: u64 = 0,
        node: u32 = 0,
        boot: [16]u8 = @splat(0),
        count: u64 = 0,
        ms: u64 = 0,
        coverage: enum { observed, partial, collecting, gap } = .observed,
    };
    rows: [p.minutes.max_rows]Row = @splat(.{}),
    count: usize = 0,
    retention_days: u16 = p.minutes.retention_days,
    before: ?p.minutes.Cursor = null,
    next: ?p.minutes.Cursor = null,
    scope_node: ?u32 = null,
    requested_node: ?u32 = null,
    from: u64 = 0,
    until: u64 = 0,
    hours: u16 = 1,
    all_nodes: bool = false,
    generation: u32 = 0,
    requested_at: u64 = 0,
    received_at: u64 = 0,
    busy: bool = false,
    loaded: bool = false,
    failed: bool = false,

    pub fn clear(self: *Model) void {
        @memset(std.mem.asBytes(self), 0);
        self.before = null;
        self.next = null;
        self.scope_node = null;
        self.requested_node = null;
        self.hours = 1;
        self.retention_days = p.minutes.retention_days;
    }

    fn decode(self: *Model, value: std.json.Value, alloc: std.mem.Allocator) !void {
        const page = try @import("json_value.zig").decode(p.minutes.Reply, value, alloc);
        if (page.version != 1 or page.retention_days == 0 or
            page.retention_days > p.minutes.retention_days or page.rows.len > self.rows.len or
            page.from_minute > page.until_minute or page.until_minute > page.observed_at / 60 or
            page.until_minute - page.from_minute > 90 * 1440)
            return error.InvalidResponse;
        if (self.before != null and (page.until_minute != self.until or
            page.from_minute < self.from)) return error.InvalidResponse;
        var replacement = self.*;
        replacement.count = page.rows.len;
        replacement.retention_days = page.retention_days;
        replacement.next = page.next;
        replacement.from = page.from_minute;
        replacement.until = page.until_minute;
        replacement.scope_node = self.requested_node;
        var previous = self.before;
        for (page.rows, 0..) |row, i| {
            if (row.minute != row.utc_end / 60 or row.end_ms <= row.start_ms or
                row.utc_start > row.utc_end or
                row.observed_ms != row.end_ms - row.start_ms or row.observations == 0 or
                row.epoch == 0 or std.mem.allEqual(u8, &row.boot, 0) or
                row.minute < page.from_minute or row.minute > page.until_minute or
                (self.requested_node != null and row.node != self.requested_node.?) or
                (row.complete and (!row.sealed or row.gap))) return error.InvalidResponse;
            if (previous) |cursor| if (!precedes(row.cursor(), cursor))
                return error.InvalidResponse;
            previous = row.cursor();
            var count: u64 = 0;
            inline for (p.minutes.counter_fields, 0..) |name, field_index| {
                if (field_index < 6) {
                    count = std.math.add(u64, count, @field(row.counts, name)) catch
                        return error.InvalidResponse;
                }
            }
            replacement.rows[i] = .{
                .minute = row.minute,
                .node = row.node,
                .boot = row.boot,
                .count = count,
                .ms = row.observed_ms,
                .coverage = if (row.gap) .gap else if (!row.sealed)
                    .collecting
                else if (!row.complete) .partial else .observed,
            };
        }
        if (page.next) |cursor| {
            if (page.rows.len == 0 or !std.meta.eql(cursor, page.rows[page.rows.len - 1].cursor()))
                return error.InvalidResponse;
        }
        replacement.loaded = true;
        replacement.failed = false;
        self.* = replacement;
    }
};

pub const precedes = p.minute_summary.precedes;

pub const Request = struct { id: p.Bytes(32), body: p.minutes.Request };
pub fn request(state: *State, force: bool) ?Request {
    const model = &state.minute_history;
    const stats = state.stats orelse return null;
    if (!state.fullAccess() or state.kiosk or state.phase != .dashboard or !state.timeline_open or
        !state.history_minutes or state.paused or state.hidden or model.busy or
        !@import("dashboard_scope.zig").historyAvailable(state)) return null;
    if (!force and (model.before != null or (model.generation != 0 and
        state.browser_time -| model.requested_at < 10))) return null;
    generation +%= 1;
    if (generation == 0) generation = 1;
    model.generation = generation;
    model.requested_at = state.browser_time;
    model.busy = true;
    const until = if (model.before != null) model.until else stats.timestamp / 60;
    model.requested_node = if (model.before != null)
        model.scope_node
    else if (model.all_nodes or stats.node == 0)
        null
    else
        stats.node;
    var id: p.Bytes(32) = .{};
    id.len = (std.fmt.bufPrint(&id.data, "minutes-{d}", .{generation}) catch unreachable).len;
    const from = if (model.before != null) model.from else until -| (@as(u64, model.hours) * 60);
    return .{ .id = id, .body = .{
        .from_minute = from,
        .until_minute = until,
        .node = model.requested_node,
        .before = model.before,
    } };
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    alloc: std.mem.Allocator,
) bool {
    const ticket = std.fmt.parseInt(u32, id[8..], 10) catch return false;
    const model = &state.minute_history;
    if (ticket == 0 or ticket != model.generation) return false;
    model.busy = false;
    if (!state.fullAccess() or state.kiosk or state.phase != .dashboard or state.paused or
        !state.history_minutes) return false;
    if (status == 401 or status == 403) return true;
    model.failed = true;
    if (status != 200) return false;
    model.decode(body, alloc) catch return false;
    model.received_at = state.browser_time;
    return false;
}

pub fn table(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.minute_history;
    if (state.stats == null or !@import("dashboard_scope.zig").historyAvailable(state))
        return html.render(w, "<div id=\"timeline-values\" role=\"status\">" ++
            "Minute history is unavailable on this node.</div>", .{});
    try controls(state, w);
    try html.render(w, "<p class=\"sb-note\">Stored outcome intervals, retained for " ++
        "up to {{ days }} days. " ++
        "Each node and boot stays separate. Missing history is unobserved, not zero traffic. " ++
        "Minute labels describe sample-aligned intervals.</p>", .{ .days = model.retention_days });
    if (model.failed) try html.render(w, "<p role=\"status\">Minute history unavailable. " ++
        "Displayed records may be stale. Retry Latest after storage recovers.</p>", .{});
    if (!model.loaded) return html.render(w, "<div id=\"timeline-values\" role=\"status\">" ++
        "Waiting for stored minute history.</div>", .{});
    try html.render(
        w,
        "<p class=\"sb-note\">{{ v0 }} · Updated {{ v1 }} seconds ago. ",
        .{
            .v0 = if (model.busy) "Loading" else if (state.paused)
                "Paused"
            else if (model.before != null)
                "Earlier records"
            else
                "Latest · refreshes every 10 seconds",
            .v1 = state.browser_time -| model.received_at,
        },
    );
    if (model.scope_node) |node| {
        try html.render(w, "Node {{ v0 }}.</p>", .{
            .v0 = node,
        });
    } else try html.render(w, "All nodes.</p>", .{});
    try html.render(
        w,
        "<div id=\"timeline-values\" data-preserve-scroll " ++
            "class=\"overflow-x-auto\" " ++
            "tabindex=\"0\" role=\"region\" aria-label=\"Scrollable minute history\">" ++
            "<table class=\"table\"><caption>Up to eight stored intervals</caption><thead><tr>" ++
            "<th>Minute (UTC)</th><th>Node / boot</th><th>Requests</th><th>Elapsed ms</th>" ++
            "<th>Coverage</th></tr></thead><tbody>",
        .{},
    );
    for (model.rows[0..model.count]) |row| {
        try html.render(w, "<tr><td class=\"whitespace-nowrap\">", .{});
        try @import("events_page.zig").timestamp(w, row.minute * 60);
        const boot = std.fmt.bytesToHex(row.boot, .lower);
        try html.render(
            w,
            "</td><td class=\"whitespace-nowrap\">{{ v0 }} / " ++
                "<abbr title=\"{{ v1 }}\">{{ v2 }}</abbr></td><td>{{ v3 " ++
                "}}</td><td>{{ v4 }}</td><td>{{ v5 }}</td></tr>",
            .{
                .v0 = row.node,
                .v1 = boot,
                .v2 = boot[0..8],
                .v3 = row.count,
                .v4 = row.ms,
                .v5 = switch (row.coverage) {
                    .observed => "Complete interval",
                    .partial => "Partial interval",
                    .collecting => "Unsealed interval",
                    .gap => "Gap / delayed",
                },
            },
        );
    }
    if (model.count == 0) try html.render(w, "<tr><td colspan=\"5\">No stored intervals in " ++
        "this page and time window.</td></tr>", .{});
    try html.render(w, "</tbody></table></div>", .{});
}

fn controls(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.minute_history;
    try html.render(w, "<form id=\"minute-window\" data-change=\"minute-window\">" ++
        "<fieldset class=\"sb-settings-form my-3\"{{ v0 }}>" ++
        "<label class=\"sb-field\"><span>History window</span>" ++
        "<select id=\"minute-hours\" name=\"hours\" class=\"select\">", .{
        .v0 = if (model.busy or state.paused) " disabled" else "",
    });
    const hours = [_]u16{ 1, 24, 168, 2160 };
    const labels = [_][]const u8{ "Last hour", "Last 24 hours", "Last 7 days", "Last 90 days" };
    for (hours, labels) |hour, label| try html.render(
        w,
        "<option value=\"{{ v0 }}\"{{ v1 }}>{{ v2 }}</option>",
        .{
            .v0 = hour,
            .v1 = if (model.hours == hour) " selected" else "",
            .v2 = label,
        },
    );
    try html.render(w, "</select></label><label><input type=\"checkbox\" class=\"checkbox\" " ++
        "id=\"minute-all-nodes\" name=\"all_nodes\" value=\"true\"{{ v0 }}> All nodes</label>" ++
        "</fieldset></form>" ++
        "<div class=\"flex flex-wrap gap-2\"><button class=\"btn btn-sm\" " ++
        "data-action=\"minute-latest\"{{ v1 }}>Latest</button><button class=\"btn btn-sm\" " ++
        "data-action=\"minute-older\"{{ v2 }}>Older</button></div>", .{
        .v0 = if (model.all_nodes) " checked" else "",
        .v1 = if (model.busy or state.paused) " disabled" else "",
        .v2 = if (model.busy or state.paused or model.next == null) " disabled" else "",
    });
}

test "minute rows retain exact counters and reject unordered or inconsistent pages atomically" {
    const t = std.testing;
    const source =
        \\{"from_minute":100,"until_minute":120,"observed_at":7200,"next":null,
        \\ "rows":[{"node":2,"boot":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        \\ "epoch":1,"minute":120,"utc_start":7140,"utc_end":7200,"start_ms":1000,
        \\ "end_ms":61000,"observed_ms":60000,"observations":240,"sealed":true,
        \\ "complete":true,"counts":{"admitted":"9007199254740993","banned":1,
        \\ "origin_4xx":2}}]}
    ;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const value = try std.json.parseFromSliceLeaky(std.json.Value, alloc, source, .{});
    var model: Model = .{ .requested_node = 2 };
    try model.decode(value, alloc);
    try t.expectEqual(@as(u64, 9007199254740994), model.rows[0].count);
    try t.expectEqual(.observed, model.rows[0].coverage);
    const old = model;
    const rows = value.object.getPtr("rows").?;
    const sealed = rows.array.items[0].object.getPtr("sealed").?;
    sealed.* = .{ .bool = false };
    try t.expectError(error.InvalidResponse, model.decode(value, alloc));
    try t.expectEqualDeep(old, model);
    sealed.* = .{ .bool = true };
    try rows.array.append(rows.array.items[0]);
    try t.expectError(error.InvalidResponse, model.decode(value, alloc));
    try t.expectEqualDeep(old, model);
    for (0..7) |_| try rows.array.append(rows.array.items[0]);
    var empty: [0]u8 = .{};
    var bounded = std.heap.FixedBufferAllocator.init(&empty);
    try t.expectError(error.InvalidResponse, model.decode(value, bounded.allocator()));
    model.clear();
    try t.expectEqual(@as(u16, 1), model.hours);
    try t.expect(model.before == null and model.next == null and model.scope_node == null);
    try t.expect(std.mem.allEqual(u8, &model.rows[0].boot, 0));
}

test "minute queries pin scope and ignore old sessions and inactive sources" {
    const t = std.testing;
    var state: State = .{};
    try t.expect(request(&state, true) == null);
    state.phase = .dashboard;
    state.csrf = try p.Bytes(64).init("test");
    state.timeline_open = true;
    state.history_minutes = true;
    state.stats = std.mem.zeroes(p.StatsSnapshot);
    state.stats.?.node = 2;
    state.stats.?.timestamp = 7200;
    try t.expect(request(&state, true) == null);
    state.stats.?.minute_history.available = true;
    const first = request(&state, false).?;
    try t.expectEqual(@as(?u64, 60), first.body.from_minute);
    try t.expectEqual(@as(?u32, 2), first.body.node);
    try t.expect(request(&state, true) == null);
    state.history_minutes = false;
    try t.expect(!response(&state, first.id.slice(), 401, .null, t.allocator));
    state.history_minutes = true;
    state.minute_history.before = .{ .minute = 119, .node = 2, .boot = @splat(1), .epoch = 1 };
    state.minute_history.from = 60;
    state.minute_history.until = 120;
    state.minute_history.scope_node = 2;
    state.stats.?.node = 3;
    state.stats.?.timestamp = 9000;
    try t.expect(request(&state, false) == null);
    const older = request(&state, true).?;
    try t.expectEqual(first.body.from_minute, older.body.from_minute);
    try t.expectEqual(first.body.until_minute, older.body.until_minute);
    try t.expectEqual(first.body.node, older.body.node);
    state.reset();
    try t.expect(!response(&state, older.id.slice(), 401, .null, t.allocator));
    try t.expect(!state.minute_history.busy and state.minute_history.before == null);
}
