//! Retained server intervals remain available when a browser reconnects or opens later.
const html = @import("html");
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
var generation: u32 = 0;
pub const Model = struct {
    const Row = struct {
        utc: u64 = 0,
        count: u64 = 0,
        ms: u64 = 0,
        gap: bool = false,
        partial: bool = false,
    };
    rows: [10]Row = @splat(.{}),
    count: usize = 0,
    boot: [32]u8 = @splat(0),
    epoch: u32 = 0,
    before: u64 = 0,
    next: u64 = 0,
    generation: u32 = 0,
    requested_at: u64 = 0,
    received_at: u64 = 0,
    busy: bool = false,
    loaded: bool = false,
    failed: bool = false,
    conflict: bool = false,

    pub fn clear(self: *Model) void {
        // Only integers, booleans and fixed arrays: every field's default is all-zero.
        @memset(std.mem.asBytes(self), 0);
    }

    fn decode(self: *Model, value: std.json.Value, alloc: std.mem.Allocator) !void {
        const page = try @import("json_value.zig").decode(p.timeline.Page, value, alloc);
        if (page.version != 1 or page.retention_seconds != 3600 or page.epoch == 0 or
            page.boot.len != 32) return error.InvalidResponse;
        for (page.boot) |byte| if (!std.ascii.isHex(byte)) return error.InvalidResponse;
        if (self.before != 0 and (page.epoch != self.epoch or
            !std.mem.eql(u8, page.boot, &self.boot))) return error.InvalidResponse;
        var replacement = self.*;
        @memcpy(&replacement.boot, page.boot);
        replacement.epoch = page.epoch;
        replacement.next = page.next_before orelse 0;
        replacement.count = page.rows.len;
        var previous: u64 = self.before;
        for (page.rows, 0..) |row, i| {
            if (row.end_ms <= row.start_ms or row.observed_ms != row.end_ms - row.start_ms or
                row.observations == 0 or (previous != 0 and row.sequence >= previous))
                return error.InvalidResponse;
            previous = row.sequence;
            var count: u64 = 0;
            const names = .{
                "admitted", "challenged", "denied", "banned", "rate_limited", "other",
            };
            inline for (names) |name| {
                count = std.math.add(u64, count, @field(row.counts, name)) catch
                    return error.InvalidResponse;
            }
            replacement.rows[i] = .{
                .utc = row.utc_end,
                .count = count,
                .ms = row.observed_ms,
                .gap = row.gap,
                .partial = row.partial,
            };
        }
        if (replacement.next != 0 and
            (page.rows.len == 0 or replacement.next != previous)) return error.InvalidResponse;
        replacement.loaded = true;
        replacement.failed = false;
        replacement.conflict = false;
        self.* = replacement;
    }
};

pub const Request = struct { id: p.Bytes(32), body: p.timeline.Query };
pub fn request(state: *State, force: bool) ?Request {
    const model = &state.timeline;
    if (!state.fullAccess() or state.phase != .dashboard or !state.timeline_open or
        state.history_minutes or state.paused or state.hidden or model.busy) return null;
    if (!force and (model.before != 0 or (model.generation != 0 and
        state.browser_time -| model.requested_at < 10))) return null;
    generation +%= 1;
    if (generation == 0) generation = 1;
    model.generation = generation;
    model.requested_at = state.browser_time;
    model.busy = true;
    var id: p.Bytes(32) = .{};
    id.len = (std.fmt.bufPrint(&id.data, "timeline-{d}", .{generation}) catch unreachable).len;
    return .{
        .id = id,
        .body = .{
            .limit = 10,
            .before = if (model.before == 0) null else model.before,
            .epoch = if (model.before == 0) null else model.epoch,
            .boot = if (model.before == 0) null else &model.boot,
        },
    };
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    alloc: std.mem.Allocator,
) bool {
    const ticket = std.fmt.parseInt(u32, id[9..], 10) catch return false;
    const model = &state.timeline;
    if (ticket == 0 or ticket != model.generation) return false;
    model.busy = false;
    if (!state.fullAccess() or state.phase != .dashboard or state.paused or
        state.history_minutes) return false;
    if (status == 401 or status == 403) return true;
    model.failed = true;
    model.conflict = status == 409;
    if (status != 200) return false;
    model.decode(body, alloc) catch return false;
    model.received_at = state.browser_time;
    return false;
}

pub fn table(state: *const State, w: *Writer) Writer.Error!void {
    if (!try header(state, w)) return;
    if (state.history_minutes) return @import("minute_panel.zig").table(state, w);
    const model = &state.timeline;
    try html.render(w, "<p class=\"sb-note\">Server observations retained for one hour. " ++
        "UTC labels describe interval endings; gaps are not zero traffic.</p>", .{});
    if (model.failed) try w.writeAll(if (model.conflict)
        "<p role=\"status\">History changed. Reload the latest page.</p>"
    else
        "<p role=\"status\">History unavailable. Displayed values may be stale.</p>");
    try html.render(
        w,
        "<div class=\"flex flex-wrap gap-2\">" ++
            "<button class=\"btn btn-sm\" " ++
            "data-action=\"timeline-latest\"{{ v0 }}>Latest</button>" ++
            "<button class=\"btn btn-sm\" data-action=\"timeline-older\"{{ " ++
            "v1 }}>Older</button></div>",
        .{
            .v0 = if (model.busy or state.paused) " disabled" else "",
            .v1 = if (model.busy or state.paused or model.next == 0 or model.conflict)
                " disabled"
            else
                "",
        },
    );
    if (model.loaded) try html.render(
        w,
        "<p class=\"sb-note\">{{ v0 }} · Updated {{ v1 }} seconds " ++
            "ago.</p>",
        .{
            .v0 = if (model.busy) "Loading" else if (state.paused)
                "Paused"
            else if (model.before == 0)
                "Latest · refreshes every 10 seconds"
            else
                "Earlier observations",
            .v1 = state.browser_time -| model.received_at,
        },
    ) else try html.render(w, "<p role=\"status\">Waiting for retained observations.</p>", .{});
    try html.render(
        w,
        "<div id=\"timeline-values\" data-preserve-scroll " ++
            "class=\"overflow-x-auto\" " ++
            "tabindex=\"0\" role=\"region\" aria-label=\"Scrollable timeline values\">" ++
            "<table class=\"table\"><caption>Up to ten retained intervals</caption><thead><tr>" ++
            "<th>Ending at</th><th>Requests</th><th>Milliseconds</th><th>Requests/s</th>" ++
            "<th>Coverage</th></tr></thead><tbody>",
        .{},
    );
    try values(model, w);
}

fn values(model: *const Model, w: *Writer) Writer.Error!void {
    for (model.rows[0..model.count]) |row| {
        try w.writeAll("<tr><td class=\"whitespace-nowrap\">");
        try @import("events_page.zig").timestamp(w, row.utc);
        const coverage = if (row.gap) "Gap / delayed" else if (row.partial)
            "Collecting"
        else
            "Observed";
        try w.print("</td><td>{d}</td><td>{d}</td><td>{d:.2}</td><td>{s}</td></tr>", .{
            row.count, row.ms,
            @import("stats_series.zig").rate(.{
                .count = row.count,
                .duration_ms = row.ms,
            }),
            coverage,
        });
    }
    if (model.count == 0) try w.writeAll("<tr><td colspan=\"5\">No retained observations " ++
        "on this page.</td></tr>");
    try w.writeAll("</tbody></table></div>");
}

fn header(state: *const State, w: *Writer) Writer.Error!bool {
    try w.print("<button type=\"button\" class=\"btn btn-sm\" " ++
        "data-action=\"timeline-values\" aria-expanded=\"{}\" " ++
        "aria-controls=\"timeline-values\">Retained timeline values</button>", .{
        state.timeline_open,
    });
    if (!state.timeline_open) {
        try html.render(w, "<div id=\"timeline-values\" hidden></div>", .{});
        return false;
    }
    try w.print("<div class=\"join my-3\" role=\"group\" aria-label=\"History source\">" ++
        "<button class=\"btn btn-sm join-item\" data-action=\"timeline-seconds\" " ++
        "aria-pressed=\"{}\">Seconds</button>" ++
        "<button class=\"btn btn-sm join-item\" data-action=\"timeline-minutes\" " ++
        "aria-pressed=\"{}\">Minute history</button></div>", .{
        !state.history_minutes, state.history_minutes,
    });
    return true;
}

test "retained history owns decoded rows, preserves large counts and refuses invalid intervals" {
    const t = std.testing;
    const source =
        \\{"node":1,"boot":"00000000000000000000000000000001","epoch":1,
        \\ "as_of_ms":1250,"discarded_intervals":0,"oldest_sequence":0,"next_before":1,
        \\ "rows":[{"sequence":1,"utc_start":100,"utc_end":101,"start_ms":750,
        \\ "end_ms":1250,"observed_ms":500,"observations":2,"gap":false,
        \\ "counts":{"admitted":"9007199254740993","banned":1,"origin_4xx":2}}]}
    ;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), source, .{});
    var model: Model = .{};
    try model.decode(value, arena.allocator());
    try t.expectEqual(@as(u64, 9007199254740994), model.rows[0].count);
    try t.expectEqual(@as(u64, 1), model.next);
    const old = model;
    const rows = value.object.getPtr("rows").?;
    const duration = rows.array.items[0].object.getPtr("observed_ms").?;
    duration.* = .{ .integer = 0 };
    try t.expectError(error.InvalidResponse, model.decode(value, arena.allocator()));
    try t.expectEqualDeep(old, model);
    duration.* = .{ .integer = 500 };
    for (0..10) |_| try rows.array.append(rows.array.items[0]);
    try t.expectError(error.InvalidResponse, model.decode(value, arena.allocator()));
    try t.expectEqualDeep(old, model);
    model.clear();
    try t.expectEqual(@as(usize, 0), model.count);
    try t.expect(std.mem.allEqual(u8, &model.boot, 0));
}

test "history queries require authentication and ignore stale responses after session reset" {
    const t = std.testing;
    var state: State = .{};
    try t.expect(request(&state, true) == null);
    state.phase = .dashboard;
    state.csrf = try p.Bytes(64).init("test");
    try t.expect(request(&state, true) == null);
    state.timeline_open = true;
    const first = request(&state, false).?;
    try t.expect(request(&state, true) == null);
    state.reset();
    state.phase = .dashboard;
    state.csrf = try p.Bytes(64).init("replacement");
    state.timeline_open = true;
    const next = request(&state, false).?;
    try t.expect(!response(&state, first.id.slice(), 401, .null, t.allocator));
    try t.expect(state.timeline.busy);
    try t.expect(!response(&state, next.id.slice(), 409, .null, t.allocator));
    try t.expect(state.timeline.conflict and state.timeline.failed);
    try t.expect(request(&state, false) == null);
    const refresh = request(&state, true).?;
    try t.expect(response(&state, refresh.id.slice(), 401, .null, t.allocator));
}
