//! Per-address challenge records and adaptive-difficulty transitions on the Challenges page.
//! Records are bounded observations: queue losses are stated beside the table, absent
//! durations read as not recorded, and no cohort rate is inferred from them.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
const decode = @import("json_value.zig").decode;
const string = @import("events_state.zig").string;
const wire = p.challenge_records;

const WireRow = struct {
    id: u64,
    node: u32,
    second: u64,
    ip: []const u8,
    outcome: wire.Outcome,
    cause: u8,
    algorithm: u8,
    parameter: u8,
    openings: u8,
    duration_ms: ?u32,
};
const WireCursor = struct { second: u64, id: u64 };

pub const Model = struct {
    hours: u16 = 24,
    cause: ?u8 = null,
    outcome: ?wire.Outcome = null,
    rows: [wire.max_rows]wire.Row = undefined,
    count: u8 = 0,
    next: ?wire.Cursor = null,
    dropped: u64 = 0,
    retention_days: u16 = wire.retention_days,
    loaded: bool = false,
    busy: bool = false,
    failed: bool = false,
    received_at: u64 = 0,
    difficulty: ?wire.DifficultyPage = null,
    difficulty_busy: bool = false,
    difficulty_failed: bool = false,

    pub fn records(self: *Model, value: std.json.Value, allocator: std.mem.Allocator) !void {
        const page = try decode(struct {
            version: u8,
            retention_days: u16,
            dropped_since_boot: u64,
            rows: []const WireRow,
            next: ?WireCursor,
        }, value, allocator);
        if (page.version != 1 or page.rows.len > self.rows.len) return error.InvalidResponse;
        var candidate: [wire.max_rows]wire.Row = undefined;
        for (page.rows, candidate[0..page.rows.len]) |row, *item| {
            if (row.ip.len == 0 or row.ip.len > 48 or !std.unicode.utf8ValidateSlice(row.ip))
                return error.InvalidResponse;
            item.* = .{
                .id = row.id,
                .node = row.node,
                .second = row.second,
                .ip = try p.Bytes(48).init(row.ip),
                .outcome = row.outcome,
                .cause = row.cause,
                .algorithm = row.algorithm,
                .parameter = row.parameter,
                .openings = row.openings,
                .duration_ms = row.duration_ms,
            };
        }
        @memcpy(self.rows[0..page.rows.len], candidate[0..page.rows.len]);
        self.count = @intCast(page.rows.len);
        self.next = if (page.next) |cursor|
            .{ .second = cursor.second, .id = cursor.id }
        else
            null;
        self.dropped = page.dropped_since_boot;
        self.retention_days = page.retention_days;
        self.loaded = true;
    }

    pub fn transitions(self: *Model, value: std.json.Value, allocator: std.mem.Allocator) !void {
        const page = try decode(struct {
            version: u8,
            current_bits: ?u8,
            rows: []const struct {
                node: u32,
                second: u64,
                previous_bits: u8,
                bits: u8,
                rate_256: u64,
            },
            truncated: bool,
        }, value, allocator);
        if (page.version != 1 or page.rows.len > wire.max_transitions)
            return error.InvalidResponse;
        var result: wire.DifficultyPage = .{
            .current_bits = page.current_bits,
            .truncated = page.truncated,
        };
        for (page.rows, 0..) |row, i| result.rows[i] = .{
            .node = row.node,
            .second = row.second,
            .previous_bits = row.previous_bits,
            .bits = row.bits,
            .rate_256 = row.rate_256,
        };
        result.count = @intCast(page.rows.len);
        self.difficulty = result;
    }
};

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    try difficulty(state, w);
    try records(state, w);
}

fn difficulty(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.challenge_records;
    try html.render(w, "<section class=\"sb-panel mt-6\" id=\"challenge-difficulty\">" ++
        "<h2>Adaptive difficulty</h2><p class=\"sb-note\">The load controller adds bits when " ++
        "the smoothed issue rate exceeds its baseline. Transitions are this console's " ++
        "once-per-second observations over the selected window, retained seven days.</p>", .{});
    if (model.difficulty_busy) try w.writeAll("<p role=\"status\">Loading transitions…</p>");
    if (model.difficulty_failed)
        try w.writeAll("<p class=\"sb-note\">Transitions unavailable. Retry.</p>");
    const page = model.difficulty orelse return w.writeAll("</section>");
    try html.render(w, "<p>Current adaptive bump: {{ bits }}</p>", .{
        .bits = if (page.current_bits) |bits| bits else 0,
    });
    if (page.current_bits == null)
        try w.writeAll("<p class=\"sb-note\">Not recorded on this node.</p>");
    try w.writeAll("<div class=\"overflow-x-auto\"><table class=\"table\"><thead><tr>" ++
        "<th scope=\"col\">Time (UTC)</th><th scope=\"col\">Node</th>" ++
        "<th scope=\"col\">Bits</th><th scope=\"col\">Issue rate/s</th></tr></thead><tbody>");
    for (page.rows[0..page.count]) |row| {
        try w.writeAll("<tr><td>");
        try @import("events_page.zig").timestamp(w, row.second);
        try html.render(w, "</td><td>{{ node }}</td><td>{{ before }} → {{ after }}</td>" ++
            "<td>{{ rate }}</td></tr>", .{
            .node = row.node,
            .before = row.previous_bits,
            .after = row.bits,
            .rate = row.rate_256 / 256,
        });
    }
    if (page.count == 0)
        try w.writeAll("<tr><td colspan=\"4\">No transitions in the window.</td></tr>");
    try w.writeAll("</tbody></table></div>");
    if (page.truncated)
        try w.writeAll("<p class=\"sb-note\">Only the newest 32 transitions are shown.</p>");
    try w.writeAll("</section>");
}

fn records(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.challenge_records;
    try html.render(w, "<section class=\"sb-panel mt-6\" id=\"challenge-records\">" ++
        "<h2>Per-address records</h2><p class=\"sb-note\">Issued, accepted and rejected " ++
        "challenges by client address over the selected window, retained seven days. " ++
        "Durations are untrusted client telemetry; a full queue drops records and the loss is " ++
        "counted below.</p><div class=\"sb-filter-actions\">" ++
        "<button class=\"btn btn-sm\" data-action=\"challenges-records-all\"{{ busy }}>" ++
        "All records</button><button class=\"btn btn-sm\" " ++
        "data-action=\"challenges-records-rejected\"{{ busy }}>Rejected only</button>" ++
        "<button class=\"btn btn-sm\" data-action=\"challenges-records-accepted\"{{ busy }}>" ++
        "Accepted only</button></div>", .{ .busy = if (model.busy) " disabled" else "" });
    if (model.busy) try w.writeAll("<p role=\"status\">Loading records…</p>");
    if (model.failed) try w.writeAll("<p class=\"sb-note\">Records unavailable. Retry.</p>");
    if (!model.loaded) return w.writeAll("<p class=\"sb-note\">Choose a rejection cause above " ++
        "or a filter here to load records.</p></section>");
    try html.render(w, "<p class=\"sb-note\">{{ filter }} · {{ dropped }} records dropped " ++
        "by the bounded queue since boot · retention {{ days }} days.</p>", .{
        .filter = filterText(model),
        .dropped = model.dropped,
        .days = model.retention_days,
    });
    try w.writeAll("<div class=\"overflow-x-auto\"><table class=\"table\"><thead><tr>" ++
        "<th scope=\"col\">Time (UTC)</th><th scope=\"col\">Address</th>" ++
        "<th scope=\"col\">Outcome</th><th scope=\"col\">Parameters</th>" ++
        "<th scope=\"col\">Duration</th><th scope=\"col\">Actions</th></tr></thead><tbody>");
    for (model.rows[0..model.count]) |*row| try record(state, row, w);
    if (model.count == 0) try w.writeAll("<tr><td colspan=\"6\">No records match.</td></tr>");
    try w.writeAll("</tbody></table></div>");
    if (model.next != null) try html.render(w, "<button class=\"btn btn-sm\" " ++
        "data-action=\"challenges-records-more\"{{ busy }}>Older records</button>", .{
        .busy = if (model.busy) " disabled" else "",
    });
    try w.writeAll("</section>");
}

fn filterText(model: *const Model) []const u8 {
    if (model.cause) |cause| return causeName(cause);
    if (model.outcome) |outcome| return switch (outcome) {
        .issued => "Issued",
        .accepted => "Accepted",
        .rejected => "Rejected",
    };
    return "All records";
}

pub fn causeName(cause: u8) []const u8 {
    const names = @import("challenges_page.zig").cause_names;
    return if (cause < names.len) names[cause] else "No cause";
}

fn record(state: *const State, row: *const wire.Row, w: *Writer) Writer.Error!void {
    try w.writeAll("<tr><td>");
    try @import("events_page.zig").timestamp(w, row.second);
    try html.render(w, "</td><td><code>{{ ip }}</code> · node {{ node }}</td><td>{{ outcome }}" ++
        "{{ cause }}</td><td>", .{
        .ip = row.ip.slice(),
        .node = row.node,
        .outcome = @tagName(row.outcome),
        .cause = if (row.outcome == .rejected) causeName(row.cause) else "",
    });
    switch (row.algorithm) {
        0 => try w.print("Hashcash, {d} bits", .{row.parameter}),
        else => try w.print("PoSW, depth {d}, {d} openings", .{ row.parameter, row.openings }),
    }
    try w.writeAll("</td><td>");
    if (row.duration_ms) |ms| try w.print("{d} ms", .{ms}) else try w.writeAll("Not recorded");
    try w.writeAll("</td><td>");
    if (state.allows(.manage_policy)) {
        const labels = .{ "Deny address…", "Allow address…" };
        inline for (.{ "deny", "allow" }, labels) |action, label| {
            try html.render(w, "<button class=\"btn btn-sm btn-outline\" " ++
                "data-action=\"events-{{ action }}-{{ ip }}\">{{ label }}</button>", .{
                .action = action,
                .ip = row.ip.slice(),
                .label = label,
            });
        }
    } else try w.writeAll("—");
    try w.writeAll("</td></tr>");
}

test "records decode owned addresses and render durations as not recorded when absent" {
    const t = std.testing;
    var state: State = .{ .phase = .challenges };
    state.csrf = try p.Bytes(64).init("csrf");
    state.role = try p.Bytes(16).init("admin");
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const source =
        \\{"version":1,"retention_days":7,"observed_at":1,"from":0,"until":1,
        \\"dropped_since_boot":3,"rows":[{"id":5,"node":1,"second":100,
        \\"ip":"8.8.12.1","outcome":"rejected","cause":3,"algorithm":1,
        \\"parameter":13,"openings":16,"duration_ms":null}],"next":null}
    ;
    const page = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), source, .{});
    try state.challenge_records.records(page, arena.allocator());
    try t.expectEqual(@as(u8, 1), state.challenge_records.count);
    var buffer: [16384]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&state, &writer);
    const out = writer.buffered();
    try t.expect(std.mem.indexOf(u8, out, "8.8.12.1") != null);
    try t.expect(std.mem.indexOf(u8, out, "Malformed solution") != null);
    try t.expect(std.mem.indexOf(u8, out, "Not recorded") != null);
    try t.expect(std.mem.indexOf(u8, out, "events-deny-8.8.12.1") != null);
    try t.expect(std.mem.indexOf(u8, out, "3 records dropped") != null);
}
