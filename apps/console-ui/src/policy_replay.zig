//! Replay summary under the rule editor: how many retained events the draft would have
//! matched, how many were inconclusive, and the first rows.
const std = @import("std");
const html = @import("html");
const Writer = std.Io.Writer;
const string = @import("events_state.zig").string;
const field = @import("events_state.zig").field;

pub fn render(w: *Writer, source: []const u8) Writer.Error!void {
    if (source.len == 0) return;
    var memory: [16384]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        source,
        .{},
    ) catch return;
    try html.render(w, "<section id=\"policy-replay\" tabindex=\"-1\" class=\"mt-4\">" ++
        "<h3>Replay of recent events</h3><p role=\"status\">Would have matched {{ matched }} " ++
        "of {{ total }} recent events ({{ inconclusive }} inconclusive: retained inputs were " ++
        "truncated or had a query or body the replay cannot reproduce).</p>" ++
        "<div class=\"overflow-x-auto\"><table " ++
        "class=\"table table-sm\"><thead><tr><th>Address</th><th>Path</th><th>Decision</th>" ++
        "<th>Rule</th><th>Evidence</th></tr></thead><tbody>", .{
        .matched = number(parsed, "matched"),
        .total = number(parsed, "total"),
        .inconclusive = number(parsed, "inconclusive"),
    });
    const rows = field(parsed, "rows") orelse .null;
    if (rows == .array) for (rows.array.items) |row| {
        const conclusive = field(row, "conclusive") orelse .null;
        const matched = field(row, "matched") orelse .null;
        try html.render(w, @embedFile("snippets/policy-replay-row.html"), .{
            .ip = string(row, "ip"),
            .path = string(row, "path"),
            .action = string(row, "action"),
            .rule = string(row, "rule"),
            .verdict = verdict(matched == .bool and matched.bool, conclusive == .bool and
                conclusive.bool),
        });
    };
    try html.render(w, "</tbody></table></div></section>", .{});
}

fn verdict(matched: bool, conclusive: bool) []const u8 {
    if (matched) return if (conclusive) "matched" else "matched (inconclusive)";
    return if (conclusive) "not matched" else "inconclusive";
}

fn number(value: std.json.Value, key: []const u8) i64 {
    const item = field(value, key) orelse return 0;
    return if (item == .integer) item.integer else 0;
}
