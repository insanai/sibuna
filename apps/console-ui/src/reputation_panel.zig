//! IP groups: console-managed reputation prefixes with their provenance, plus the country
//! builder. Rendered under the applied policies on the policies page.
const std = @import("std");
const html = @import("html");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
const string = @import("events_state.zig").string;
const field = @import("events_state.zig").field;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    if (!state.allows(.manage_policy)) return;
    const model = &state.reputation;
    const busy = if (model.busy) " disabled" else "";
    try html.render(w, "<section class=\"sb-panel\"><h2>IP groups</h2><p class=\"sb-note\">" ++
        "Reputation prefixes the console manages beside the data plane's own bans. Deny " ++
        "prefixes refuse before any rule; allow prefixes bypass rules. Revision {{ revision }}" ++
        " · {{ nodes }} trie nodes of 8,192.</p><div class=\"overflow-x-auto\"><table " ++
        "class=\"table\"><thead><tr><th>Prefix</th><th>Action</th><th>Expires</th>" ++
        "<th>Source</th><th>Note</th><th>Hits</th><th></th></tr></thead><tbody>", .{
        .revision = model.committed.slice(),
        .nodes = nodes(model.page()),
    });
    try rows(model.page(), busy, w);
    try html.render(w, "</tbody></table></div><div class=\"flex flex-wrap gap-2 mt-3\">" ++
        "<button class=\"btn btn-sm\" data-action=\"reputation-refresh\"{{ busy }}>" ++
        "{{ load }}</button><button class=\"btn btn-sm\" data-action=\"reputation-next\"" ++
        "{{ next }}>Next page</button></div>", .{
        .busy = busy,
        .load = if (model.loaded) "Reload" else "Load IP groups",
        .next = if (model.busy or model.next.len == 0) " disabled" else "",
    });
    try html.render(w, @embedFile("snippets/reputation-form.html"), .{ .busy = busy });
    if (model.undo.expires_at > state.browser_time) try html.render(w, "<button " ++
        "class=\"btn btn-outline\" type=\"button\" data-action=\"reputation-undo\">Undo " ++
        "({{ left }} s)</button>", .{ .left = model.undo.expires_at - state.browser_time });
    try html.render(w, "</div></form>", .{});
    try html.render(w, @embedFile("snippets/country-form.html"), .{
        .busy = busy,
        .apply = if (model.busy or model.country_review.len == 0) " disabled" else "",
        .prefixes = model.summary_prefixes,
        .country = model.country.slice(),
        .action = model.country_action.slice(),
        .next = if (model.busy or model.country_next == null) " disabled" else "",
    });
    try countrySummary(model.summary(), w);
    try html.render(w, "</form>", .{});
    try html.render(w, "</section>", .{});
}

fn nodes(page: []const u8) u64 {
    var memory: [16384]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), page, .{}) catch
        return 0;
    const value = field(parsed, "nodes") orelse return 0;
    return if (value == .integer and value.integer >= 0) @intCast(value.integer) else 0;
}

fn rows(page: []const u8, busy: []const u8, w: *Writer) Writer.Error!void {
    var memory: [16384]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), page, .{}) catch
        return;
    const list = field(parsed, "rows") orelse return;
    if (list != .array) return;
    for (list.array.items) |row| {
        const score = field(row, "score") orelse .null;
        const denied = score != .integer or score.integer < 0;
        const expires = string(row, "banned_until");
        try html.render(w, @embedFile("snippets/reputation-row.html"), .{
            .prefix = string(row, "prefix"),
            .action = if (denied) "deny" else "allow",
            .expires = if (expires.len == 0) "never" else expires,
            .source = string(row, "source"),
            .note = string(row, "note"),
            .hits = string(row, "hits"),
            .busy = busy,
        });
    }
}

fn countrySummary(summary: []const u8, w: *Writer) Writer.Error!void {
    if (summary.len == 0) return;
    var memory: [8192]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        summary,
        .{},
    ) catch return;
    const sample = field(parsed, "sample") orelse .null;
    const first = if (sample == .array and sample.array.items.len != 0)
        (if (sample.array.items[0] == .string) sample.array.items[0].string else "")
    else
        "";
    try html.render(w, "<p role=\"status\" class=\"sb-note mt-3\">{{ prefixes }} prefixes; " ++
        "{{ added }} added, {{ removed }} removed, {{ retained }} retained. " ++
        "trie nodes {{ before }} → {{ after }}; {{ overlaps }} already listed; " ++
        "first {{ first }}; " ++
        "generation {{ old }} → {{ generation }}.</p>", .{
        .prefixes = number(parsed, "prefixes"),
        .added = number(parsed, "added"),
        .removed = number(parsed, "removed"),
        .retained = number(parsed, "retained"),
        .old = string(parsed, "previous_generation"),
        .before = number(parsed, "nodes_before"),
        .after = number(parsed, "nodes_after"),
        .overlaps = number(parsed, "overlaps"),
        .first = first,
        .generation = string(parsed, "generation")[0..@min(string(parsed, "generation").len, 12)],
    });
    try removedPrefixes(parsed, w);
    try changeTable(parsed, w);
}

fn removedPrefixes(value: std.json.Value, w: *Writer) Writer.Error!void {
    const items = field(value, "removed_sample") orelse return;
    if (items != .array or items.array.items.len == 0) return;
    try w.writeAll("<p>First obsolete prefixes to remove (up to eight):</p><ul>");
    for (items.array.items) |row| {
        if (row != .string) continue;
        try html.render(w, "<li>{{ prefix }}</li>", .{ .prefix = row.string });
    }
    try w.writeAll("</ul>");
}

fn changeTable(value: std.json.Value, w: *Writer) Writer.Error!void {
    const items = field(value, "changes") orelse return;
    if (items != .array) return;
    try w.writeAll("<table class=\"table\"><caption>Reviewed prefix changes " ++
        "(eight per page)</caption><thead><tr><th>Prefix</th><th>Change</th></tr>" ++
        "</thead><tbody>");
    for (items.array.items) |row| try html.render(
        w,
        "<tr><td>{{ prefix }}</td><td>{{ kind }}</td></tr>",
        .{ .prefix = string(row, "prefix"), .kind = string(row, "kind") },
    );
    try w.writeAll("</tbody></table>");
}

fn number(value: std.json.Value, key: []const u8) u16 {
    const item = field(value, key) orelse return 0;
    if (item != .integer or item.integer < 0 or item.integer > 65535) return 0;
    return @intCast(item.integer);
}
