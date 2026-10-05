//! Configuration names are escaped and labelled; conditional coverage is not universal.
const std = @import("std");
const html = @import("html");
const p = @import("console_protocol");
const api = p.crs_tasks.review.exclusions;
const Model = @import("crs_state.zig").Model;
const W = std.Io.Writer;

pub fn render(model: *const Model, w: *W) W.Error!void {
    if (!model.reviewReady()) return;
    try w.writeAll("<h4 id=\"crs-exclusions-heading\" class=\"mt-4\" tabindex=\"-1\" " ++
        "aria-describedby=\"crs-exclusions-count\">Excluded protection</h4>" ++
        "<p>Static exclusions skip the listed fields. Conditional exclusions apply after " ++
        "their controlling rule matches; a rule-wide exclusion skips all its targets.</p>" ++
        "<div class=\"flex flex-wrap gap-2 mt-3\" role=\"group\" " ++
        "aria-label=\"Exclusion source\">");
    const busy = model.busy != .idle;
    try button(w, "before", "Current exclusions", model.exclusion_side == .before, busy);
    try button(w, "after", "Candidate exclusions", model.exclusion_side == .after, busy);
    try w.writeAll("</div>");
    const output = model.exclusion_page orelse {
        try w.writeAll("<p role=\"status\">Exclusion details have not loaded.</p>");
        try button(w, "retry", "Load exclusion details", false, model.busy != .idle);
        return;
    };
    const page = output.page;
    try w.writeAll("<ul class=\"grid gap-3 mt-3\" aria-label=\"Excluded protection\">");
    for (page.rows[0..page.count]) |item| try row(w, item.?);
    try w.writeAll("</ul>");
    if (page.count == 0) try w.writeAll("<p>No configured exclusions in this source.</p>");
    try html.render(w, "<p id=\"crs-exclusions-count\">" ++
        "{{ start }}–{{ end }} of {{ total }} exclusions.</p>", .{
        .start = if (page.count == 0) @as(u32, 0) else page.offset + 1,
        .end = page.offset + @as(u32, @intCast(page.count)),
        .total = page.total,
    });
    try w.writeAll("<div class=\"flex flex-wrap gap-2\">");
    const first = page.offset == 0;
    try button(w, "previous", "Previous exclusions", false, busy or first);
    try button(w, "next", "Next exclusions", false, model.busy != .idle or page.next == null);
    try w.writeAll("</div>");
}

fn button(
    w: *W,
    action: []const u8,
    label: []const u8,
    selected: bool,
    disabled: bool,
) W.Error!void {
    try html.render(w, "<button class=\"btn btn-sm\" type=\"button\" " ++
        "data-action=\"crs-exclusions-{{ action }}\"", .{ .action = action });
    if (std.mem.eql(u8, action, "before") or std.mem.eql(u8, action, "after"))
        try html.render(w, " aria-pressed=\"{{ pressed }}\"", .{ .pressed = selected });
    if (disabled) try w.writeAll(" disabled");
    try html.render(w, ">{{ label }}</button>", .{ .label = label });
}

fn row(w: *W, item: api.Row) W.Error!void {
    try w.writeAll("<li class=\"border border-base-300 rounded-box p-3\"><p>");
    if (item.selector == .tag) {
        try w.writeAll("Rules tagged ");
        try text(w, item.tag.?);
    } else if (item.first == item.last) {
        try html.render(w, "Rule {{ id }}", .{ .id = item.first });
    } else try html.render(w, "Rules {{ first }}–{{ last }}", .{
        .first = item.first,
        .last = item.last,
    });
    if (item.scope == .conditional_rule) {
        try w.writeAll(" · skip all targets");
    } else {
        var collection: [32]u8 = undefined;
        const name = item.collection.?.slice();
        for (name, collection[0..name.len]) |byte, *output| output.* = std.ascii.toUpper(byte);
        const field = .{ .collection = collection[0..name.len] };
        try html.render(w, " · skip {{ collection }}", field);
        switch (item.selection) {
            .exact, .pattern => {
                try w.writeAll(if (item.selection == .exact) ":" else " fields matching ");
                try text(w, item.key.?);
                if (item.selection == .pattern) {
                    try w.writeAll(" (regex; case-insensitive by default)");
                }
            },
            .all => try w.writeAll(" · all fields"),
            .xml_elements => try w.writeAll(" · XML elements"),
            .xml_attributes => try w.writeAll(" · XML attributes"),
            .none => unreachable,
        }
    }
    const configured = item.scope == .static_target;
    const timing = if (configured) "Configured on rule" else "After matching rule";
    var link: [32]u8 = undefined;
    const continuation = std.fmt.bufPrint(&link, "chain link {d}", .{item.chain_link}) catch
        unreachable;
    const position = if (item.chain_link == 0) "root" else continuation;
    try html.render(w, "</p><p class=\"sb-note\">{{ timing }} {{ id }}, phase {{ phase }}, " ++
        "{{ link }}.</p></li>", .{
        .timing = timing,
        .id = item.rule_id,
        .phase = item.phase,
        .link = position,
    });
}

fn text(w: *W, value: api.Text) W.Error!void {
    var bytes: [api.preview_bytes]u8 = undefined;
    const preview = std.fmt.hexToBytes(&bytes, value.hex.slice()) catch unreachable;
    const readable = std.unicode.utf8ValidateSlice(preview) and
        std.mem.indexOfAny(u8, preview, "\x00\r\n") == null;
    try html.render(w, "<code class=\"break-all\">{{ name }}</code>", .{
        .name = if (readable) preview else value.hex.slice(),
    });
    if (!readable) try w.writeAll(" (hexadecimal bytes)");
    if (value.bytes > preview.len) {
        const lengths = .{ .shown = preview.len, .total = value.bytes };
        try html.render(w, " (first {{ shown }} of {{ total }} bytes; " ++
            "inspect the full configured selector)", lengths);
    }
    if (!readable or value.bytes > preview.len) {
        const identity = .{ .digest = value.digest.slice() };
        try html.render(w, "<span class=\"block break-all sb-note\">" ++
            "SHA-256: {{ digest }}</span>", identity);
    }
}

test "exclusion descriptions escape configured names and mark long or binary previews" {
    const t = std.testing;
    var bytes: [4096]u8 = undefined;
    var writer: W = .fixed(&bytes);
    try text(&writer, api.Text.init("<script>alert(1)</script>"));
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "<script>") == null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "&lt;script&gt;") != null);
    writer.end = 0;
    try text(&writer, api.Text.init(&@as([1024]u8, @splat(0xff))));
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "hexadecimal bytes") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "first 256 of 1024 bytes") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "SHA-256:") != null);
}
