//! Explain template previews and actual net bucket changes without expanded request values.
const std = @import("std");
const html = @import("html");
const p = @import("console_protocol");
const api = p.incident_crs.api;
const Model = @import("incident_crs_controller.zig").Model;
const W = std.Io.Writer;

pub fn render(model: *const Model, id: u64, w: *W) W.Error!void {
    if (model.id != id or !model.loaded) {
        if (model.id == id and model.busy)
            return w.writeAll("<p role=\"status\">Loading CRS rule details…</p>");
        if (model.id == id and model.failed)
            try w.writeAll("<p role=\"status\">Rule details unavailable. Try again.</p>");
        const template = "<p><button class=\"btn btn-sm\" " ++
            "data-action=\"events-crs-{{ id }}\">Show CRS rule details</button></p>";
        return html.render(w, template, .{ .id = id });
    }
    try w.writeAll("<section class=\"mt-4\" aria-labelledby=\"incident-crs-heading\">" ++
        "<h3 id=\"incident-crs-heading\" tabindex=\"-1\">CRS rule details</h3>");
    if (model.detail) |*detail| {
        try details(detail, w);
    } else try w.writeAll("<p>Not recorded for this incident.</p>");
    try w.writeAll("</section>");
}

pub fn details(detail: *const api.Detail, w: *W) W.Error!void {
    try w.writeAll("<h4>Unexpanded rule templates</h4><p class=\"sb-note\">" ++
        "Values substituted during inspection are not retained.</p><dl><dt>Message</dt><dd>");
    if (detail.message) |*message| {
        try preview(message, w);
    } else try w.writeAll("No message action recorded.");
    try w.writeAll("</dd><dt>Tags</dt><dd><ul>");
    for (detail.tags[0..detail.tag_count]) |tag| {
        try w.writeAll("<li>");
        try preview(&tag.?, w);
        try w.writeAll("</li>");
    }
    if (detail.tag_count == 0) try w.writeAll("<li>No tag actions recorded.</li>");
    try w.writeAll("</ul></dd></dl>");
    if (detail.omitted_tags != 0) {
        try html.render(w, "<p>{{ count }} additional tag templates omitted.</p>", .{
            .count = detail.omitted_tags,
        });
    }
    try w.writeAll("<h4 class=\"mt-4\">Net bucket score change</h4>");
    if (detail.score) |*score| {
        try scoreTable(score, w);
    } else try w.writeAll("<p>No score total attached to this finding. " ++
        "Repeated findings share one rule total; a rule may also write no score.</p>");
}

fn preview(value: anytype, w: *W) W.Error!void {
    const bytes = value.slice();
    const readable = std.unicode.utf8ValidateSlice(bytes) and
        std.mem.indexOfAny(u8, bytes, "\x00\r\n") == null;
    const hex = std.fmt.bytesToHex(&value.data, .lower);
    try html.render(w, "<code class=\"break-all\">{{ value }}</code>", .{
        .value = if (readable) bytes else hex[0 .. bytes.len * 2],
    });
    if (!readable) try w.writeAll(" (hexadecimal bytes)");
    if (value.bytes > bytes.len) {
        try html.render(w, " (first {{ shown }} of {{ total }} bytes)", .{
            .shown = bytes.len,
            .total = value.bytes,
        });
    }
}

fn scoreTable(score: *const api.Contribution, w: *W) W.Error!void {
    const introduction = "<p class=\"sb-note\">" ++
        "Actual committed change for this rule and phase, " ++
        "including repeated matches. Final blocking and detection scores are separate.</p>" ++
        "<div class=\"overflow-x-auto\"><table class=\"table table-sm\">" ++
        "<caption class=\"sr-only\">Net anomaly changes " ++
        "by direction and paranoia level</caption>" ++
        "<thead><tr><th>Bucket</th><th>Writes</th><th>Net change</th></tr></thead><tbody>";
    try w.writeAll(introduction);
    for (score.buckets, 0..) |bucket, index| {
        const row = "<tr><th>{{ direction }} PL{{ level }}</th><td>{{ writes }}</td><td>";
        try html.render(w, row, .{
            .direction = if (index < 4) "Inbound" else "Outbound",
            .level = index % 4 + 1,
            .writes = bucket.writes,
        });
        if (bucket.writes == 0) {
            try w.writeAll("No writes");
        } else if (bucket.delta) |delta| {
            try html.render(w, "{{ delta }}", .{ .delta = delta });
        } else try w.writeAll("Unknown numeric change");
        try w.writeAll("</td></tr>");
    }
    try w.writeAll("</tbody></table></div>");
}
