//! Reuse the incident template and score rendering; private results add bounded pagination.
const std = @import("std");
const html = @import("html");
const Model = @import("crs_state.zig").Model;
const W = std.Io.Writer;

pub fn render(model: *const Model, w: *W) W.Error!void {
    const result = model.test_result orelse return;
    const report = result.report orelse return;
    if (result.state != .complete or report.event_count == 0) return;
    try w.writeAll("<section class=\"sb-panel mt-4\">" ++
        "<h2 id=\"crs-test-details-heading\" tabindex=\"-1\">Private rule details</h2>");
    if (model.test_details_expired) {
        try w.writeAll("<p>Details expired. Run the sample again to inspect them.</p>");
    } else if (model.test_details) |page| {
        try html.render(w, "<p>{{ first }}–{{ last }} of {{ total }} findings</p>", .{
            .first = @as(u16, page.page.offset) + 1,
            .last = @as(u16, page.page.offset) + page.page.count,
            .total = page.page.total,
        });
        for (page.page.rows[0..page.page.count]) |row| {
            const detail = row.?;
            try html.render(w, "<article class=\"border-b border-base-300 py-4\">" ++
                "<h3>Rule {{ rule }} · Phase {{ phase }}</h3>", .{
                .rule = detail.rule_id,
                .phase = detail.phase,
            });
            try @import("crs_detail_page.zig").details(&detail, w);
            try w.writeAll("</article>");
        }
        try controls(model, page.page.next != null, w);
    } else {
        if (model.busy == .test_details) {
            try w.writeAll("<p role=\"status\">Loading safe rule details…</p>");
        } else try html.render(w, "<button class=\"btn btn-sm\" " ++
            "data-action=\"crs-test-details-retry\">Show rule details</button>", .{});
    }
    try w.writeAll("</section>");
}

fn controls(model: *const Model, next: bool, w: *W) W.Error!void {
    const busy = model.busy != .idle;
    try html.render(w, "<div class=\"flex flex-wrap gap-3 mt-4\">" ++
        "<button class=\"btn btn-sm\" data-action=\"crs-test-details-previous\"" ++
        "{{ previous }}>Previous details</button>" ++
        "<button class=\"btn btn-sm\" data-action=\"crs-test-details-next\"" ++
        "{{ next }}>Next details</button></div>", .{
        .previous = if (busy or model.test_details_offset == 0) " disabled" else "",
        .next = if (busy or !next) " disabled" else "",
    });
}
