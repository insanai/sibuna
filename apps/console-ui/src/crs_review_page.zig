//! The comparison identifies saved immutable sources, not runtime publication.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const Model = @import("crs_state.zig").Model;
const W = std.Io.Writer;

pub fn render(model: *const Model, w: *W) W.Error!void {
    try w.writeAll("<h3 class=\"mt-4\">Rule changes</h3>");
    const result = model.review_result orelse {
        if (model.busy == .review_submit or model.review_job != null) {
            try w.writeAll("<p role=\"status\">Preparing the rule comparison. " ++
                "Selection is available after it completes.</p>");
        } else {
            try w.writeAll("<p role=\"status\">Compare the verified candidate again to " ++
                "reload its rule and exclusion details.</p><button class=\"btn btn-sm\" " ++
                "type=\"button\" data-action=\"crs-compare\">Compare again</button>");
        }
        return;
    };
    if (result.state == .queued or result.state == .running) {
        try w.writeAll("<p role=\"status\">Comparing verified rules on the private worker. " ++
            "Active protection is unchanged.</p>");
        return;
    }
    if (result.diagnostic) |diagnostic|
        try @import("crs_diagnostic_page.zig").render(w, diagnostic);
    if (result.failure) |failure| try html.render(
        w,
        "<p class=\"sb-error\" role=\"status\">Comparison refused: {{ cause }}. " ++
            "Refresh the saved revision and source before retrying.</p>",
        .{ .cause = failure.slice() },
    );
    if (result.comparison) |report| {
        try html.render(w, "<p>Compared with saved revision {{ revision }}. " ++
            "{{ added }} added · {{ removed }} removed · {{ modified }} modified · " ++
            "{{ reordered }} reordered · {{ unchanged }} unchanged.</p>", .{
            .revision = result.expected_revision,
            .added = report.added,
            .removed = report.removed,
            .modified = report.modified,
            .reordered = report.reordered,
            .unchanged = report.unchanged,
        });
        try exclusions(w, report);
        try changes(w, report);
        try @import("crs_exclusion_page.zig").render(model, w);
    }
    if (!model.reviewReady()) try w.writeAll("<p class=\"sb-note\">This comparison does not " ++
        "confirm the current candidate and saved revision. Refresh and compare again.</p>");
    try w.writeAll("<button class=\"btn btn-sm mt-3\" type=\"button\" " ++
        "data-action=\"crs-compare\">Compare again</button>");
}

fn exclusions(w: *W, report: p.crs_tasks.review.Report) W.Error!void {
    try html.render(w, "<p>Configured target exclusions: {{ before }} → {{ after }}. " ++
        "Runtime exclusion entries: {{ runtime_before }} → {{ runtime_after }}.</p>" ++
        "<p class=\"sb-note\">Runtime exclusions apply when their controlling rules match. " ++
        "These counts describe configuration, not the coverage of every request. " ++
        "Removed rules and exclusions may reduce protection; review the operator rules " ++
        "and test application traffic before selection.</p>", .{
        .before = report.before.target_exclusions,
        .after = report.after.target_exclusions,
        .runtime_before = report.before.runtime_exclusions,
        .runtime_after = report.after.runtime_exclusions,
    });
}

fn changes(w: *W, report: p.crs_tasks.review.Report) W.Error!void {
    try w.writeAll("<div class=\"overflow-x-auto mt-3\"><table class=\"table\">" ++
        "<thead><tr><th>Rule</th><th>Change</th><th>Order changed</th></tr></thead><tbody>");
    for (report.changes[0..report.count]) |item| {
        const change = item.?;
        try html.render(w, "<tr><td>{{ id }}</td><td>{{ kind }}</td>" ++
            "<td>{{ moved }}</td></tr>", .{
            .id = change.id,
            .kind = @tagName(change.kind),
            .moved = if (change.moved) "yes" else "no",
        });
    }
    if (report.count == 0) try w.writeAll("<tr><td colspan=\"3\">" ++
        "No rule-definition or order changes.</td></tr>");
    try html.render(w, "</tbody></table></div><p>{{ count }} changed rules shown · " ++
        "{{ omitted }} additional rows omitted.</p>", .{
        .count = report.count,
        .omitted = report.omitted,
    });
}

test "comparison selection binds candidate, baseline, kind and saved revision" {
    const t = std.testing;
    const State = @import("state.zig").State;
    const state = try t.allocator.create(State);
    defer t.allocator.destroy(state);
    state.* = .{};
    @import("crs_fixture.zig").configure(state, true, false);
    try state.crs.review_result.?.validate();
    try t.expect(state.crs.reviewReady());
    state.crs.review_result.?.baseline.?.operator_digest = try p.Bytes(64).init("wrong");
    try t.expect(!state.crs.reviewReady());
    @import("crs_fixture.zig").configure(state, true, false);
    state.crs.review_result.?.kind = .sample;
    try t.expect(!state.crs.reviewReady());
    state.crs.review_result.?.kind = .review;
    state.crs.review_result.?.expected_revision = 3;
    try t.expect(!state.crs.reviewReady());
    @import("crs_fixture.zig").configure(state, true, false);
    state.crs.review_result.?.state = .queued;
    try t.expect(state.crs.reviewPending() and !state.crs.reviewReady());
    var bytes: [32768]u8 = undefined;
    var writer: W = .fixed(&bytes);
    try @import("crs_page.zig").render(state, &writer);
    const disabled = std.mem.indexOf(u8, writer.buffered(), "data-action=\"crs-select\" disabled");
    try t.expect(disabled != null);
}
