//! Retained challenge window: durable per-minute records summed on the storage owner and
//! rendered with the live page's panels. Missing minutes are shown as coverage, never as
//! zero activity; a window longer than one bounded scan continues from its cursor.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
const page = @import("challenges_page.zig");
pub const max_continuations = 8;

pub const Model = struct {
    summary: ?p.challenge_minutes.Summary = null,
    hours: u16 = 24,
    busy: bool = false,
    failed: bool = false,
    received_at: u64 = 0,
    continuations: u8 = 0,
    /// The partition whose timing histogram the window carries; null selects the default.
    selected: ?u8 = null,
};

pub fn window(state: *const State, hours: u16) struct { from: u64, until: u64 } {
    const until = state.browser_time / 60 -| 1;
    return .{ .from = until -| (@as(u64, hours) * 60 - 1), .until = until };
}

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.challenge_summary;
    try html.render(w, "<section class=\"sb-panel mt-6\" id=\"challenge-window\">" ++
        "<h2>Retained window</h2><form id=\"challenges-period\" class=\"sb-filter-toolbar\">" ++
        "<div class=\"sb-filter-field\"><label for=\"challenge-hours\">Window</label>" ++
        "<select id=\"challenge-hours\" name=\"hours\" class=\"select w-full\">" ++
        "<option value=\"1\"{{ h1 }}>Last hour</option>" ++
        "<option value=\"24\"{{ h24 }}>Last 24 hours</option>" ++
        "<option value=\"168\"{{ h168 }}>Last 7 days</option></select></div>" ++
        "<button class=\"btn\" type=\"submit\"{{ busy }}>Load window</button></form>", .{
        .h1 = if (model.hours == 1) " selected" else "",
        .h24 = if (model.hours == 24) " selected" else "",
        .h168 = if (model.hours == 168) " selected" else "",
        .busy = if (model.busy) " disabled" else "",
    });
    if (model.busy) try html.render(w, "<p role=\"status\">Summing retained minutes…</p>", .{});
    if (model.failed) try html.render(
        w,
        "<p class=\"sb-note\">Retained challenge minutes are unavailable. Retry.</p>",
        .{},
    );
    const summary = model.summary orelse {
        if (!model.busy and !model.failed) try html.render(
            w,
            "<p class=\"sb-note\">Load a window to sum durable challenge minutes.</p>",
            .{},
        );
        return html.render(w, "</section>", .{});
    };
    try coverage(state, &summary, w);
    try html.render(w, "<div class=\"sb-panels\"><section class=\"sb-panel mt-6\">" ++
        "<h2>Window flow</h2><table class=\"table\"><tbody>", .{});
    try page.row(w, "Issued", summary.totals.issued);
    try page.row(w, "Submitted", summary.totals.submitted);
    try page.row(w, "Accepted", summary.totals.accepted);
    try page.row(w, "Rejected", summary.totals.rejected);
    try html.render(w, "</tbody></table><p class=\"sb-note\">Sums of per-minute deltas across " ++
        "contributing nodes and boots. Retries and cross-window solutions prevent a cohort " ++
        "conversion rate.</p></section>", .{});
    try page.rejection(&summary.totals, false, w);
    try html.render(w, "</div><div class=\"sb-panels\">", .{});
    try page.timing(&summary.totals, model.busy, "challenges-window-bin", w);
    try html.render(w, "</div></section>", .{});
}

fn coverage(
    state: *const State,
    summary: *const p.challenge_minutes.Summary,
    w: *Writer,
) Writer.Error!void {
    const c = &summary.coverage;
    const expected = c.until -| c.from + 1;
    try html.render(w, "<p class=\"sb-note\">{{ rows }} recorded minutes ({{ complete }} " ++
        "complete) of {{ expected }} in the window; unrecorded minutes are not zero activity. " ++
        "Retention {{ days }} days. Received {{ age }} seconds ago.</p>", .{
        .rows = c.rows,
        .complete = c.complete_rows,
        .expected = expected,
        .days = c.retention_days,
        .age = state.browser_time -| state.challenge_summary.received_at,
    });
    if (!c.finished) try html.render(
        w,
        "<p class=\"sb-note\">The window exceeds the bounded scan; totals cover the newest " ++
            "recorded minutes only.</p>",
        .{},
    );
    if (c.bins_dropped != 0) try html.render(w, "<p class=\"sb-note\">{{ dropped }} " ++
        "partition observations were dropped by the eight-partition minute bound.</p>", .{
        .dropped = c.bins_dropped,
    });
    if (c.retention_changed) try html.render(
        w,
        "<p class=\"sb-note\">Retention shortened this window.</p>",
        .{},
    );
}
