//! Stream freshness is separate from a historical page's fixed query boundary.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const State = @import("state.zig").State;

pub fn render(state: *const State, topic: p.Topic, w: *std.Io.Writer) std.Io.Writer.Error!void {
    const value = state.live.topics[@backingInt(topic)];
    try html.render(w, "<section class=\"sb-note my-4\" aria-label=\"Live updates\">" ++
        "<p>{{ status }} · Last update {{ age }} seconds ago.</p>", .{
        .status = status(value),
        .age = if (value.received_at == 0) 0 else state.browser_time -| value.received_at,
    });
    if (topic == .events or topic == .audit) {
        try html.render(w, "<p>{{ count }} recent summaries newer than this page. " ++
            "Rows stay in place while you read. <button class=\"btn btn-sm\" " ++
            "data-action=\"{{ action }}\">Load latest records</button></p>" ++
            "<p>At most 64 summaries retained in the live feed; this is not a total count. " ++
            "{{ gaps }} unavailable source IDs, including expired history. " ++
            "Storage observation age: {{ age }} seconds.</p>", .{
            .count = value.newer,
            .action = if (topic == .events) "events-refresh" else "audit-refresh",
            .gaps = value.missing_ids,
            .age = if (value.observed_at == 0) 0 else state.browser_time -| value.observed_at,
        });
    }
    if (topic == .policy and value.available) try html.render(
        w,
        "<p>Current committed revision {{ committed }}; applied revision {{ applied }}. " ++
            "Refresh to review newer policy. An open draft keeps its reviewed revision.</p>",
        .{ .committed = state.live.committed, .applied = state.live.applied },
    );
    try w.writeAll("</section>");
}

pub fn status(value: @import("live_state.zig").Observation) []const u8 {
    if (value.received_at == 0) return "Waiting for live updates";
    if (value.stale) return "Disconnected / stale";
    if (!value.available) return "Observations unavailable";
    return "Live";
}
