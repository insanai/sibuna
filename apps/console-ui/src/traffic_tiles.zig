//! Dashboard and kiosk summaries share exact counters, semantic decision colours and
//! the same observed outcome series. Boot totals are labelled separately from rates.
const std = @import("std");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
const html = @import("html");
const sparkline = @import("outcome_sparkline.zig");

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    try html.render(w, "<section class=\"sb-tiles\" aria-label=\"Request summary\">", .{});
    const labels = [_][]const u8{
        "Requests", "Admitted",   "Challenged", "Policy denied", "Banned", "Rate limited",
        "Other",    "Origin 4xx", "Origin 5xx",
    };
    const keys = .{
        "requests",   "admitted",   "challenged", "denied", "banned", "rate_limited", "other",
        "origin_4xx", "origin_5xx",
    };
    inline for (keys, labels) |key, label| {
        try html.render(
            w,
            "<article class=\"sb-tile {{ tone }}\"><span class=\"sb-subtitle\">{{ v0 " ++
                "}}</span><strong>",
            .{
                .v0 = label,
                .tone = sparkline.tone(@field(sparkline.Metric, key)),
            },
        );
        if (state.stats) |stats| {
            const origin = comptime std.mem.startsWith(u8, key, "origin_");
            const separated = comptime std.mem.eql(u8, key, "denied") or
                std.mem.eql(u8, key, "banned") or std.mem.eql(u8, key, "rate_limited") or
                std.mem.eql(u8, key, "other");
            if (origin and stats.proxy_mode != .reverse_proxy)
                try w.writeAll(
                    "Not observed",
                )
            else if (separated and stats.outcomes_version != 1)
                try w.writeAll(
                    "Not recorded",
                )
            else
                try @import("count_display.zig").write(w, @field(stats, key));
        } else try w.writeAll(
            "—",
        );
        try w.writeAll("</strong>");
        try sparkline.render(state, w, @field(sparkline.Metric, key), label);
        try w.writeAll("</article>");
    }
    try html.render(w, "</section>", .{});
    if (state.stats) |stats| if (stats.proxy_mode == .forward_auth) try w.writeAll(
        "<p class=\"sb-note\">Forward auth: admitted counts authorization approvals. " ++
            "The ingress carries uploads, WebSockets and origin responses. " ++
            "Bodies omitted from authorization requests are not inspected.</p>",
    );
    try html.render(w, "<p class=\"sb-note\">Outcomes count parsed external requests once. " ++
        "Banned counts requests, not distinct addresses. Origin 4xx/5xx overlap admitted " ++
        "traffic. Counter loads are not simultaneous.</p>", .{});
}
