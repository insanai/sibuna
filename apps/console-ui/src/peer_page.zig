//! Ephemeral peer observations remain separate from replicated membership and probe health.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;

pub fn render(state: *const State, writer: *Writer) Writer.Error!void {
    const peers = &state.nodes.peers;
    if (!peers.loaded) return;
    try html.render(
        writer,
        "<section class=\"sb-panel sb-users\" " ++
            "aria-labelledby=\"peer-telemetry\"><h2 id=\"peer-telemetry\">" ++
            "Live peer telemetry</h2>",
        .{},
    );
    if (peers.direct_count == 0) try html.render(
        writer,
        "<p>No management peers configured.</p>",
        .{},
    );
    for (peers.direct[0..peers.direct_count]) |peer|
        try row(writer, peer, state.browser_time -| peers.received_at);
    try html.render(writer, "</section>", .{});
}

fn row(writer: *Writer, peer: p.nodes.Peer, elapsed: u64) Writer.Error!void {
    var buffers: [6][20]u8 = undefined;
    const age = if (peer.age_seconds) |value| value +| elapsed else null;
    const stale = if (age) |value| value >= 10 else false;
    try html.render(writer, @embedFile("snippets/peer-observation.html"), .{
        .node = peer.node,
        .status = if (stale and peer.status == .current) "stale" else @tagName(peer.status),
        .age = optional(&buffers[0], age),
        .skew = optional(&buffers[1], peer.clock_skew_seconds),
        .requests = optional(&buffers[2], peer.requests),
        .loss = optional(&buffers[3], peer.sample_loss),
        .memory = optional(&buffers[4], peer.rss_kib),
        .cpu = optional(&buffers[5], if (peer.cpu_permille) |value| @as(u64, value) else null),
        .boot = if (peer.boot) |boot| boot.slice() else "not observed",
        .resets = peer.resets,
        .sequence = peer.sequence,
        .watermark = peer.watermark,
    });
}

fn optional(buffer: *[20]u8, value: ?u64) []const u8 {
    return if (value) |number|
        std.fmt.bufPrint(buffer, "{d}", .{number}) catch unreachable
    else
        "not observed";
}
