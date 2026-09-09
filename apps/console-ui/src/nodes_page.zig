const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const html = @import("html");
const Writer = std.Io.Writer;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.nodes;
    const busy = model.busy != .idle;
    try html.render(w, @embedFile("snippets/nodes-header.html"), .{
        .busy = if (busy) " disabled" else "",
    });
    if (!state.fullAccess()) return html.render(w, "<p>Sign in to view nodes.</p></main>", .{});
    if (state.message.len != 0) try html.render(
        w,
        "<p id=\"console-message\" tabindex=\"-1\" role=\"status\">{{ message }}</p>",
        .{ .message = state.message.slice() },
    );
    if (model.status) |node| {
        try status(state, node, w);
    } else try html.render(w, "<p role=\"status\">{{ status }}</p>", .{
        .status = if (busy)
            "Loading node state…"
        else
            "Node state unavailable. Refresh to retry.",
    });
    if (model.pending) |pending| try confirmation(state, pending.kind, w);
    if (model.receipt) |receipt| try result(receipt, w);
    try html.render(w, "</main>", .{});
}

fn status(state: *const State, node: p.nodes.Status, w: *Writer) Writer.Error!void {
    const model = &state.nodes;
    const fresh = model.fresh(state.browser_time);
    try html.render(w, @embedFile("snippets/nodes-status.html"), .{
        .node = node.node,
        .admission = if (node.draining) "Draining" else "Accepting connections",
        .freshness = if (fresh) "Current" else "Stale; refresh before changes",
        .age = state.browser_time -| node.observed_at,
        .connections = node.connections,
        .bans = node.active_ban_entries,
        .committed = node.committed,
        .applied = node.applied,
        .revision = node.control_revision,
        .uptime = node.uptime_ms / 1000,
        .boot = node.boot.slice(),
        .pending = if (node.completion_pending)
            "A local effect is awaiting durable completion. New commands are paused."
        else
            "Status refreshes every five seconds while no confirmation is open.",
    });
    if (state.allows(.control_node)) {
        const disabled = !fresh or model.busy != .idle or model.pending != null or
            node.completion_pending or node.control_revision >= std.math.maxInt(i64);
        try html.render(w, @embedFile("snippets/nodes-controls.html"), .{
            .drain = if (disabled or node.draining) " disabled" else "",
            .@"resume" = if (disabled or !node.draining) " disabled" else "",
            .clear = if (disabled or node.active_ban_entries == 0) " disabled" else "",
        });
    } else try html.render(w, "<p>An operator or administrator can change this node.</p>", .{});
    try html.render(w, "</section>", .{});
}

fn confirmation(state: *const State, kind: p.nodes.Kind, w: *Writer) Writer.Error!void {
    const model = &state.nodes;
    try html.render(w, "<section class=\"sb-panel\" id=\"nodes-confirmation\" tabindex=\"-1\">" ++
        "<h2>{{ heading }}</h2><p>{{ impact }}</p><p>Operation: " ++
        "<code class=\"break-all\">{{ id }}</code></p>", .{
        .heading = if (model.attempted)
            "Operation awaiting confirmation"
        else
            "Review node change",
        .impact = switch (kind) {
            .drain => "New connections will receive 503. Existing connections can finish. " ++
                "The console remains available; restarting this node resumes admission.",
            .@"resume" => "This node will accept new connections again.",
            .clear_local_bans => "Temporary local ban entries will be cleared. Replicated " ++
                "policy and reputation denials still apply. Later traffic can create new bans.",
        },
        .id = model.pending.?.id.slice(),
    });
    if (model.status) |node| try html.render(
        w,
        "<p>Preview: {{ connections }} open connections; " ++
            "{{ bans }} active local ban entries. Counts can change before execution.</p>",
        .{ .connections = node.connections, .bans = node.active_ban_entries },
    );
    const disabled = if (model.busy != .idle) " disabled" else "";
    if (model.attempted) {
        try html.render(
            w,
            "<div class=\"flex flex-wrap gap-2\">" ++
                "<button class=\"btn btn-primary\" data-action=\"nodes-receipt\"{{ busy }}>" ++
                "Inspect receipt</button><button class=\"btn btn-outline\" " ++
                "data-action=\"nodes-retry\"{{ busy }}>Retry same operation</button></div>",
            .{ .busy = disabled },
        );
        if (model.receipt != null and model.receipt.?.state == .uncertain) try html.render(
            w,
            "<button class=\"btn btn-sm\" data-action=\"nodes-acknowledge\"{{ busy }}>" ++
                "Acknowledge uncertainty and refresh</button>",
            .{ .busy = disabled },
        );
    } else try html.render(w, "<div class=\"flex flex-wrap gap-2\">" ++
        "<button class=\"btn btn-primary\" data-action=\"nodes-confirm\"{{ busy }}>" ++
        "Confirm change</button><button class=\"btn\" data-action=\"nodes-cancel\"{{ busy }}>" ++
        "Cancel</button></div>", .{ .busy = disabled });
    try html.render(w, "</section>", .{});
}

fn result(receipt: p.nodes.Receipt, w: *Writer) Writer.Error!void {
    try html.render(w, "<section class=\"sb-panel\" id=\"nodes-receipt\" tabindex=\"-1\">" ++
        "<h2>Command receipt: {{ state }}</h2><p>{{ completion }}</p>" ++
        "<p>Operation: <code class=\"break-all\">{{ id }}</code></p>", .{
        .state = switch (receipt.state) {
            .applied => "Applied locally",
            .rejected => "Not applied",
            .intent => "Intent recorded",
            .uncertain => "Outcome uncertain",
        },
        .completion = completion(receipt),
        .id = receipt.id.slice(),
    });
    if (receipt.cleared_entries) |count| try html.render(
        w,
        "<p>Cleared local ban entries: {{ count }}</p>",
        .{ .count = count },
    );
    try html.render(w, "<p>Node {{ node }} · Expected control revision {{ expected }}</p>" ++
        "<p>Boot: <code class=\"break-all\">{{ boot }}</code></p><p>Requested: ", .{
        .node = receipt.node,
        .expected = receipt.expected_revision,
        .boot = receipt.boot.slice(),
    });
    try @import("events_page.zig").timestamp(w, receipt.requested_at);
    if (receipt.completed_at) |time| {
        try html.render(w, "</p><p>Completed: ", .{});
        try @import("events_page.zig").timestamp(w, time);
    }
    try html.render(w, "</p>", .{});
    if (receipt.applied_revision) |revision| try html.render(
        w,
        "<p>Applied control revision: {{ revision }}</p>",
        .{ .revision = revision },
    );
    try html.render(w, "</section>", .{});
}

fn completion(receipt: p.nodes.Receipt) []const u8 {
    if (receipt.completion_persisted) return "Completion and audit are recorded.";
    if (receipt.state == .applied) return "Completion has not yet been persisted. Inspect again.";
    return "No completion is recorded. This command will not replay automatically.";
}
