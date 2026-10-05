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
        try @import("crs_status.zig").render(node.crs, w);
    } else try html.render(w, "<p role=\"status\">{{ status }}</p>", .{
        .status = if (busy)
            "Loading node state…"
        else
            "Node state unavailable. Refresh to retry.",
    });
    if (model.pending) |pending| try confirmation(state, pending.kind, w);
    if (model.receipt) |receipt| try result(receipt, w);
    try members(state, w);
    try @import("peer_page.zig").render(state, w);
    try html.render(w, "</main>", .{});
}

const Rank = struct { health: p.nodes.Health, observed: bool, leader: bool, node: u32 };

fn rank(peers: *const @import("nodes_state.zig").Peers, value: p.nodes.Member) Rank {
    // The serving node is never probed; it is the live node rendering this page.
    var health: p.nodes.Health = if (value.node == peers.self) .healthy else .unknown;
    for (peers.probes[0..peers.probe_count]) |probe| {
        if (probe.node == value.node) health = probe.health;
    }
    const leader = peers.storage.leader != null and peers.storage.leader.? == value.node;
    return .{
        .health = health,
        .observed = value.last_seen != 0,
        .leader = leader,
        .node = value.node,
    };
}

/// Unhealthy members first, then unobserved, then healthy; the leader leads its group.
fn before(a: Rank, b: Rank) bool {
    const order = [_]u8{ 2, 3, 1, 0 }; // unknown, healthy, degraded, down → rank
    const ra = order[@backingInt(a.health)];
    const rb = order[@backingInt(b.health)];
    if (ra != rb) return ra < rb;
    if (a.observed != b.observed) return !a.observed;
    if (a.leader != b.leader) return a.leader;
    return a.node < b.node;
}

fn members(state: *const State, w: *Writer) Writer.Error!void {
    const peers = &state.nodes.peers;
    if (!peers.loaded) return html.render(w, "<p class=\"sb-note\">Cluster membership " ++
        "not loaded yet.</p>", .{});
    const observed = state.browser_time -| peers.received_at;
    try html.render(w, "<h2>Members</h2><p role=\"status\">{{ count }} member rows · " ++
        "{{ probes }} probed peers · leader {{ leader }} · quorum {{ quorum }} · " ++
        "page age {{ age }} s</p>", .{
        .count = peers.count,
        .probes = peers.probe_count,
        .leader = peers.storage.leader orelse 0,
        .quorum = if (peers.storage.quorum) "available" else "not established",
        .age = observed,
    });
    var order: [p.nodes.max_members]u8 = undefined;
    for (0..peers.count) |i| order[i] = @intCast(i);
    // Insertion sort over at most nine rows.
    for (0..peers.count) |i| {
        var j = i;
        while (j > 0 and before(
            rank(peers, peers.members[order[j]]),
            rank(peers, peers.members[order[j - 1]]),
        )) {
            std.mem.swap(u8, &order[j], &order[j - 1]);
            j -= 1;
        }
    }
    for (order[0..peers.count]) |index| try renderMember(state, peers.members[index], w);
    for (peers.probes[0..peers.probe_count]) |probe| {
        var known = false;
        for (peers.members[0..peers.count]) |m| known = known or m.node == probe.node;
        if (!known) try html.render(w, "<section class=\"sb-panel\"><h2>Node {{ node }} · " ++
            "unobserved</h2><p>Configured for probing but no membership row has been " ++
            "replicated. Counters are unavailable, not zero.</p></section>", .{
            .node = probe.node,
        });
    }
}

fn renderMember(state: *const State, value: p.nodes.Member, w: *Writer) Writer.Error!void {
    const peers = &state.nodes.peers;
    const info = rank(peers, value);
    var probe_text: [96]u8 = undefined;
    var probe: []const u8 = "not configured";
    for (peers.probes[0..peers.probe_count]) |entry| {
        if (entry.node != value.node) continue;
        probe = std.fmt.bufPrint(&probe_text, "{s}, {d} ms, {d} requests since last probe", .{
            @tagName(entry.health), entry.latency_ms, entry.requests,
        }) catch "probe summary unavailable";
    }
    const behind = value.applied_revision < peers.committed;
    var slots: [48]u8 = undefined;
    var lag_text: [64]u8 = undefined;
    const lag = value.decided_slot -| value.applied_slot;
    try html.render(w, @embedFile("snippets/nodes-member.html"), .{
        .node = value.node,
        .health = if (value.node == peers.self) "serving this console" else switch (info.health) {
            .healthy => "healthy",
            .degraded => "degraded (draining)",
            .down => "unreachable",
            .unknown => "not probed",
        },
        .leader = if (info.leader) " · leader" else "",
        .summary = if (value.draining)
            "Draining: new connections are refused."
        else if (value.node == peers.self)
            "This node."
        else
            "Announced through replicated storage.",
        .address = value.address.slice(),
        .version = value.version.slice(),
        .applied = value.applied_revision,
        .ack = if (behind) "behind committed" else "applied",
        .slots = std.fmt.bufPrint(&slots, "{d} / {d}", .{
            value.applied_slot,
            value.decided_slot,
        }) catch "?",
        .lag = if (value.last_seen == 0)
            "unobserved"
        else if (lag == 0)
            "none: every decided slot is applied"
        else
            std.fmt.bufPrint(&lag_text, "{d} decided slots not yet applied", .{lag}) catch "?",
        .seen = if (value.last_seen == 0) "never" else "recorded",
        .probe = probe,
    });
    if (value.console_url.len != 0 and value.node != peers.self) try html.render(
        w,
        "<a class=\"btn btn-sm\" href=\"{{ url }}\" rel=\"noopener noreferrer\" " ++
            "target=\"_blank\">Open console</a>",
        .{ .url = value.console_url.slice() },
    );
    try html.render(w, "</section>", .{});
}

fn status(state: *const State, node: p.nodes.Status, w: *Writer) Writer.Error!void {
    const model = &state.nodes;
    const fresh = model.fresh(state.browser_time);
    var gauge_text: [2][32]u8 = undefined;
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
        .memory = memoryText(state, node.node, &gauge_text[0]),
        .cpu = cpuText(state, node.node, &gauge_text[1]),
        .boot = node.boot.slice(),
        .pending = if (node.completion_pending)
            "A local effect is awaiting durable completion. New commands are paused."
        else
            "Status refreshes every five seconds while no confirmation is open.",
    });
    if (state.stats) |stats| if (stats.node == node.node) {
        const sparkline = @import("outcome_sparkline.zig");
        try w.writeAll("<div class=\"sb-panels\"><figure>" ++
            "<figcaption>Resident memory, KiB</figcaption>");
        try sparkline.renderGauge(state, w, .memory, "Resident memory");
        try w.writeAll("</figure><figure><figcaption>CPU, percent of one core</figcaption>");
        try sparkline.renderGauge(state, w, .cpu, "CPU");
        try w.writeAll("</figure></div>");
    };
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

/// Gauges come from the live snapshot of the node rendering this page; another node's
/// selection or a snapshot without the gauge reads as not recorded.
fn memoryText(state: *const State, node: u32, buffer: *[32]u8) []const u8 {
    const stats = state.stats orelse return "Not recorded";
    if (stats.node != node) return "Not recorded";
    const kib = stats.rss_kib orelse return "Not recorded";
    return std.fmt.bufPrint(buffer, "{d} KiB", .{kib}) catch "Not recorded";
}

fn cpuText(state: *const State, node: u32, buffer: *[32]u8) []const u8 {
    const stats = state.stats orelse return "Not recorded";
    if (stats.node != node) return "Not recorded";
    const permille = stats.cpu_permille orelse return "Not recorded";
    return std.fmt.bufPrint(buffer, "{d}.{d} %", .{ permille / 10, permille % 10 }) catch
        "Not recorded";
}
