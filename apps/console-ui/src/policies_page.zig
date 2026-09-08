const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const Writer = std.Io.Writer;

pub const Model = struct {
    inspection_draft: ?@import("inspection_form.zig").Modes = null,
    manager: @import("policy_manager.zig").Model = .{},
    path: p.Bytes(512) = .{},
    ip: p.Bytes(48) = .{},
    user_agent: p.Bytes(256) = .{},
    query_string: p.Bytes(512) = .{},
    body: p.Bytes(2048) = .{},
    headers: p.Bytes(2048) = .{},
    page: p.Bytes(4096) = .{},
    decision: p.Bytes(1024) = .{},
    applied: p.Bytes(20) = .{},
    offset: u8 = 0,
    next: ?u8 = null,
    busy: bool = false,
    testing: bool = false,
    stale: bool = false,
};
const data = @import("policy_data.zig");
const Row = data.Row;

pub fn render(state: *const @import("state.zig").State, w: *Writer) Writer.Error!void {
    if (state.policies.manager.active) return @import("policy_manager.zig").render(state, w);
    try html.render(w, @embedFile("snippets/policies-header.html"), .{});
    try @import("render.zig").message(state, w);
    if (state.policies.page.len == 0) {
        try w.writeAll(if (state.policies.busy)
            "<p role=\"status\">Loading applied policies…</p></main>"
        else
            "<p>No applied policy snapshot is available.</p></main>");
        return;
    }
    var memory: [64 * 1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        fixed.allocator(),
        state.policies.page.slice(),
        .{},
    ) catch {
        return w.writeAll("<p>Could not read policies. Refresh to retry.</p></main>");
    };
    defer parsed.deinit();
    var rows: [8]Row = undefined;
    const page = data.page(parsed.value, &rows) catch {
        return w.writeAll("<p>Invalid policy snapshot. Refresh to retry.</p></main>");
    };
    try html.render(w, @embedFile("snippets/policies-summary.html"), .{
        .committed = page.committed,
        .applied = page.applied,
        .total = page.total,
        .waf = if (page.waf) "Enabled" else "Disabled",
        .difficulty = page.default_difficulty,
        .algorithm = page.default_algorithm,
    });
    for (page.rows) |row| try policyRow(w, row);
    try w.writeAll("</section><div class=\"flex flex-wrap gap-3 my-4\">");
    try button(w, "policies-refresh", "First page / refresh", state.policies.busy);
    try button(w, "policies-next", "Next rules", state.policies.busy or
        state.policies.stale or page.next == null);
    try w.writeAll("</div>");
    try @import("inspection_form.zig").render(state, parsed.value, w, fixed.allocator());
    try html.render(w, @embedFile("snippets/policies-test.html"), .{
        .path = if (state.policies.path.len == 0) "/" else state.policies.path.slice(),
        .ip = if (state.policies.ip.len == 0) "8.8.8.8" else state.policies.ip.slice(),
        .query = state.policies.query_string.slice(),
        .user_agent = state.policies.user_agent.slice(),
        .body = state.policies.body.slice(),
        .headers = state.policies.headers.slice(),
    });
    try button(w, "policy-run", "Evaluate policy", state.policies.testing or
        state.policies.busy or state.policies.stale);
    try w.writeAll("</form>");
    try decision(w, &state.policies, fixed.allocator());
    try w.writeAll("</section></main>");
}

fn policyRow(w: *Writer, row: Row) Writer.Error!void {
    try html.render(w, @embedFile("snippets/policies-row.html"), .{
        .index = @as(u16, row.index) + 1,
        .name = row.name,
        .action = row.action,
        .path = if (row.path.len == 0) "Any path" else row.path,
        .user_agent = if (row.user_agent.len == 0) "Any user agent" else row.user_agent,
        .headers = row.header_count,
        .cidrs = row.cidr_count,
        .weight = row.weight,
        .algorithm = row.algorithm orelse "Inherit",
    });
    if (row.difficulty) |difficulty| {
        try w.print("<p>Configured difficulty override: {d}</p>", .{difficulty});
    } else try w.writeAll("<p>Difficulty: inherit</p>");
    try @import("policy_limits.zig").summary(w, row.limits);
    if (row.truncated) try w.writeAll("<p class=\"sb-note\">Display shortened or invalid text " ++
        "replaced. Evaluation uses the full applied matchers.</p>");
    try w.writeAll("</article>");
}

pub fn decision(w: *Writer, model: *const Model, allocator: std.mem.Allocator) Writer.Error!void {
    if (model.decision.len == 0) return;
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        model.decision.slice(),
        .{},
    ) catch return w.writeAll("<p>Could not read the evaluation result.</p>");
    defer parsed.deinit();
    const result = data.decision(parsed.value) catch
        return w.writeAll("<p>Invalid evaluation result. Please retry.</p>");
    try html.render(w, @embedFile("snippets/policies-decision.html"), .{
        .kind = if (result.preview) "Draft decision" else "Policy decision",
        .revision_label = if (result.preview) "Draft committed revision" else "Applied revision",
        .action = result.action,
        .rule = result.rule,
        .revision = result.committed orelse result.applied,
        .difficulty = result.difficulty,
        .algorithm = result.algorithm,
        .score = result.score,
    });
    try @import("inspection_form.zig").findings(w, result.audited);
    try @import("policy_limits.zig").summary(w, result.limits);
    try w.writeAll("<p class=\"sb-note\">This preview does not consume quota or simulate " ++
        "session cookies, existing local bans or global rate limits.</p>");
}

fn button(w: *Writer, action: []const u8, label: []const u8, disabled: bool) Writer.Error!void {
    try w.print("<button class=\"btn\" {s}", .{
        if (std.mem.eql(u8, action, "policy-run")) "type=\"submit\"" else "type=\"button\"",
    });
    if (!std.mem.eql(u8, action, "policy-run")) try w.print(" data-action=\"{s}\"", .{action});
    if (disabled) try w.writeAll(" disabled");
    try w.print(">{s}</button>", .{label});
}
