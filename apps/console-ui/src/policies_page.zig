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
    if (state.rule_history.open) return @import("rule_hit_page.zig").render(state, w);
    if (state.policies.manager.active) return @import("policy_manager.zig").render(state, w);
    try html.render(w, @embedFile("snippets/policies-header.html"), .{});
    try @import("render.zig").message(state, w);
    try @import("live_status.zig").render(state, .policy, w);
    if (state.policies.page.len == 0) {
        try w.writeAll(if (state.policies.busy)
            "<p role=\"status\">Loading applied policies…</p></main>"
        else
            "<p>No applied policy snapshot is available.</p></main>");
        return;
    }
    // The event-local fixed arena owns this tree. Wrapping it in another arena
    // wastes its bounded space on geometric chunk growth for eight hourly arrays.
    var memory: [64 * 1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = std.json.parseFromSliceLeaky(
        std.json.Value,
        fixed.allocator(),
        state.policies.page.slice(),
        .{},
    ) catch {
        return html.render(w, "<p>Could not read policies. Refresh to retry.</p></main>", .{});
    };
    var rows: [8]Row = undefined;
    const page = data.page(parsed, &rows) catch {
        return html.render(w, "<p>Invalid policy snapshot. Refresh to retry.</p></main>", .{});
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
    try html.render(w, "</section><div class=\"flex flex-wrap gap-3 my-4\">", .{});
    try button(w, "policies-refresh", "First page / refresh", state.policies.busy);
    try button(w, "policies-next", "Next rules", state.policies.busy or
        state.policies.stale or page.next == null);
    try html.render(w, "</div>", .{});
    try @import("inspection_form.zig").render(state, parsed, w, fixed.allocator());
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
    try html.render(w, "</form>", .{});
    try decision(w, &state.policies, fixed.allocator());
    try html.render(w, "</section>", .{});
    try @import("reputation_panel.zig").render(state, w);
    try html.render(w, "</main>", .{});
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
        try html.render(w, "<p>Configured difficulty override: {{ v0 }}</p>", .{
            .v0 = difficulty,
        });
    } else try html.render(w, "<p>Difficulty: inherit</p>", .{});
    try @import("policy_limits.zig").summary(w, row.limits);
    try @import("rule_hit_today.zig").render(w, row.history_key, row.today);
    if (row.truncated) try html.render(
        w,
        "<p class=\"sb-note\">Display shortened or invalid text " ++
            "replaced. Evaluation uses the full applied matchers.</p>",
        .{},
    );
    try html.render(w, "</article>", .{});
}

pub fn decision(w: *Writer, model: *const Model, allocator: std.mem.Allocator) Writer.Error!void {
    if (model.decision.len == 0) return;
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        model.decision.slice(),
        .{},
    ) catch return html.render(w, "<p>Could not read the evaluation result.</p>", .{});
    defer parsed.deinit();
    const result = data.decision(parsed.value) catch
        return html.render(w, "<p>Invalid evaluation result. Please retry.</p>", .{});
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
    try html.render(w, "<p class=\"sb-note\">This preview does not consume quota or simulate " ++
        "session cookies, existing local bans or global rate limits.</p>", .{});
}

fn button(w: *Writer, action: []const u8, label: []const u8, disabled: bool) Writer.Error!void {
    const submit = std.mem.eql(u8, action, "policy-run");
    try html.render(w, "<button class=\"btn\" type=\"{{ kind }}\"", .{
        .kind = if (submit) "submit" else "button",
    });
    if (!submit) try html.render(w, " data-action=\"{{ action }}\"", .{ .action = action });
    if (disabled) try w.writeAll(" disabled");
    try html.render(w, ">{{ label }}</button>", .{ .label = label });
}

test "policy controls retain their button types under escaped template substitution" {
    const t = std.testing;
    var buffer: [512]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try button(&writer, "policy-run", "Evaluate", false);
    try button(&writer, "policies", "Refresh", true);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "type=\"submit\"") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "type=\"button\"") != null);
    const navigation = "data-action=\"policies\" disabled";
    try t.expect(std.mem.indexOf(u8, writer.buffered(), navigation) != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "&quot;") == null);
}

test "a full applied rule page renders all hourly cohorts within its fixed scratch" {
    const t = std.testing;
    const State = @import("state.zig").State;
    const state = try t.allocator.create(State);
    defer t.allocator.destroy(state);
    state.* = .{ .phase = .policies };
    var json: Writer = .fixed(&state.policies.page.data);
    try json.writeAll("{\"committed\":\"2\",\"applied\":\"2\",\"total\":9," ++
        "\"waf\":true,\"default_difficulty\":8,\"default_algorithm\":\"hashcash\",\"rows\":[");
    for (0..8) |index| {
        if (index != 0) try json.writeByte(',');
        try std.json.Stringify.value(.{
            .index = index,
            .name = "Default rule",
            .action = "deny",
            .path = "/private",
            .user_agent = "",
            .truncated = false,
            .header_count = 0,
            .cidr_count = 0,
            .difficulty = @as(?u32, null),
            .algorithm = @as(?[]const u8, null),
            .weight = 0,
            .limits = @as(?u8, null),
            .history_key = "m:default",
            .today = p.rule_hit_history.Today{ .hits = 1, .hours = @splat(1) },
        }, .{}, &json);
    }
    try json.writeAll("],\"next\":8}");
    state.policies.page.len = json.buffered().len;
    const output = try t.allocator.alloc(u8, 128 * 1024);
    defer t.allocator.free(output);
    var writer: Writer = .fixed(output);
    try render(state, &writer);
    const rendered = writer.buffered();
    try t.expect(std.mem.indexOf(u8, rendered, "Could not read policies") == null);
    try t.expect(std.mem.indexOf(u8, rendered, "Invalid policy snapshot") == null);
    try t.expectEqual(@as(usize, 8), std.mem.count(u8, rendered, "Compare rule hits"));
    try t.expectEqual(@as(usize, 8), std.mem.count(u8, rendered, "Recorded UTC hourly cohorts"));
}
