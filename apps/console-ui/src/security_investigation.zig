//! Drill-downs carry the frozen summary range into the normal incident workflow.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Selection = struct {
    module: ?p.security.Module = null,
    category: p.Bytes(32) = .{},
    ip: p.Bytes(48) = .{},
    path: p.Bytes(256) = .{},
};

pub fn open(state: *State, name: []const u8) !bool {
    if (!state.fullAccess() or state.kiosk or state.phase != .security_overview) return false;
    const picked = try selection(state, name) orelse return false;
    const summary = &state.security_overview;
    const events = &state.events;
    events.clear();
    events.module = picked.module;
    events.category = picked.category;
    events.ip = picked.ip;
    events.path = picked.path;
    events.node = summary.request.node;
    events.from = summary.request.from;
    // Incident queries use inclusive endpoints; the summary's upper boundary is exclusive.
    events.until = summary.request.until - 1;
    events.hours = summary.hours;
    events.busy = true;
    state.phase = .events;
    state.message = .{};
    return true;
}

fn selection(state: *const State, name: []const u8) !?Selection {
    const model = &state.security_overview;
    const prefix = "security-";
    if (!std.mem.startsWith(u8, name, prefix)) return null;
    var parts = std.mem.splitScalar(u8, name[prefix.len..], '-');
    const kind = parts.next() orelse return null;
    const source = std.mem.eql(u8, kind, "source");
    const module = std.mem.eql(u8, kind, "module");
    const category = std.mem.eql(u8, kind, "category");
    const path = std.mem.eql(u8, kind, "path");
    if (!source and !module and !category and !path) return null;
    const index = try std.fmt.parseInt(usize, parts.next() orelse return error.InvalidRequest, 10);
    if (source or module) {
        if (!model.loaded[0] or index >= 3) return error.InvalidRequest;
        var result: Selection = .{ .module = @enumFromInt(index) };
        if (source) {
            const rank = try std.fmt.parseInt(
                usize,
                parts.next() orelse return error.InvalidRequest,
                10,
            );
            if (rank >= 3) return error.InvalidRequest;
            const row = model.modules[index].sources[rank] orelse return error.InvalidRequest;
            try result.ip.set(row.label.slice());
        }
        if (parts.next() != null) return error.InvalidRequest;
        return result;
    }
    if (parts.next() != null or index >= 5 or !model.loaded[if (category) 1 else 2])
        return error.InvalidRequest;
    const row = (if (category) model.categories[index] else model.paths[index]) orelse
        return error.InvalidRequest;
    var result: Selection = .{};
    if (category) {
        try result.category.set(row.label.slice());
    } else try result.path.set(row.label.slice());
    return result;
}

pub fn filter(
    model: *const @import("events_state.zig").Model,
    w: *std.Io.Writer,
) std.Io.Writer.Error!void {
    const html = @import("html");
    try html.render(w, "<label for=\"event-module\">Module</label>" ++
        "<select class=\"select select-bordered\" id=\"event-module\" name=\"module\">" ++
        "<option value=\"\">All recorded modules</option>", .{});
    for ([_]p.security.Module{ .inspection, .honeypot, .other }) |module| {
        try html.render(w, "<option value=\"{{ name }}\"{{ selected }}>{{ name }}</option>", .{
            .name = @tagName(module),
            .selected = if (model.module == module) " selected" else "",
        });
    }
    try html.render(w, "</select>", .{});
    if (model.from) |from| {
        try html.render(w, "<p class=\"sb-note\">Security drill-down uses the fixed period ", .{});
        try @import("events_page.zig").timestamp(w, from);
        try w.writeAll(" through ");
        try @import("events_page.zig").timestamp(w, model.until);
        try w.writeAll(". Applying filters starts a new period.</p>");
    }
}

test "security drill-down preserves the node and half-open period without query secrets" {
    const t = std.testing;
    var state: State = .{ .phase = .security_overview };
    try state.csrf.set("test");
    state.security_overview.loaded = @splat(true);
    state.security_overview.request = .{ .node = 2, .from = 100, .until = 220 };
    try t.expect(try open(&state, "security-module-0"));
    try t.expectEqual(@as(?p.security.Module, .inspection), state.events.module);
    try t.expectEqual(@as(?u64, 100), state.events.from);
    try t.expectEqual(@as(u64, 219), state.events.until);
    try t.expectEqual(@as(u32, 2), state.events.node);
    state.kiosk = true;
    state.phase = .security_overview;
    try t.expect(!try open(&state, "security-module-0"));
}
