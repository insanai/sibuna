const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const Kind = @import("audit_state.zig").Kind;
const string = @import("events_state.zig").string;
const equal = std.mem.eql;
var generation: u64 = 0;

pub fn action(state: *State, name: []const u8, fields: std.json.Value, out: Outbox) !bool {
    if (equal(u8, name, "audit") and state.fullAccess()) {
        state.audit.clear();
        state.phase = .audit;
        state.stats_busy = false;
        state.stale = true;
        window(state);
        try query(state, out, .query);
        return true;
    }
    if (!std.mem.startsWith(u8, name, "audit-")) return false;
    const model = &state.audit;
    if (!state.fullAccess() or state.phase != .audit or model.busy) return true;
    if (equal(u8, name, "audit-filter")) {
        capture(state, fields) catch {
            message(state, "Use a numeric actor ID, an exact action name and a supported period.");
            try out.emit(.{ .op = "focus", .selector = "#console-message" });
            return true;
        };
        window(state);
        try query(state, out, .query);
    } else if (equal(u8, name, "audit-refresh")) {
        window(state);
        try query(state, out, .query);
    } else if (equal(u8, name, "audit-next")) {
        if (model.next == null or model.page + 1 == model.pages.len) return true;
        model.page += 1;
        model.pages[model.page] = model.next.?;
        try query(state, out, .query);
    } else if (equal(u8, name, "audit-previous")) {
        if (model.page == 0) return true;
        model.page -= 1;
        try query(state, out, .query);
    } else if (equal(u8, name, "audit-export")) {
        try query(state, out, .export_page);
    } else if (std.mem.startsWith(u8, name, "audit-open-")) {
        const index = std.fmt.parseInt(usize, name[11..], 10) catch return true;
        if (index >= model.count) return true;
        model.selected = model.rows[index].id;
        model.has_detail = false;
        try ticket(state, .read);
        errdefer model.busy = false;
        var id: [20]u8 = undefined;
        try out.post(model.ticket.slice(), "/console/api/audit/read", .{
            .id = try std.fmt.bufPrint(&id, "{d}", .{model.selected}),
        });
    } else if (equal(u8, name, "audit-close")) {
        model.has_detail = false;
        try out.emit(.{ .op = "focus", .selector = "#audit-catalog" });
    }
    return true;
}

fn capture(state: *State, fields: std.json.Value) !void {
    const actor = try p.Bytes(20).init(string(fields, "actor"));
    const action_name = try p.Bytes(48).init(string(fields, "action"));
    if (actor.len != 0) {
        for (actor.slice()) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidResponse;
        }
        if (try std.fmt.parseInt(u64, actor.slice(), 10) > p.audit.last_id)
            return error.InvalidResponse;
    }
    if (!p.audit.validAction(action_name.slice())) return error.InvalidResponse;
    const days = try std.fmt.parseInt(u16, string(fields, "days"), 10);
    if (days != 1 and days != 7 and days != 30 and days != 365) return error.InvalidResponse;
    state.audit.actor = actor;
    state.audit.action = action_name;
    state.audit.days = days;
}

fn window(state: *State) void {
    const model = &state.audit;
    model.page = 0;
    model.pages[0] = p.audit.last_id;
    model.until = state.browser_time;
    model.since = model.until -| @as(u64, model.days) * 86400;
}

fn ticket(state: *State, kind: Kind) !void {
    if (generation == std.math.maxInt(u64)) return error.Capacity;
    generation += 1;
    const model = &state.audit;
    const name = try std.fmt.bufPrint(&model.ticket.data, "audit-{d}", .{generation});
    model.ticket.len = name.len;
    model.kind = kind;
    model.busy = true;
    state.message = .{};
}

fn query(state: *State, out: Outbox, kind: Kind) !void {
    const model = &state.audit;
    try ticket(state, kind);
    errdefer model.busy = false;
    model.loaded = false;
    model.count = 0;
    model.has_detail = false;
    model.next = null;
    var before: [20]u8 = undefined;
    var since: [20]u8 = undefined;
    var until: [20]u8 = undefined;
    try out.post(model.ticket.slice(), if (kind == .export_page)
        "/console/api/audit/export"
    else
        "/console/api/audit/query", .{
        .before = try std.fmt.bufPrint(&before, "{d}", .{model.pages[model.page]}),
        .actor = if (model.actor.len == 0) null else model.actor.slice(),
        .action = model.action.slice(),
        .since = try std.fmt.bufPrint(&since, "{d}", .{model.since}),
        .until = try std.fmt.bufPrint(&until, "{d}", .{model.until}),
    });
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    allocator: std.mem.Allocator,
    out: Outbox,
) !void {
    const model = &state.audit;
    if (!state.fullAccess() or state.phase != .audit or
        !equal(u8, id, model.ticket.slice())) return;
    model.busy = false;
    if (status == 401) {
        state.reset();
        state.phase = .login;
        message(state, "Your session ended. Sign in to continue.");
        return out.emit(.{ .op = "disconnect" });
    }
    if (status != 200) {
        message(state, switch (status) {
            404 => "This record is unavailable. Refresh; retention may have removed it.",
            429 => "Too many audit requests. Wait a minute, then refresh.",
            0, 503 => "Audit data is unavailable. Narrow the filters and retry.",
            else => "Check the audit filters and your current session, then retry.",
        });
        return;
    }
    if (model.kind == .read) {
        try model.detailValue(body, allocator);
    } else {
        try model.pageValue(body, allocator);
        if (model.kind == .export_page) {
            var buffer: [8192]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&buffer);
            try std.json.Stringify.value(body, .{}, &writer);
            try out.emit(.{
                .op = "save-text",
                .filename = "sibuna-audit-page.json",
                .text = writer.buffered(),
            });
        }
    }
    try out.emit(.{ .op = "focus", .selector = if (model.has_detail)
        "#audit-detail"
    else
        "#audit-catalog" });
}

fn message(state: *State, value: []const u8) void {
    state.message = p.Bytes(256).init(value) catch unreachable;
    state.message_success = false;
}

test {
    _ = @import("audit_test.zig");
}
