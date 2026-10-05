//! One owned detail view, fenced across incident pages and later authenticated sessions.
const std = @import("std");
const p = @import("console_protocol");
const ctx = @import("controller_context.zig");
pub const Model = struct {
    id: u64 = 0,
    ticket: p.Bytes(48) = .{},
    busy: bool = false,
    loaded: bool = false,
    failed: bool = false,
    detail: ?p.incident_crs.api.Detail = null,

    pub fn clear(self: *Model) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = .{};
    }
};
var generation: u64 = 0;

fn finding(c: ctx.Context, id: u64) ?p.events.security_evidence.Crs {
    for (c.state.events.rows[0..c.state.events.count]) |row| {
        if (row.id == id and !row.grouped) return row.crs;
    }
    return null;
}

pub fn action(c: ctx.Context, name: []const u8) !bool {
    const prefix = "events-crs-";
    if (!std.mem.startsWith(u8, name, prefix)) return false;
    if (c.state.phase != .events or !c.state.fullAccess()) return true;
    const id = std.fmt.parseInt(u64, name[prefix.len..], 10) catch return true;
    if (finding(c, id) == null or c.state.incident_crs.busy) return true;
    if (generation == std.math.maxInt(u64)) return error.GenerationExhausted;
    generation += 1;
    const model = &c.state.incident_crs;
    model.clear();
    model.id = id;
    const ticket = try std.fmt.bufPrint(&model.ticket.data, "incident-crs-{d}", .{generation});
    model.ticket.len = ticket.len;
    model.busy = true;
    errdefer model.busy = false;
    try c.out.post(ticket, "/console/api/events/crs", .{ .id = name[prefix.len..] });
    return true;
}

pub fn response(c: ctx.Context, reply: ctx.Response) !void {
    const model = &c.state.incident_crs;
    if (!std.mem.eql(u8, reply.id, model.ticket.slice()) or c.state.phase != .events or
        !c.state.fullAccess()) return;
    const scalar = finding(c, model.id) orelse {
        model.clear();
        return;
    };
    model.busy = false;
    if (reply.status == 401 or reply.status == 403) {
        c.state.reset();
        c.state.phase = .login;
        try c.state.message.set("Your session ended. Sign in to continue.");
        return c.out.emit(.{ .op = "disconnect" });
    }
    model.failed = true;
    if (reply.status != 200) return;
    const wire = try p.json_value.decode(p.incident_crs.Wire, reply.body, reply.allocator);
    if (wire.id != model.id) return error.InvalidResponse;
    if (wire.detail) |value| {
        var detail: p.incident_crs.api.Detail = undefined;
        try value.into(&detail);
        if (detail.rule_id != scalar.rule_id or detail.phase != scalar.phase)
            return error.InvalidResponse;
        model.detail = detail;
    }
    model.failed = false;
    model.loaded = true;
    try c.out.emit(.{ .op = "focus", .selector = "#incident-crs-heading" });
}
