//! One-time wall-display grants use the existing operator API. The account page owns the
//! bounded code; navigation, hiding, expiry and session reset erase it and fence late replies.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const text = @import("events_state.zig").string;
var generation: u64 = 0;

pub const Model = struct {
    ticket: p.Bytes(32) = .{},
    code: p.Bytes(64) = .{},
    use_by: u64 = 0,
    expires: u64 = 0,
    busy: bool = false,

    pub fn clear(self: *Model) void {
        std.crypto.secureZero(u8, &self.code.data);
        self.* = .{};
    }
};

pub fn retain(state: *State) void {
    const model = &state.kiosk_grant;
    if (state.phase != .password or !state.allows(.open_kiosk) or state.hidden or
        (model.code.len != 0 and state.browser_time >= model.use_by)) model.clear();
}

pub fn action(state: *State, name: []const u8, fields: std.json.Value, out: Outbox) !bool {
    if (!std.mem.eql(u8, name, "kiosk-grant") and
        !std.mem.eql(u8, name, "kiosk-grant-hide")) return false;
    const model = &state.kiosk_grant;
    if (state.phase != .password or !state.allows(.open_kiosk)) return true;
    if (std.mem.eql(u8, name, "kiosk-grant-hide")) {
        model.clear();
        return true;
    }
    if (model.busy or model.code.len != 0) return true;
    const label = text(fields, "label");
    if (label.len == 0 or label.len > p.kiosk.max_label) {
        try state.message.set("Give the wall display a label of 1 to 64 bytes.");
        return true;
    }
    if (generation == std.math.maxInt(u64)) return error.Capacity;
    generation += 1;
    const ticket = try std.fmt.bufPrint(&model.ticket.data, "kiosk-grant-{d}", .{generation});
    model.ticket.len = ticket.len;
    model.busy = true;
    errdefer model.clear();
    state.message = .{};
    try out.post(ticket, "/console/api/kiosk/token", .{ .label = label });
    return true;
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    allocator: std.mem.Allocator,
    out: Outbox,
) !void {
    const model = &state.kiosk_grant;
    if (!model.busy or !std.mem.eql(u8, id, model.ticket.slice())) return;
    model.busy = false;
    if (state.phase != .password or !state.allows(.open_kiosk) or state.hidden) {
        model.clear();
        return;
    }
    if (status != 200) {
        model.clear();
        try state.message.set(if (status == 401 or status == 403)
            "Your session cannot create wall displays. Sign in with operator access."
        else
            "No code received. An unused grant may exist; it expires after ten minutes.");
        return;
    }
    errdefer model.clear();
    const code = text(body, "code");
    if (code.len != 64) return error.InvalidResponse;
    for (code) |byte| if (!std.ascii.isHex(byte) or std.ascii.isUpper(byte))
        return error.InvalidResponse;
    const decode = @import("json_value.zig").decode;
    if (body != .object) return error.InvalidResponse;
    const use_by = try decode(u64, body.object.get("use_by") orelse
        return error.InvalidResponse, allocator);
    const expires = try decode(u64, body.object.get("expires") orelse
        return error.InvalidResponse, allocator);
    if (use_by <= state.browser_time or use_by > state.browser_time +| p.kiosk.use_seconds or
        expires < use_by or expires > state.browser_time +| p.kiosk.lifetime_seconds)
        return error.InvalidResponse;
    try model.code.set(code);
    model.use_by = use_by;
    model.expires = expires;
    try out.emit(.{ .op = "focus", .selector = "#wall-display-code" });
}

pub fn render(state: *const State, w: *std.Io.Writer) std.Io.Writer.Error!void {
    if (!state.allows(.open_kiosk)) return;
    const model = &state.kiosk_grant;
    try w.writeAll("<section class=\"mt-6\" aria-labelledby=\"wall-display-heading\">" ++
        "<h2 id=\"wall-display-heading\">Wall display</h2>" ++
        "<p>A display receives read-only statistics access for up to twelve hours. " ++
        "Deliver its one-time code privately and paste it into the display's sign-in page. " ++
        "Do not put the code in a URL.</p>");
    if (model.code.len == 0) {
        try html.render(w, @embedFile("snippets/kiosk-grant-form.html"), .{
            .busy = if (model.busy) " disabled" else "",
        });
    } else {
        try html.render(w, @embedFile("snippets/kiosk-grant-code.html"), .{
            .code = model.code.slice(),
        });
        try w.writeAll("<p>Exchange before ");
        try @import("events_page.zig").timestamp(w, model.use_by);
        try w.writeAll(". Display access expires ");
        try @import("events_page.zig").timestamp(w, model.expires);
        try w.writeAll(".</p><button class=\"btn\" data-action=\"kiosk-grant-hide\">" ++
            "Hide code</button>");
    }
    try w.writeAll("</section>");
}

test {
    _ = @import("kiosk_grant_test.zig");
}
