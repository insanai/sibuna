//! Serial browser request correlation survives sign-out without retaining old session data.
const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
var generation: u32 = 0;

pub fn request(state: *State) ?p.Bytes(32) {
    const model = &state.rankings;
    if (@import("dashboard_scope.zig").needsRetainedNode(state)) return null;
    if (!state.fullAccess() or state.kiosk or state.phase != .dashboard or
        state.paused or state.hidden)
        return null;
    if (model.busy or (model.generation != 0 and
        state.browser_time -| model.requested_at < 10)) return null;
    generation +%= 1;
    if (generation == 0) generation = 1;
    model.generation = generation;
    model.requested_at = state.browser_time;
    model.busy = true;
    var id: p.Bytes(32) = .{};
    const text = std.fmt.bufPrint(&id.data, "rankings-{d}", .{generation}) catch unreachable;
    id.len = text.len;
    return id;
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    alloc: std.mem.Allocator,
) enum { retained, expired } {
    if (!std.mem.startsWith(u8, id, "rankings-")) return .retained;
    const ticket = std.fmt.parseInt(u32, id[9..], 10) catch return .retained;
    const model = &state.rankings;
    if (ticket == 0 or ticket != model.generation) return .retained;
    model.busy = false;
    if (!state.fullAccess() or state.kiosk or state.phase != .dashboard or state.paused)
        return .retained;
    if (status == 401 or status == 403) return .expired;
    model.stale = true;
    if (status != 200) return .retained;
    if (@import("dashboard_scope.zig").selectedNode(state)) |node| {
        const value = @import("events_state.zig").field(body, "node") orelse return .retained;
        if (value != .integer or value.integer != node) return .retained;
    }
    model.decode(body, alloc) catch return .retained;
    model.received_at = state.browser_time;
    return .retained;
}

test "rankings are authenticated, throttled and immune to responses from a reset session" {
    const t = std.testing;
    var state: State = .{};
    try t.expect(request(&state) == null);
    state.csrf = try p.Bytes(64).init("session");
    state.phase = .dashboard;
    const first = request(&state).?;
    try t.expect(request(&state) == null);
    try t.expectEqual(.expired, response(&state, first.slice(), 401, .null, t.allocator));
    state.reset();
    state.csrf = try p.Bytes(64).init("replacement");
    state.phase = .dashboard;
    const second = request(&state).?;
    try t.expect(!std.mem.eql(u8, first.slice(), second.slice()));
    try t.expectEqual(.retained, response(&state, first.slice(), 401, .null, t.allocator));
    try t.expect(state.rankings.busy);
    _ = response(&state, second.slice(), 503, .null, t.allocator);
    try t.expect(state.rankings.stale and !state.rankings.busy);
    try t.expect(request(&state) == null);
    state.browser_time = 10;
    try t.expect(request(&state) != null);
}

pub fn render(state: *const State, w: *std.Io.Writer) std.Io.Writer.Error!void {
    if (@import("dashboard_scope.zig").needsRetainedNode(state)) {
        try w.writeAll("<section class=\"sb-panel mt-6\"><h2>Sampled request paths</h2>" ++
            "<p class=\"sb-note\">Select one node for current-minute path rankings. " ++
            "Partial winner lists cannot establish a cluster-wide ranking.</p></section>");
        return;
    }
    try @import("rankings_panel.zig").render(
        &state.rankings,
        w,
        state.browser_time,
        state.paused or state.stale,
    );
}
