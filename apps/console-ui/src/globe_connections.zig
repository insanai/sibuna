//! Observed country-to-node activity; the destination is explicitly declared by the operator.
const std = @import("std");
const State = @import("state.zig").State;
const geo = @import("geography.zig");
const routes = @import("geographic_route.zig");
const Writer = std.Io.Writer;

pub fn destination(state: *const State) ?geo.Point {
    const stats = state.stats orelse return null;
    const location = stats.server_location orelse return null;
    if (!location.valid()) return null;
    return .{ .lat = location.lat, .lon = location.lon };
}

pub fn render(state: *const State, bytes: []const u8, w: *Writer) Writer.Error!void {
    const end = destination(state) orelse return;
    const stats = state.stats orelse return;
    const selected = @import("globe_data.zig").view(state) orelse return;
    if (!stats.geoip_available or state.stale or
        state.browser_time -| state.received_at > 5) return;
    var drawn: usize = 0;
    for (selected.countries, 0..) |country, index| {
        if (country.samples == 0 or drawn == 16) continue;
        const start = geo.center(bytes, country.code) orelse continue;
        const route = routes.Route.init(start, end);
        const code = [_]u8{ @intCast(country.code >> 8), @intCast(country.code & 255) };
        try w.writeAll("<path class=\"sb-connection\" d=\"");
        var previous = route.screen(state.globe, 0);
        for (1..49) |step| {
            const next = route.screen(state.globe, @as(f64, @floatFromInt(step)) / 48);
            if (routes.segment(previous, next, state.globe.flat)) |line| try w.print(
                "M{d:.1},{d:.1}L{d:.1},{d:.1}",
                .{ line[0].x, line[0].y, line[1].x, line[1].y },
            );
            previous = next;
        }
        try w.print(
            "\" fill=\"none\" stroke=\"#7c5cdb\" stroke-opacity=\".7\" " ++
                "stroke-width=\"1\"><title>{s} → Sibuna: {d} {s} / 60 s</title></path>",
            .{ code, country.samples, selected.unit },
        );
        const phase = @mod(state.motion.flow + @as(f64, @floatFromInt(index)) * 0.137, 1);
        try arrow(w, route, state.globe, phase);
        drawn += 1;
    }
}

/// Draw the node even during an empty window, GeoIP outage or disconnection. Its configured
/// location is independent of telemetry freshness; the surrounding dashboard shows its age.
pub fn marker(state: *const State, w: *Writer) Writer.Error!void {
    const point = destination(state) orelse return;
    const projected = geo.project(point, state.globe);
    if (!state.globe.flat and projected.z < 0) return;
    const x = if (state.globe.flat) 200 + point.lon else 200 + 110 * projected.x;
    const y = if (state.globe.flat) 135 - point.lat else 135 - 110 * projected.y;
    try w.print(
        "<g id=\"sibuna-location\"><circle cx=\"{d:.1}\" cy=\"{d:.1}\" r=\"4\" " ++
            "fill=\"#7c5cdb\" stroke=\"white\"><title>Sibuna server: {d:.4}, {d:.4} " ++
            "(configured)</title></circle><text x=\"{d:.1}\" y=\"{d:.1}\" " ++
            "font-size=\"9\" text-anchor=\"middle\" fill=\"currentColor\">Sibuna</text></g>",
        .{ x, y, point.lat, point.lon, x, y - 8 },
    );
}

fn arrow(w: *Writer, route: routes.Route, view: geo.View, t: f64) Writer.Error!void {
    const a = route.screen(view, t);
    const b = route.screen(view, @min(1, t + 0.008));
    if (a.z < 0 or b.z < 0 or routes.segment(a, b, view.flat) == null) return;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const length = @sqrt(dx * dx + dy * dy);
    if (length < 0.001) return;
    const vx = dx / length;
    const vy = dy / length;
    try w.print("<path class=\"sb-flow-arrow\" " ++
        "d=\"M{d:.1},{d:.1}L{d:.1},{d:.1}L{d:.1},{d:.1}Z\" fill=\"#18a8b7\"/>", .{
        a.x + 3 * vx,            a.y + 3 * vy,
        a.x - 3 * vx + 1.8 * vy, a.y - 3 * vy - 1.8 * vx,
        a.x - 3 * vx - 1.8 * vy, a.y - 3 * vy + 1.8 * vx,
    });
}

test "connections require observed countries and a real destination; stale data hides flows" {
    const t = std.testing;
    const world = @embedFile("console_world");
    var state: State = .{ .globe = .{ .lon = -100, .lat = 35 } };
    state.stats = std.mem.zeroes(@import("console_protocol").StatsSnapshot);
    state.stats.?.geoip_available = true;
    state.stats.?.countries[0] = .{ .code = 0x5553, .samples = 4 };
    var buffer: [8192]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&state, world, &writer);
    try t.expectEqual(@as(usize, 0), writer.buffered().len);
    state.stats.?.server_location = .{ .lon = -90, .lat = 30 };
    try render(&state, world, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "US → Sibuna: 4 samples") != null);
    state.globe_attacks = true;
    writer = .fixed(&buffer);
    try render(&state, world, &writer);
    try t.expectEqual(@as(usize, 0), writer.buffered().len);
    state.stats.?.incident_geo = .{};
    state.stats.?.incident_geo.?.countries[0] = .{ .code = 0x5553, .samples = 2 };
    try render(&state, world, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "US → Sibuna: 2 findings") != null);
    state.stale = true;
    writer = .fixed(&buffer);
    try render(&state, world, &writer);
    try t.expectEqual(@as(usize, 0), writer.buffered().len);
    try marker(&state, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "sibuna-location") != null);
}
