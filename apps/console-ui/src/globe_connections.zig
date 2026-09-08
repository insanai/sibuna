//! Aggregate country-to-service flow. The service hub is deliberately outside geographic
//! coordinates: a loopback review daemon has no known public destination location.
const std = @import("std");
const State = @import("state.zig").State;
const geo = @import("geography.zig");
const Writer = std.Io.Writer;
const Point = struct { x: f64, y: f64 };

pub fn render(state: *const State, bytes: []const u8, w: *Writer) Writer.Error!void {
    const stats = state.stats orelse return;
    const selected = @import("globe_data.zig").view(state) orelse return;
    if (!stats.geoip_available or state.stale or state.paused or
        state.browser_time -| state.received_at > 5) return;
    var drawn: usize = 0;
    const hub: Point = .{ .x = 363, .y = 29 };
    for (selected.countries, 0..) |country, index| {
        if (country.samples == 0 or drawn == 16) continue;
        const location = geo.center(bytes, country.code) orelse continue;
        const projected = geo.project(location, state.globe);
        if (!state.globe.flat and projected.z < 0) continue;
        const start: Point = .{
            .x = if (state.globe.flat) 200 + location.lon else 200 + 110 * projected.x,
            .y = if (state.globe.flat) 135 - location.lat else 135 - 110 * projected.y,
        };
        const control: Point = .{ .x = (start.x + hub.x) / 2, .y = @min(start.y, hub.y) - 24 };
        const code = [_]u8{ @intCast(country.code >> 8), @intCast(country.code & 255) };
        try w.print("<path d=\"M{d:.1},{d:.1}Q{d:.1},{d:.1} {d:.1},{d:.1}\" " ++
            "fill=\"none\" stroke=\"#7c5cdb\" stroke-opacity=\".55\" stroke-width=\".8\">" ++
            "<title>{s} → Sibuna: {d} {s} / 60 s</title></path>", .{
            start.x, start.y,         control.x,     control.y, hub.x, hub.y,
            code,    country.samples, selected.unit,
        });
        const phase = @mod(state.motion.flow + @as(f64, @floatFromInt(index)) * 0.137, 1);
        try arrow(w, start, control, hub, phase);
        drawn += 1;
    }
    if (drawn != 0) try w.writeAll("<circle cx=\"363\" cy=\"29\" r=\"5\" " ++
        "fill=\"#7c5cdb\" stroke=\"white\"/><text x=\"350\" y=\"16\" " ++
        "font-size=\"8\" fill=\"currentColor\">Sibuna</text>");
}

fn arrow(w: *Writer, a: Point, b: Point, c: Point, t: f64) Writer.Error!void {
    const u = 1 - t;
    const x = u * u * a.x + 2 * u * t * b.x + t * t * c.x;
    const y = u * u * a.y + 2 * u * t * b.y + t * t * c.y;
    const dx = u * (b.x - a.x) + t * (c.x - b.x);
    const dy = u * (b.y - a.y) + t * (c.y - b.y);
    const length = @sqrt(dx * dx + dy * dy);
    if (length < 0.001) return;
    const vx = dx / length;
    const vy = dy / length;
    try w.print("<path d=\"M{d:.1},{d:.1}L{d:.1},{d:.1}L{d:.1},{d:.1}Z\" " ++
        "fill=\"#18a8b7\"/>", .{
        x + 3 * vx,            y + 3 * vy,
        x - 3 * vx + 1.8 * vy, y - 3 * vy - 1.8 * vx,
        x - 3 * vx - 1.8 * vy, y - 3 * vy + 1.8 * vx,
    });
}

test "connection arcs require observed countries and disappear when data is stale" {
    const t = std.testing;
    const world = @embedFile("console_world");
    var state: State = .{ .globe = .{ .lon = -100, .lat = 35 } };
    state.stats = std.mem.zeroes(@import("console_protocol").StatsSnapshot);
    state.stats.?.geoip_available = true;
    var buffer: [8192]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&state, world, &writer);
    try t.expectEqual(@as(usize, 0), writer.buffered().len);
    state.stats.?.countries[0] = .{ .code = 0x5553, .samples = 4 };
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
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "4 samples") == null);
    state.stale = true;
    writer = .fixed(&buffer);
    try render(&state, world, &writer);
    try t.expectEqual(@as(usize, 0), writer.buffered().len);
}
