const std = @import("std");
const State = @import("state.zig").State;
const geography = @import("geography.zig");
const Writer = std.Io.Writer;
const data = @import("globe_data.zig");
const html = @import("html");

pub fn scene(state: *const State, w: *Writer) Writer.Error!void {
    try w.writeAll("<svg viewBox=\"0 0 400 280\" role=\"img\" " ++
        "aria-label=\"Earth and country activity. See coverage and the country table below.\">");
    try @import("html").render(w, @embedFile("snippets/globe-definitions.html"), .{});
    if (state.globe.flat) {
        try w.writeAll("<rect x=\"20\" y=\"45\" width=\"360\" height=\"180\" " ++
            "fill=\"url(#ocean)\" stroke=\"#94b6d5\"/>");
    } else try w.writeAll("<circle cx=\"200\" cy=\"135\" r=\"110\" " ++
        "fill=\"url(#ocean)\" stroke=\"#94b6d5\"/>");
    const available = if (state.stats) |stats| stats.geoip_available else false;
    if (!state.globe.flat) try w.writeAll("<g clip-path=\"url(#globe-clip)\">");
    try geography.graticule(state.globe, w);
    if (state.geometry) |bytes| {
        try geography.render(bytes, state.globe, w);
        if (available) try markers(state, bytes, w);
    }
    if (!state.globe.flat) try w.writeAll("</g>");
    if (state.geometry) |bytes| try @import("globe_connections.zig").render(state, bytes, w);
    try w.writeAll("</svg>");
}

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    try w.writeAll("<h2>Live earth globe</h2>");
    try html.render(w, @embedFile("snippets/globe-mode.html"), .{
        .traffic = !state.globe_attacks,
        .attacks = state.globe_attacks,
    });
    try w.writeAll("<div id=\"globe-scene\">");
    try scene(state, w);
    try w.writeAll("</div><div class=\"sb-globe-controls\">");
    if (state.geometry != null and !state.motion.reduced) {
        try w.print("<button class=\"btn btn-sm\" data-action=\"globe-motion\">{s}</button>", .{
            if (state.motion.rotating) "Pause animation" else "Start animation",
        });
    }
    const available = if (state.stats) |stats| stats.geoip_available else false;
    if (state.geometry != null) try w.writeAll(
        "<button id=\"rotate-left\" class=\"btn btn-sm\" " ++
            "data-action=\"rotate-left\">Rotate left</button>" ++
            "<button id=\"rotate-right\" class=\"btn btn-sm\" " ++
            "data-action=\"rotate-right\">Rotate right</button>" ++
            "<button id=\"reset-globe\" class=\"btn btn-sm\" " ++
            "data-action=\"reset-globe\">Reset</button>" ++
            "<button id=\"flat-map\" class=\"btn btn-sm\" " ++
            "data-action=\"flat-map\">Globe / flat map</button>",
    );
    try w.writeAll("</div>");
    try w.writeAll("<p class=\"sb-note\"><a href=\"https://www.naturalearthdata.com\">" ++
        "Made with Natural Earth</a>. Boundaries provide geographic context.</p>");
    if (state.geometry == null) try w.writeAll(if (state.geometry_busy)
        "<p class=\"sb-note\" role=\"status\">Loading world boundaries…</p>"
    else
        "<p class=\"sb-note\" role=\"status\">World boundaries unavailable. Retrying soon.</p>");
    try description(state, w);
    if (!available) {
        try w.writeAll("<p class=\"sb-note\">GeoIP unavailable. " ++
            "Activity is counted as Unknown; no locations are inferred.</p>" ++
            "<button class=\"btn btn-sm\" " ++
            "data-action=\"geoip\">Set up GeoIP</button>");
    }
    try w.writeAll("<p class=\"sb-note\">" ++
        "Markers show representative country positions, not client coordinates. " ++
        "Arrows illustrate recorded inbound activity over this window; " ++
        "the service hub is not a geographic destination. " ++
        "<a href=\"https://db-ip.com\">IP Geolocation by DB-IP</a>.</p>");
    try rankings(state, w);
}

fn description(state: *const State, w: *Writer) Writer.Error!void {
    if (!state.globe_attacks) return w.writeAll(
        "<p class=\"sb-note\">Sampled traffic over 60 seconds. Sample probability: 1/64.</p>",
    );
    const stats = state.stats orelse return;
    if (stats.incident_geo) |incidents| {
        if (incidents.version == 1) {
            try w.writeAll("<p class=\"sb-note\">Local recorded findings over 60 seconds, " ++
                "including audit findings. Coverage is incomplete: not every blocked " ++
                "request creates an incident, and one request can create several findings. " ++
                "These are not unique attacks. Findings are not sampled.</p>");
            try w.print("<button class=\"btn btn-ghost btn-sm\" data-action=\"globe-coverage\" " ++
                "aria-expanded=\"{s}\" aria-controls=\"incident-geo-coverage\">" ++
                "Incident geography coverage</button>", .{
                if (state.globe_coverage) "true" else "false",
            });
            if (!state.globe_coverage) return w.writeAll(
                "<div id=\"incident-geo-coverage\" hidden></div>",
            );
            var buffer: [64]u8 = undefined;
            var writer: Writer = .fixed(&buffer);
            try @import("events_page.zig").timestamp(&writer, incidents.started_at);
            return html.render(w, @embedFile("snippets/globe-incidents.html"), .{
                .started = writer.buffered(),
                .dropped = incidents.dropped,
                .expired = incidents.expired,
                .future = incidents.future,
                .storage_loss = stats.incidents_dropped,
            });
        }
    }
    try w.writeAll("<p role=\"status\">Incident geography unavailable from this server.</p>");
}

fn markers(state: *const State, bytes: []const u8, w: *Writer) Writer.Error!void {
    const selected = data.view(state) orelse return;
    for (selected.countries) |country| {
        if (country.samples == 0) continue;
        const location = geography.center(bytes, country.code) orelse continue;
        const projected = geography.project(location, state.globe);
        if (!state.globe.flat and projected.z < 0) continue;
        const x = if (state.globe.flat) 200 + location.lon else 200 + 110 * projected.x;
        const y = if (state.globe.flat) 135 - location.lat else 135 - 110 * projected.y;
        const radius = @min(14, 2 * @sqrt(@as(f64, @floatFromInt(country.samples))));
        const code = [_]u8{ @intCast(country.code >> 8), @intCast(country.code & 255) };
        try w.print(
            "<circle cx=\"{d:.1}\" cy=\"{d:.1}\" r=\"{d:.1}\" " ++
                "fill=\"#d94736\" fill-opacity=\".7\" stroke=\"white\">" ++
                "<title>{s}: {d} {s}</title></circle>",
            .{ x, y, radius, code, country.samples, selected.unit },
        );
    }
}

fn rankings(state: *const State, w: *Writer) Writer.Error!void {
    const selected = data.view(state) orelse return;
    try w.print("<table class=\"table\"><caption>Countries across all hemispheres</caption>" ++
        "<thead><tr><th>Country</th><th>{s} / 60 s</th></tr></thead><tbody>", .{selected.unit});
    var any = false;
    for (selected.countries) |country| {
        if (country.samples == 0) continue;
        any = true;
        const code = [_]u8{ @intCast(country.code >> 8), @intCast(country.code & 255) };
        try w.print("<tr><td><button id=\"country-{d}\" class=\"btn btn-ghost btn-sm\" " ++
            "data-action=\"country-{d}\" aria-label=\"Center country {s}\">{s}</button>" ++
            "</td><td>{d}</td></tr>", .{
            country.code, country.code, code, code, country.samples,
        });
    }
    if (!any) {
        try w.writeAll(
            "<tr><td colspan=\"2\">No known-country activity in this window.</td></tr>",
        );
    }
    try w.print("<tr><th>Other countries</th><td>{d}</td></tr>" ++
        "<tr><th>Unknown</th><td>{d}</td></tr></tbody></table>", .{
        selected.other, selected.unknown,
    });
}

test "incident coverage remains explicit while its bounded details are expandable" {
    const t = std.testing;
    var state: State = .{ .globe_attacks = true };
    state.stats = std.mem.zeroes(@import("console_protocol").StatsSnapshot);
    state.stats.?.incident_geo = .{ .started_at = 1, .unknown = 7 };
    var buffer: [32768]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&state, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "Coverage is incomplete") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "aria-expanded=\"false\"") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "id=\"incident-geo-coverage\"") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "<th>Unknown</th><td>7</td>") != null);
    state.globe_coverage = true;
    writer = .fixed(&buffer);
    try render(&state, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "aria-expanded=\"true\"") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "1970-01-01 00:00:01 UTC") != null);
    state.stats.?.incident_geo = null;
    writer = .fixed(&buffer);
    try render(&state, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "Incident geography unavailable") != null);
}
