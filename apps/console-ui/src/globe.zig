const std = @import("std");
const State = @import("state.zig").State;
const geography = @import("geography.zig");
const Writer = std.Io.Writer;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    try w.writeAll("<h2>Live earth globe</h2><svg viewBox=\"0 0 400 280\" role=\"img\" " ++
        "aria-label=\"Country traffic. Representative country positions; see the table below.\">");
    if (state.globe.flat) {
        try w.writeAll("<rect x=\"20\" y=\"45\" width=\"360\" height=\"180\" " ++
            "fill=\"#e7f1fc\" stroke=\"#94b6d5\"/>");
    } else try w.writeAll("<circle cx=\"200\" cy=\"135\" r=\"110\" " ++
        "fill=\"#e7f1fc\" stroke=\"#94b6d5\"/>");
    const available = if (state.stats) |stats| stats.geoip_available else false;
    if (available) {
        if (!state.globe.flat) try w.writeAll("<defs><clipPath id=\"globe-clip\">" ++
            "<circle cx=\"200\" cy=\"135\" r=\"110\"/></clipPath></defs>" ++
            "<g clip-path=\"url(#globe-clip)\">");
        if (state.geometry) |bytes| {
            try geography.render(bytes, state.globe, w);
            try markers(state, bytes, w);
        }
        if (!state.globe.flat) try w.writeAll("</g>");
    }
    try w.writeAll("</svg><div class=\"sb-globe-controls\">");
    if (available) try w.writeAll(
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
    if (!available) {
        try w.writeAll("<p class=\"sb-note\">GeoIP unavailable. Traffic is counted as Unknown; " ++
            "no locations are inferred.</p><button class=\"btn btn-sm\" " ++
            "data-action=\"geoip\">Set up GeoIP</button>");
        return;
    }
    try w.writeAll("<p class=\"sb-note\">Sampled traffic over 60 seconds. " ++
        "Markers show representative country positions, not client coordinates. " ++
        "<a href=\"https://db-ip.com\">IP Geolocation by DB-IP</a> · " ++
        "<a href=\"https://www.naturalearthdata.com\">Made with Natural Earth</a>.</p>");
    try rankings(state, w);
}

fn markers(state: *const State, bytes: []const u8, w: *Writer) Writer.Error!void {
    const stats = state.stats orelse return;
    for (stats.countries) |country| {
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
                "<title>{s}: {d} samples</title></circle>",
            .{ x, y, radius, code, country.samples },
        );
    }
}

fn rankings(state: *const State, w: *Writer) Writer.Error!void {
    const stats = state.stats orelse return;
    try w.writeAll("<table class=\"table\"><caption>Countries across all hemispheres</caption>" ++
        "<thead><tr><th>Country</th><th>Samples</th></tr></thead><tbody>");
    var any = false;
    for (stats.countries) |country| {
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
        try w.writeAll("<tr><td colspan=\"2\">No known-country samples in this window.</td></tr>");
    }
    try w.print("<tr><th>Other countries</th><td>{d}</td></tr>" ++
        "<tr><th>Unknown</th><td>{d}</td></tr></tbody></table>", .{
        stats.other_country_samples, stats.unknown_samples,
    });
}
