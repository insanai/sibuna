const html = @import("html");
const std = @import("std");
const State = @import("state.zig").State;
const escape = @import("render.zig").escape;

pub fn render(state: *const State, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try html.render(w, "<main class=\"sb-main min-h-screen\"><header class=\"sb-header\"><div>" ++
        "<p class=\"sb-subtitle\">COUNTRY ENRICHMENT</p>" ++
        "<h1 id=\"page-heading\" tabindex=\"-1\">GeoIP</h1></div>" ++
        "<button class=\"btn\" data-action=\"dashboard\">Back to dashboard</button></header>" ++
        "<section class=\"sb-panel mt-6\"><h2>DB-IP IP to Country Lite</h2>" ++
        "<p>Monthly country data, licensed under CC BY 4.0. " ++
        "<a href=\"https://db-ip.com/db/lite.php\">IP Geolocation by DB-IP</a>.</p>", .{});
    try html.render(
        w,
        "<p>Active revision: {{ v0 }} · Known ranges loaded: {{ v1 " ++
            "}}</p><p>Status: ",
        .{
            .v0 = state.geo.revision,
            .v1 = state.geo.ranges,
        },
    );
    try escape(w, state.geo_status.slice());
    try html.render(w, " · {{ v0 }} ranges processed</p>", .{
        .v0 = state.geo_progress,
    });
    if (std.mem.eql(u8, state.geo_status.slice(), "failed")) try w.writeAll(
        "<p role=\"status\" class=\"sb-error\">Import failed. " ++
            "The previous generation remains active. " ++
            "Check the published month, network connection, CSV, " ++
            "and checksum before retrying.</p>",
    );
    if (state.message.len != 0) {
        try html.render(w, "<p role=\"status\" class=\"sb-error\">", .{});
        try escape(w, state.message.slice());
        try html.render(w, "</p>", .{});
    }
    if (!std.mem.eql(u8, state.role.slice(), "admin")) {
        try html.render(
            w,
            "<p>An administrator can import a country " ++
                "database.</p></section></main>",
            .{},
        );
        return;
    }
    try html.render(w, "<form id=\"geo-import\" class=\"sb-settings-form\">" ++
        "<label for=\"source_version\">Published month</label>" ++
        "<input id=\"source_version\" name=\"source_version\" type=\"month\" " ++
        "class=\"input input-bordered\" required value=\"", .{});
    try escape(w, state.geo.source_version.slice());
    try html.render(
        w,
        "\"><label for=\"checksum\">Publisher or operator SHA-256 " ++
            "(optional)</label>" ++
            "<input id=\"checksum\" name=\"checksum\" class=\"input input-bordered\" " ++
            "maxlength=\"64\">" ++
            "<p class=\"sb-note\">A locally computed digest identifies the download; " ++
            "an independently supplied checksum also verifies the expected file.</p>" ++
            "<details><summary>Import a small DB-IP CSV instead</summary>" ++
            "<label for=\"csv\">Address start, address end, country code (up to 8 KiB)</label>" ++
            "<textarea id=\"csv\" name=\"csv\" class=\"textarea textarea-bordered\" rows=\"5\" " ++
            "maxlength=\"8192\"></textarea></details>" ++
            "<p class=\"sb-note\">Otherwise the console downloads " ++
            "this month from DB-IP over HTTPS. " ++
            "Invalid data never replaces the active database.</p>" ++
            "<button class=\"btn btn-primary\" type=\"submit\"",
        .{},
    );
    if (state.geo_importing) try w.writeAll(" disabled aria-busy=\"true\"");
    try html.render(w, ">Import country data</button></form></section></main>", .{});
}
