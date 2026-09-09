const html = @import("html");
const std = @import("std");
const State = @import("state.zig").State;
const escape = @import("render.zig").escape;

fn dbip(state: *const State) bool {
    return std.mem.eql(u8, state.geo.provider.slice(), "dbip");
}

pub fn render(state: *const State, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try html.render(w, "<main class=\"sb-main min-h-screen\"><header class=\"sb-header\"><div>" ++
        "<p class=\"sb-subtitle\">COUNTRY ENRICHMENT</p>" ++
        "<h1 id=\"page-heading\" tabindex=\"-1\">GeoIP</h1></div>" ++
        "<button class=\"btn\" data-action=\"dashboard\">Back to dashboard</button></header>" ++
        "<section class=\"sb-panel mt-6\">", .{});
    if (dbip(state)) {
        try html.render(w, "<h2>DB-IP IP to Country Lite</h2>" ++
            "<p>Monthly country data, licensed under CC BY 4.0. " ++
            "<a href=\"https://db-ip.com/db/lite.php\">IP Geolocation by DB-IP</a>.</p>", .{});
    } else {
        try html.render(w, "<h2>ip-location-db user-country</h2>" ++
            "<p>Daily country data in the public domain (PDDL 1.0); " ++
            "no attribution is required.</p>", .{});
    }
    try html.render(
        w,
        "<p>Active revision: {{ v0 }} · Known ranges loaded: {{ v1 " ++
            "}} · Source version: ",
        .{
            .v0 = state.geo.revision,
            .v1 = state.geo.ranges,
        },
    );
    try escape(w, state.geo.source_version.slice());
    try w.writeAll("</p><p>Status: ");
    try escape(w, state.geo_status.slice());
    try html.render(w, " · {{ v0 }} ranges processed</p>", .{
        .v0 = state.geo_progress,
    });
    if (std.mem.eql(u8, state.geo_status.slice(), "failed")) try w.writeAll(
        "<p role=\"status\" class=\"sb-error\">Import failed. " ++
            "The previous generation remains active. " ++
            "Check the provider, published version, network connection, CSV, " ++
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
    try form(state, w);
}

fn form(state: *const State, w: *std.Io.Writer) std.Io.Writer.Error!void {
    const dbip_selected = dbip(state);
    try html.render(w, "<form id=\"geo-import\" class=\"sb-settings-form\">" ++
        "<label for=\"provider\">Provider</label>" ++
        "<select id=\"provider\" name=\"provider\" class=\"select select-bordered\">" ++
        "<option value=\"user-country\"{{ v0 }}>ip-location-db user-country " ++
        "(public domain, daily)</option>" ++
        "<option value=\"dbip\"{{ v1 }}>DB-IP IP to Country Lite (CC BY 4.0, monthly)" ++
        "</option></select>" ++
        "<label for=\"source_version\">Published version (YYYY-MM-DD, or YYYY-MM for DB-IP)" ++
        "</label><input id=\"source_version\" name=\"source_version\" " ++
        "class=\"input input-bordered\" required pattern=\"[0-9]{4}-[0-9]{2}(-[0-9]{2})?\" " ++
        "maxlength=\"10\" value=\"", .{
        .v0 = if (dbip_selected) "" else " selected",
        .v1 = if (dbip_selected) " selected" else "",
    });
    try escape(w, state.geo.source_version.slice());
    try html.render(
        w,
        "\"><label for=\"checksum\">Operator SHA-256 of the source bytes (optional)</label>" ++
            "<input id=\"checksum\" name=\"checksum\" class=\"input input-bordered\" " ++
            "maxlength=\"64\">" ++
            "<p class=\"sb-note\">Publisher checksums are always verified when the provider " ++
            "publishes them; an independently supplied digest also pins the expected files.</p>" ++
            "<details><summary>Import a small CSV instead</summary>" ++
            "<label for=\"csv\">Address start, address end, country code (up to 8 KiB)</label>" ++
            "<textarea id=\"csv\" name=\"csv\" class=\"textarea textarea-bordered\" rows=\"5\" " ++
            "maxlength=\"8192\"></textarea></details>" ++
            "<p class=\"sb-note\">Otherwise the console downloads " ++
            "the selected version from the provider over HTTPS. " ++
            "Invalid data never replaces the active database.</p>" ++
            "<button class=\"btn btn-primary\" type=\"submit\"",
        .{},
    );
    if (state.geo_importing) try w.writeAll(" disabled aria-busy=\"true\"");
    try html.render(w, ">Import country data</button></form></section></main>", .{});
}
