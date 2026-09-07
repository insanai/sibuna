const std = @import("std");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.similarity;
    try w.writeAll("<main class=\"sb-main min-h-screen\"><header class=\"sb-header\"><div>" ++
        "<p class=\"sb-subtitle\">INVESTIGATION / SIMILARITY SEARCH</p>" ++
        "<h1 id=\"page-heading\" tabindex=\"-1\">Similar incidents</h1></div>" ++
        "<button class=\"btn\" data-action=\"events\">Back to events</button></header>");
    try w.print("<p class=\"mt-4\">Source incident #{d}. Searching the selected time range " ++
        "across nodes.</p>", .{model.source});
    try w.writeAll("<p class=\"sb-note\">Cosine distance between stored 64-dimensional " ++
        "payload fingerprints: lower means more similar. This heuristic is not attribution " ++
        "or proof of a common attacker. Raw payloads are not returned.</p>");
    if (state.message.len != 0) {
        try w.writeAll("<p class=\"sb-error mt-4\" role=\"status\">");
        try @import("render.zig").escape(w, state.message.slice());
        try w.writeAll("</p>");
    }
    try w.print("<p class=\"mt-4\" role=\"status\">{s}: {d} records scanned, " ++
        "{d} missing or invalid vectors.</p>", .{
        if (model.unavailable) "Unavailable" else if (model.complete)
            "Complete"
        else if (model.running) "Searching" else "Paused",
        model.scanned,
        model.invalid,
    });
    if (!model.complete) try w.print(
        "<button class=\"btn mt-3\" data-action=\"{s}\">{s}</button>",
        .{
            if (model.running) "similarity-pause" else "similarity-resume",
            if (model.running) "Pause search" else "Resume search",
        },
    );
    if (model.unavailable) {
        try w.writeAll("<p class=\"sb-note mt-4\">The source has no usable retained vector. " ++
            "Choose another incident.</p></main>");
        return;
    }
    try w.writeAll("<section class=\"sb-panel mt-6\"><h2>Closest matches</h2>");
    if (!model.complete) try w.writeAll("<p class=\"sb-note\">Partial results while scanning. " ++
        "Each read examines at most 64 records and yields to other console work.</p>");
    if (model.best.count == 0) try w.writeAll("<p>No comparable incidents found so far.</p>");
    for (model.best.rows[0..model.best.count]) |row| {
        try w.print("<article class=\"border-b border-base-300 py-4\">" ++
            "<h3>Incident #{d}</h3><p>Node {d} · Cosine distance {d:.5}</p><p>", .{
            row.id, row.node, row.distance,
        });
        try @import("events_page.zig").timestamp(w, row.time);
        try w.print("</p><button class=\"btn mt-3\" data-action=\"events-incident-{d}\" " ++
            "aria-label=\"Inspect incident #{d}\">Inspect incident</button></article>", .{
            row.id, row.id,
        });
    }
    try w.writeAll("<p class=\"sb-note mt-4\">The time boundary stays fixed during the search. " ++
        "Records removed by retention while scanning may be absent. Missing vectors remain " ++
        "visible in coverage; the result is not a transactional snapshot.</p></section></main>");
}
