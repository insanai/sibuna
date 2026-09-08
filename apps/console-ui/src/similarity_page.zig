const std = @import("std");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
const html = @import("html");

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.similarity;
    try html.render(w, @embedFile("snippets/similarity-header.html"), .{
        .source = model.source,
    });
    try @import("render.zig").message(state, w);
    const status = if (model.unavailable) "Unavailable" else if (model.complete)
        "Complete"
    else if (model.running) "Searching" else "Paused";
    try html.render(w, @embedFile("snippets/similarity-status.html"), .{
        .status = status,
        .scanned = model.scanned,
        .invalid = model.invalid,
    });
    if (!model.complete) try html.render(w, @embedFile("snippets/similarity-control.html"), .{
        .action = if (model.running) "similarity-pause" else "similarity-resume",
        .label = if (model.running) "Pause search" else "Resume search",
    });
    if (model.unavailable) {
        try html.render(
            w,
            "<p class=\"sb-note mt-4\">The source has no usable retained " ++
                "vector. " ++
                "Choose another incident.</p></main>",
            .{},
        );
        return;
    }
    try html.render(w, "<section class=\"sb-panel mt-6\"><h2>Closest matches</h2>", .{});
    if (!model.complete) try html.render(
        w,
        "<p class=\"sb-note\">Partial results while scanning. " ++
            "Each read examines at most 64 records and yields to other console work.</p>",
        .{},
    );
    if (model.best.count == 0) try html.render(
        w,
        "<p>No comparable incidents found so far.</p>",
        .{},
    );
    for (model.best.rows[0..model.best.count]) |row| try match(w, row);
    try html.render(w, @embedFile("snippets/similarity-footer.html"), .{});
}

fn match(w: *Writer, row: @import("console_protocol").similarity.Match) Writer.Error!void {
    var distance_buffer: [32]u8 = undefined;
    // Validated cosine distances are finite and in [0, 2].
    const distance = std.fmt.bufPrint(&distance_buffer, "{d:.5}", .{row.distance}) catch
        unreachable;
    var time_buffer: [64]u8 = undefined;
    var time_writer: Writer = .fixed(&time_buffer);
    try @import("events_page.zig").timestamp(&time_writer, row.time);
    try html.render(w, @embedFile("snippets/similarity-match.html"), .{
        .id = row.id,
        .node = row.node,
        .distance = distance,
        .timestamp = time_writer.buffered(),
    });
}
