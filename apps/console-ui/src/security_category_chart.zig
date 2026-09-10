//! The donut includes an explicit remainder. A top-five slice is never the denominator.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const Writer = std.Io.Writer;
const colours = [_][]const u8{ "#0284c7", "#7c3aed", "#d97706", "#059669", "#db2777" };

pub fn render(w: *Writer, rows: *const [5]?p.security.Rank, total: u64) Writer.Error!void {
    if (total == 0) return;
    try w.writeAll("<svg viewBox=\"0 0 240 140\" role=\"img\" " ++
        "aria-label=\"Attack category share; exact counts in the table below\">" ++
        "<circle cx=\"120\" cy=\"70\" r=\"48\" fill=\"none\" " ++
        "stroke=\"#94a3b8\" stroke-width=\"20\"/>");
    var offset: f64 = 0;
    var shown: u64 = 0;
    const circumference = 2 * std.math.pi * 48;
    for (rows, colours) |entry, colour| if (entry) |row| {
        const count = @min(row.count, total -| shown);
        const length = @as(f64, @floatFromInt(count)) / @as(f64, @floatFromInt(total)) *
            circumference;
        try w.print(
            "<circle cx=\"120\" cy=\"70\" r=\"48\" fill=\"none\" " ++
                "stroke=\"{s}\" stroke-width=\"20\" stroke-dasharray=\"{d:.3} {d:.3}\" " ++
                "stroke-dashoffset=\"{d:.3}\" transform=\"rotate(-90 120 70)\"/>",
            .{ colour, length, circumference - length, -offset },
        );
        offset += length;
        shown += count;
    };
    try html.render(
        w,
        "</svg><p class=\"sb-note\">{{ total }} recorded findings. " ++
            "{{ other }} outside the top five (grey).</p>",
        .{ .total = total, .other = total -| shown },
    );
}
