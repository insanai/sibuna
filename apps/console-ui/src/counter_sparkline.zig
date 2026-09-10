//! Missing observations break the line. Pixel projection may round; accompanying tables
//! retain exact u64 values and distinguish missing data from observed zero.
const std = @import("std");
const html = @import("html");
const Writer = std.Io.Writer;

pub fn render(w: *Writer, values: []const ?u64, label: []const u8) Writer.Error!void {
    std.debug.assert(values.len > 0 and values.len <= 60);
    var maximum: u64 = 1;
    for (values) |value| if (value) |count| {
        maximum = @max(maximum, count);
    };
    const projection: Projection = .{ .maximum = maximum, .length = values.len };
    try html.render(w, "<svg viewBox=\"0 0 240 48\" width=\"240\" height=\"48\" " ++
        "class=\"max-w-full text-primary\" role=\"img\" aria-label=\"{{ label }}\">" ++
        "<path fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" d=\"", .{
        .label = label,
    });
    var pen = false;
    for (values, 0..) |value, index| {
        const count = value orelse {
            pen = false;
            continue;
        };
        const point = projection.point(index, count);
        try w.print("{s}{d:.2} {d:.2} ", .{ if (pen) "L" else "M", point.x, point.y });
        pen = true;
    }
    try w.writeAll("\"/>");
    for (values, 0..) |value, index| if (value) |count| {
        const point = projection.point(index, count);
        try w.print(
            "<circle cx=\"{d:.2}\" cy=\"{d:.2}\" r=\"2\" fill=\"currentColor\"/>",
            .{ point.x, point.y },
        );
    };
    try w.writeAll("</svg>");
}

const Projection = struct {
    maximum: u64,
    length: usize,

    fn point(self: Projection, index: usize, value: u64) struct { x: f64, y: f64 } {
        return .{
            .x = if (self.length == 1) 120 else 4 + @as(f64, @floatFromInt(index)) * 232 /
                @as(f64, @floatFromInt(self.length - 1)),
            .y = 44 - @as(f64, @floatFromInt(value)) * 40 /
                @as(f64, @floatFromInt(self.maximum)),
        };
    }
};
