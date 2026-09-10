//! Tiles and comparison tables give missing coverage and zero references the same meaning.
const std = @import("std");
const Change = @import("console_protocol").minute_summary.Deviation;

pub fn tinted(change: Change) bool {
    return switch (change) {
        .percent => |percent| @abs(percent) >= 25,
        .new => true,
        .unavailable => false,
    };
}

pub fn write(w: *std.Io.Writer, change: Change) std.Io.Writer.Error!void {
    switch (change) {
        .unavailable => try w.writeAll("Not available"),
        .new => try w.writeAll("↑ New"),
        .percent => |percent| try w.print("{s} {d:.1}%", .{
            if (percent > 0) "↑" else if (percent < 0) "↓" else "→",
            @abs(percent),
        }),
    }
}
