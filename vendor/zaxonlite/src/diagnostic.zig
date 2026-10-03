//! Elm-style, operator-oriented command diagnostics.

const std = @import("std");

pub fn write(
    out: *std.Io.Writer,
    title: []const u8,
    message: []const u8,
    hint: []const u8,
) !void {
    try out.writeAll("-- ");
    for (title) |byte| try out.writeByte(std.ascii.toUpper(byte));
    try out.writeAll(" --\n\n");
    try out.writeAll(message);
    try out.writeAll("\n\nHint: ");
    try out.writeAll(hint);
    try out.writeByte('\n');
}

test "diagnostic has a boundary, explanation, and hint" {
    var buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try write(&writer, "not leader", "This node cannot write.", "Retry another node.");
    const text = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, text, "-- NOT LEADER --") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "Hint: Retry") != null);
}
