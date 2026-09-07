//! Elm-style, operator-oriented diagnostics for Sibuna.
//!
//! Formats errors with clear boundaries, plain-English explanations,
//! and actionable hints indicating what can be done instead.

const std = @import("std");

pub const Diagnostic = struct {
    title: []const u8,
    message: []const u8,
    hint: []const u8,

    pub fn format(
        self: Diagnostic,
        writer: anytype,
    ) !void {
        try writer.writeAll("-- ");
        for (self.title) |byte| {
            try writer.writeByte(std.ascii.toUpper(byte));
        }
        try writer.writeAll(" ");
        var remaining: usize = 0;
        if (self.title.len + 4 < 76) {
            remaining = 76 - (self.title.len + 4);
        }
        var i: usize = 0;
        while (i < remaining) : (i += 1) {
            try writer.writeByte('-');
        }
        try writer.writeAll("\n\n");
        try writer.writeAll(self.message);
        try writer.writeAll("\n\nHint: ");
        try writer.writeAll(self.hint);
        try writer.writeByte('\n');
    }
};

pub fn write(
    writer: anytype,
    title: []const u8,
    message: []const u8,
    hint: []const u8,
) !void {
    const diag = Diagnostic{
        .title = title,
        .message = message,
        .hint = hint,
    };
    try diag.format(writer);
}

test "diagnostic format has boundary, explanation, and hint" {
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try write(
        &writer,
        "invalid challenge",
        "The submitted nonce does not satisfy the difficulty threshold.",
        "Ensure the client Web Worker completes all hashing iterations.",
    );
    const text = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, text, "-- INVALID CHALLENGE --") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "Hint: Ensure the client") != null);
}
