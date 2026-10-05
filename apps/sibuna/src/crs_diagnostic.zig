//! Consistent native diagnostics for all off-path CRS preparation commands.
const std = @import("std");
const Diagnostic = @import("crs").release_package.Diagnostic;

pub fn report(value: ?Diagnostic) void {
    const diagnostic = value orelse return;
    std.debug.print("CRSCOMPILE/{s}: {s} ({s})\n", .{
        @tagName(diagnostic.code), diagnostic.explanation(), diagnostic.cause.slice(),
    });
    if (diagnostic.path.len != 0) std.debug.print("  Source: {s}{s}\n", .{
        diagnostic.path.slice(), if (diagnostic.path_truncated) " (truncated)" else "",
    });
    if (diagnostic.line) |line| std.debug.print("  Line: {d}\n", .{line});
    if (diagnostic.rule) |rule| std.debug.print("  Rule: {d}\n", .{rule});
    std.debug.print("  Hint: {s}\n", .{diagnostic.hint()});
}
