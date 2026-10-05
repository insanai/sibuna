//! Safe source metadata has one presentation shared by candidates and private tests.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
pub fn render(
    w: *std.Io.Writer,
    diagnostic: p.crs_management.Diagnostic,
) std.Io.Writer.Error!void {
    try html.render(w, "<p><strong>CRSCOMPILE/{{ code }}</strong>: {{ explanation }} " ++
        "({{ cause }})</p><p class=\"break-all\">Source: {{ path }}{{ truncated }}</p>", .{
        .code = @tagName(diagnostic.code),
        .explanation = diagnostic.explanation(),
        .cause = diagnostic.cause.slice(),
        .path = if (diagnostic.path.len == 0) "Not available" else diagnostic.path.slice(),
        .truncated = if (diagnostic.path_truncated) " (truncated)" else "",
    });
    if (diagnostic.line) |line| try html.render(w, "<p>Line: {{ line }}</p>", .{ .line = line });
    if (diagnostic.rule) |rule| try html.render(w, "<p>Rule: {{ rule }}</p>", .{ .rule = rule });
    try html.render(w, "<p>Hint: {{ hint }}</p>", .{ .hint = diagnostic.hint() });
}
