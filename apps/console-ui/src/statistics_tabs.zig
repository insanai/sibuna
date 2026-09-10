const html = @import("html");
const Writer = @import("std").Io.Writer;

pub fn render(security: bool, w: *Writer) Writer.Error!void {
    try html.render(w, @embedFile("snippets/statistics-tabs.html"), .{
        .traffic = if (security) "false" else "true",
        .security = if (security) "true" else "false",
        .traffic_class = if (security) "" else "tab-active",
        .security_class = if (security) "tab-active" else "",
    });
}
