//! Long identities use full-width labelled values instead of narrow table cells.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const W = std.Io.Writer;

pub fn render(previous: ?p.crs_api.Artifact, next: p.crs_api.Artifact, w: *W) W.Error!void {
    try w.writeAll("<details class=\"mt-4\" open><summary>Source and operator identities" ++
        "</summary><div class=\"grid gap-4 sm:grid-cols-2 mt-3\">");
    if (previous) |artifact| {
        try identity("Current", artifact, w);
    } else try w.writeAll("<div><h3>Current</h3><p>No rules selected.</p></div>");
    try identity("Candidate", next, w);
    try w.writeAll("</div></details>");
}

fn identity(label: []const u8, artifact: p.crs_api.Artifact, w: *W) W.Error!void {
    try html.render(w, "<div class=\"min-w-0\"><h3>{{ label }}</h3><dl>" ++
        "<dt>Source SHA-256</dt><dd class=\"mt-1 mb-3\"><code class=\"break-all\">" ++
        "{{ source }}</code></dd><dt>Operator SHA-256</dt>" ++
        "<dd class=\"mt-1\"><code class=\"break-all\">{{ operator }}</code></dd></dl></div>", .{
        .label = label,
        .source = artifact.source_digest.slice(),
        .operator = artifact.operator_digest.slice(),
    });
}
