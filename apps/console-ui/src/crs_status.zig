//! A local observation sits with its node, separate from policy commit state.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const Writer = std.Io.Writer;

pub fn render(optional: ?p.crs.Status, writer: *Writer) Writer.Error!void {
    try writer.writeAll("<section class=\"sb-panel\"><h2>Core Rule Set</h2>");
    const status = optional orelse {
        return writer.writeAll("<p>This node did not report CRS status.</p></section>");
    };
    const selected = status.selection orelse {
        return writer.writeAll("<p>No CRS generation configured. " ++
            "Native CRS inspection is disabled.</p></section>");
    };
    try html.render(writer, @embedFile("snippets/crs-node-status.html"), .{
        .mode = switch (selected.mode) {
            .off => "Off",
            .audit => "Audit — findings do not enforce denials",
            .enforce => "Enforce",
        },
        .profile = switch (selected.profile) {
            .full => "Request and response headers and bounded bodies",
            .headers => "Request headers; bodies and origin responses unobserved",
        },
        .release = if (selected.release.len == 0) "No artifact" else selected.release.slice(),
        .revision = selected.revision,
        .digest = if (selected.source_digest.len == 0)
            "Not applicable; no artifact"
        else
            selected.source_digest.slice(),
        .operator_digest = if (selected.operator_digest.len == 0)
            "Not applicable; no artifact"
        else
            selected.operator_digest.slice(),
        .blocking = selected.blocking_paranoia,
        .detection = selected.detection_paranoia,
        .inbound = selected.inbound_threshold,
        .outbound = selected.outbound_threshold,
        .compiled = selected.compiled_peak,
        .reserved = selected.reserved_bytes,
        .slots = selected.slots,
        .request = selected.request_bytes,
        .response = selected.response_bytes,
        .work = selected.work_budget,
        .timeout = selected.timeout_ms / 1000,
        .inspected = status.counts.inspected,
        .headers = status.counts.headers,
        .handshake = status.counts.handshake,
        .streaming = status.counts.streaming,
        .incomplete = status.counts.incomplete,
        .denied = status.counts.denied,
        .would_deny = status.counts.would_deny,
    });
    try writer.writeAll("</section>");
}
