//! Render validated scalar findings. Coverage is independent of the decision:
//! a request denial can precede the origin and still be a complete local ending.
const std = @import("std");
const html = @import("html");
const Crs = @import("console_protocol").events.security_evidence.Crs;
const Writer = std.Io.Writer;

pub fn decision(evidence: Crs, writer: *Writer) Writer.Error!void {
    if (evidence.denied) {
        return html.render(writer, "Security inspection selected status {{ status }}. " ++
            "Delivery is not recorded.", .{
            .status = evidence.selected_status,
        });
    }
    if (evidence.would_deny and !evidence.enforcing) {
        return writer.writeAll("Audit finding: this rule would deny in enforce mode. " ++
            "Delivery is not recorded.");
    }
    return writer.writeAll("This finding did not deny the exchange. Delivery is not recorded.");
}

pub fn render(evidence: Crs, writer: *Writer) Writer.Error!void {
    const digest = std.fmt.bytesToHex(&evidence.source_digest, .lower);
    try html.render(writer, "<dt>CRS rule</dt><dd>{{ rule }}</dd>" ++
        "<dt>Inspection phase</dt><dd>{{ phase }}</dd>" ++
        "<dt>Severity</dt><dd>{{ severity }}</dd>" ++
        "<dt>Mode</dt><dd>{{ mode }}</dd>" ++
        "<dt>Coverage</dt><dd>{{ coverage }}</dd>" ++
        "<dt>Paranoia levels</dt><dd>Blocking {{ blocking }}; detection {{ detection }}</dd>" ++
        "<dt>Applied revision</dt><dd>{{ revision }}</dd>" ++
        "<dt>Signed release SHA-256</dt><dd class=\"break-all\">{{ digest }}</dd>" ++
        "<dt>Rule message and tags</dt><dd>Not retained: " ++
        "expanded values may contain secrets.</dd>" ++
        "<dt>Score contributions</dt><dd>Not recorded.</dd>", .{
        .rule = evidence.rule_id,
        .phase = phase(evidence.phase),
        .severity = severity(evidence.severity),
        .mode = if (evidence.enforcing) "Enforce" else "Audit",
        .coverage = coverage(evidence.coverage),
        .blocking = evidence.blocking_paranoia,
        .detection = evidence.detection_paranoia,
        .revision = evidence.revision,
        .digest = &digest,
    });
}

fn phase(value: u8) []const u8 {
    return switch (value) {
        1 => "1 — Request headers",
        2 => "2 — Request body",
        3 => "3 — Response headers",
        4 => "4 — Response body",
        5 => "5 — Logging",
        else => unreachable,
    };
}

fn severity(value: u8) []const u8 {
    return switch (value) {
        0 => "0 — Emergency",
        1 => "1 — Alert",
        2 => "2 — Critical",
        3 => "3 — Error",
        4 => "4 — Warning",
        5 => "5 — Notice",
        6 => "6 — Information",
        7 => "7 — Debug",
        else => unreachable,
    };
}

fn coverage(value: @import("console_protocol").events.security_evidence.Coverage) []const u8 {
    return switch (value) {
        .incomplete => "Incomplete inspection; a limit or transport failure " ++
            "interrupted evaluation",
        .inspected => "Request and response inspected",
        .headers_profile => "Request headers inspected; request and response bodies unobserved",
        .local_response => "Ended locally; later origin phases were not reached",
        .origin_unavailable => "Origin unavailable; response phases were not reached",
        .handshake_only => "WebSocket handshake inspected; tunnel frames excluded",
        .streaming_excluded => "Response headers inspected; streaming body explicitly excluded",
    };
}
