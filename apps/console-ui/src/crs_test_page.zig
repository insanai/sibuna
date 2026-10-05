//! Test data stays in the current form. Reports contain owned scalar metadata.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const State = @import("state.zig").State;
const W = std.Io.Writer;

pub fn render(state: *const State, w: *W) W.Error!void {
    const model = &state.crs;
    const snapshot = model.snapshot orelse return;
    const source = model.reviewed orelse snapshot.current orelse return;
    try html.render(w, @embedFile("snippets/crs-test.html"), .{
        .source_kind = if (model.reviewed != null) "Reviewed" else "Selected",
        .source = source.id.slice(),
        .disabled = if (model.busy != .idle or model.stale or model.reviewPending())
            " disabled"
        else
            "",
    });
    if (model.test_result) |result| {
        try html.render(w, "<section id=\"crs-test-result\" class=\"sb-panel mt-4\">" ++
            "<h2>Private test result</h2><p>State: {{ state }}</p>" ++
            "<p>Origin contacted: no · Active protection: unchanged</p>", .{
            .state = @tagName(result.state),
        });
        if (result.state == .queued or result.state == .running) {
            try w.writeAll("<p role=\"status\">Waiting for the private worker. " ++
                "No completed evaluation is available yet.</p></section>");
            return;
        }
        if (p.crs_management.validId(result.source)) {
            try html.render(w, "<p>Saved revision at test: {{ revision }}</p>", .{
                .revision = result.expected_revision,
            });
            if (result.expected_revision != snapshot.revision) try w.writeAll(
                "<p class=\"sb-note\">The saved revision changed. This result describes " ++
                    "the earlier candidate; refresh and retest before selecting rules.</p>",
            );
        }
        try identity(w, result);
        if (result.diagnostic) |diagnostic|
            try @import("crs_diagnostic_page.zig").render(w, diagnostic);
        if (result.failure) |cause| try html.render(
            w,
            "<p role=\"status\" class=\"sb-error\">Test refused: {{ cause }}. " ++
                "Refresh the saved revision and check sample fields and resource limits.</p>",
            .{ .cause = cause.slice() },
        );
        if (result.report) |report| try details(w, report);
        try w.writeAll("</section>");
    } else if (model.test_id != null) try w.writeAll(
        "<p class=\"sb-note mt-4\" role=\"status\">Private test queued. " ++
            "Results are temporary and are available to this session.</p>",
    );
}

fn identity(w: *W, result: p.crs_tests.Status) W.Error!void {
    if (!p.crs_management.validId(result.source)) return;
    const source = result.source.slice();
    try html.render(w, "<p>Tested candidate: " ++
        "<code class=\"break-all\">{{ source }}</code></p>", .{ .source = source });
    if (result.artifact) |artifact| {
        try html.render(w, "<p>CRS {{ release }} · Blocking/detection paranoia " ++
            "{{ blocking }}/{{ detection }} · Inbound/outbound thresholds " ++
            "{{ inbound }}/{{ outbound }}</p><p>Source SHA-256: " ++
            "<code class=\"break-all\">{{ digest }}</code></p>" ++
            "<p>Operator rules SHA-256: <code class=\"break-all\">{{ operator }}</code></p>", .{
            .release = artifact.release.slice(),
            .blocking = artifact.settings.blocking_paranoia,
            .detection = artifact.settings.detection_paranoia,
            .inbound = artifact.settings.inbound_threshold,
            .outbound = artifact.settings.outbound_threshold,
            .digest = artifact.source_digest.slice(),
            .operator = artifact.operator_digest.slice(),
        });
    }
}

fn details(w: *W, report: p.crs_tests.sample.Report) W.Error!void {
    try html.render(w, "<p>Mode: {{ mode }} · Profile: {{ profile }} · " ++
        "Coverage: {{ coverage }}</p><p>Would deny: {{ would_deny }} · Enforcing denial: " ++
        "{{ denied }} · Work used: {{ work }}</p>", .{
        .mode = @tagName(report.mode),
        .profile = @tagName(report.profile),
        .coverage = coverage(report.coverage),
        .would_deny = if (report.would_deny) "yes" else "no",
        .denied = if (report.denied) "yes" else "no",
        .work = report.work_used,
    });
    if (report.failure) |cause| {
        try html.render(w, "<p class=\"sb-error\">Incomplete evaluation: {{ cause }}. " ++
            "This is not a complete inspection.</p>", .{ .cause = cause.slice() });
    }
    if (report.selected_status) |status| {
        try html.render(w, "<p>Selected denial status: {{ status }}</p>", .{ .status = status });
    }
    try score(w, "Blocking inbound score", report.inbound_score);
    try score(w, "Detection inbound score", report.detection_inbound_score);
    try score(w, "Blocking outbound score", report.outbound_score);
    try score(w, "Detection outbound score", report.detection_outbound_score);
    try w.writeAll("<div class=\"overflow-x-auto mt-4\"><table class=\"table\">" ++
        "<thead><tr><th>Rule</th><th>Phase</th><th>Severity</th><th>Would deny</th>" ++
        "</tr></thead><tbody>");
    for (report.events[0..report.event_count]) |item| {
        const event = item.?;
        try html.render(w, "<tr><td>{{ id }}</td><td>{{ phase }}</td><td>{{ severity }}" ++
            "</td><td>{{ denial }}</td></tr>", .{
            .id = event.rule_id,
            .phase = event.phase,
            .severity = event.severity,
            .denial = if (event.would_deny) "yes" else "no",
        });
    }
    try html.render(w, "</tbody></table></div><p>{{ count }} findings shown · " ++
        "{{ omitted }} additional findings omitted · " ++
        "{{ unlogged }} unlogged matches excluded.</p>", .{
        .count = report.event_count,
        .omitted = report.omitted_events,
        .unlogged = report.unlogged_matches,
    });
}

fn score(w: *W, label: []const u8, value: ?i32) W.Error!void {
    if (value) |number| {
        try html.render(w, "<p>{{ label }}: {{ value }}</p>", .{
            .label = label,
            .value = number,
        });
    } else try html.render(w, "<p>{{ label }}: not recorded</p>", .{ .label = label });
}

fn coverage(value: p.crs_tests.sample.Coverage) []const u8 {
    return switch (value) {
        .disabled => "disabled",
        .incomplete => "incomplete",
        .inspected => "request and response inspected",
        .headers_profile => "request headers inspected; bodies and response excluded",
        .local_response => "terminal local response; later phases excluded",
        .response_not_supplied => "request inspected; no response supplied",
        .handshake_only => "handshake headers inspected; tunnel data excluded",
        .streaming_excluded => "response headers inspected; stream data excluded",
    };
}

test "queued private tests cannot show revision zero as a completed stale result" {
    const t = std.testing;
    const state = try t.allocator.create(State);
    defer t.allocator.destroy(state);
    state.* = .{};
    @import("crs_fixture.zig").configure(state, false, false);
    const id = try p.crs_management.Id.init("44444444444444444444444444444444");
    state.crs.test_id = id;
    state.crs.test_result = .{ .id = id, .state = .queued, .expires = 180000 };
    var bytes: [16384]u8 = undefined;
    var writer: W = .fixed(&bytes);
    try render(state, &writer);
    const start = std.mem.indexOf(u8, writer.buffered(), "id=\"crs-test-result\"").?;
    const result = writer.buffered()[start..];
    try t.expect(std.mem.indexOf(u8, result, "Waiting for the private worker") != null);
    try t.expect(std.mem.indexOf(u8, result, "saved revision changed") == null);
    try t.expect(std.mem.indexOf(u8, result, "Saved revision at test") == null);
    try t.expect(std.mem.indexOf(u8, result, "Enforcing denial") == null);
}
