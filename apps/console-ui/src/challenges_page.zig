const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
const escape = @import("render.zig").escape;
pub const Model = struct {
    snapshot: ?p.challenges.Snapshot = null,
    selected: ?u8 = null,
    busy: bool = false,
    stale: bool = false,
    received_at: u64 = 0,
};

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.challenges;
    try w.writeAll("<main class=\"sb-main min-h-screen\"><header class=\"sb-header\"><div>" ++
        "<p class=\"sb-subtitle\">SINGLE NODE / PROOF VERIFICATION</p>" ++
        "<h1 id=\"page-heading\" tabindex=\"-1\">Challenges</h1>" ++
        "<p class=\"sb-subtitle\">Understand proof issuance and verification.</p></div>" ++
        "<button class=\"btn\" data-action=\"dashboard\">Back to dashboard</button></header>");
    if (state.message.len != 0) {
        try w.writeAll("<p class=\"sb-error\" role=\"status\">");
        try escape(w, state.message.slice());
        try w.writeAll("</p>");
    }
    if (model.busy) try w.writeAll("<p role=\"status\">Refreshing challenge observations…</p>");
    try w.writeAll("<button class=\"btn mt-4\" data-action=\"challenges-refresh\"");
    if (model.busy) try w.writeAll(" disabled");
    try w.writeAll(">Refresh observations</button>");
    const snapshot = model.snapshot orelse {
        try w.writeAll("<p class=\"sb-note mt-4\">No observations received yet.</p></main>");
        return;
    };
    try w.print("<p class=\"sb-note mt-4\">{s} · Received {d} seconds ago. " ++
        "Totals since this boot; refresh to update.</p>", .{
        if (model.stale) "Disconnected / stale" else "Snapshot",
        state.browser_time -| model.received_at,
    });
    try w.writeAll("<div class=\"sb-panels\">" ++
        "<section class=\"sb-panel mt-6\"><h2>Challenge flow</h2>" ++
        "<table class=\"table\"><tbody>");
    try row(w, "Issued", snapshot.issued);
    try row(w, "Submitted", snapshot.submitted);
    try row(w, "Accepted", snapshot.accepted);
    try row(w, "Rejected", snapshot.rejected);
    try w.writeAll("</tbody></table><p class=\"sb-note\">Parsed verification requests only. " ++
        "Retries, abandonment and overlapping observations prevent a cohort conversion rate. " ++
        "Counters are individually atomic, so concurrent totals may differ briefly." ++
        "</p></section>");
    try parameters(&snapshot, w);
    try w.writeAll("</div><div class=\"sb-panels\">");
    try timing(&snapshot, model.busy, w);
    try rejection(&snapshot, w);
    try w.writeAll("</div></main>");
}

fn row(w: *Writer, label: []const u8, count: u64) Writer.Error!void {
    try w.print("<tr><th scope=\"row\">{s}</th><td>{d}</td></tr>", .{ label, count });
}

fn parameters(snapshot: *const p.challenges.Snapshot, w: *Writer) Writer.Error!void {
    try w.writeAll("<section class=\"sb-panel mt-6\"><h2>Difficulty and parameters</h2>");
    try w.print("<p>Configured default difficulty: {d}</p>", .{snapshot.configured.difficulty});
    try w.writeAll("<p>Default effective parameters: ");
    try parameterText(snapshot.configured, w);
    try w.writeAll("</p><p>Most recently issued parameters: ");
    if (snapshot.last_issued) |last| {
        try parameterText(last, w);
    } else try w.writeAll("No challenge issued during this boot.");
    try w.writeAll("</p><p class=\"sb-note mt-4\">Rule overrides and adaptive difficulty can " ++
        "change issued parameters. PoSW depth and Hashcash bits describe different work. " ++
        "PoSW uses 2^(depth + 1) − 1 labels; Hashcash expects 2^bits trials.</p></section>");
}

fn parameterText(value: p.challenges.Defaults, w: *Writer) Writer.Error!void {
    switch (value.algorithm) {
        .hashcash => try w.print("Hashcash, {d} work bits", .{value.parameter}),
        .posw => try w.print("PoSW, depth {d}, {d} openings", .{
            value.parameter, value.openings,
        }),
    }
}

fn timing(snapshot: *const p.challenges.Snapshot, busy: bool, w: *Writer) Writer.Error!void {
    try w.writeAll("<section class=\"sb-panel mt-6\"><h2>Accepted client solve timing</h2>" ++
        "<p class=\"sb-note\">Untrusted client telemetry, measured before verification. " ++
        "Missing, invalid and over-one-hour durations are excluded from the histogram.</p>" ++
        "<form id=\"challenges-bin\" class=\"grid gap-3 mt-4\">" ++
        "<label for=\"challenge-bin\">Authenticated parameter partition</label>" ++
        "<select id=\"challenge-bin\" name=\"bin\" class=\"select w-full\">");
    for (snapshot.bin_accepted, 0..) |count, i| {
        if (count == 0 and i != snapshot.selected) continue;
        try w.print("<option value=\"{d}\"{s}>", .{
            i, if (i == snapshot.selected) " selected" else "",
        });
        try binText(@intCast(i), w);
        try w.print(" · {d} accepted</option>", .{count});
    }
    try w.writeAll("</select><button class=\"btn\" type=\"submit\"");
    if (busy) try w.writeAll(" disabled");
    try w.writeAll(">View partition</button></form><table class=\"table mt-4\">" ++
        "<caption>Accepted durations in milliseconds</caption>" ++
        "<thead><tr><th scope=\"col\">Duration</th>" ++
        "<th scope=\"col\">Count</th></tr></thead><tbody>");
    for (snapshot.buckets, 0..) |count, i| {
        try w.writeAll("<tr><th scope=\"row\">");
        if (i == 0) {
            try w.writeAll("0 ≤ ms &lt; 1");
        } else if (i == 15) {
            try w.writeAll("ms ≥ 16384");
        } else {
            const low = @as(u32, 1) << @as(u5, @intCast(i - 1));
            try w.print("{d} ≤ ms &lt; {d}", .{ low, low * 2 });
        }
        try w.print("</th><td>{d}</td></tr>", .{count});
    }
    try row(w, "Timing not supplied", snapshot.missing);
    try row(w, "Invalid timing", snapshot.invalid);
    try row(w, "Reported Wasm solver", snapshot.wasm);
    try row(w, "Reported JavaScript solver", snapshot.javascript);
    try row(w, "Unknown solver", snapshot.unknown_solver);
    try w.writeAll("</tbody></table></section>");
}

fn binText(bin: u8, w: *Writer) Writer.Error!void {
    const parameter: u16 = @as(u16, (bin % 128) / 4) * 8;
    if (bin < 128) {
        try w.print("Hashcash bits {d}–{d}", .{ parameter, parameter + 7 });
    } else {
        const openings: u16 = @as(u16, bin % 4) * 16;
        try w.print("PoSW depth {d}–{d}, openings {d}–{d}", .{
            parameter, parameter + 7, openings, if (openings == 48) 255 else openings + 15,
        });
    }
}

fn rejection(snapshot: *const p.challenges.Snapshot, w: *Writer) Writer.Error!void {
    const names = [_][]const u8{
        "Address banned",
        "Body too large",
        "Missing challenge ID",
        "Malformed solution",
        "Malformed challenge",
        "Invalid challenge tag",
        "Expired challenge",
        "Fingerprint mismatch",
        "Difficulty not met",
        "Invalid proof",
        "Wrong solution type",
        "Replay",
        "Capacity exhausted",
    };
    try w.writeAll("<section class=\"sb-panel mt-6\"><h2>Rejection causes</h2>" ++
        "<table class=\"table\"><tbody>");
    for (names, snapshot.causes) |name, count| try row(w, name, count);
    try w.writeAll("</tbody></table></section>");
}

test "challenge page distinguishes PoSW depth and untrusted timing without conversion claims" {
    var state: State = .{};
    state.phase = .challenges;
    state.challenges.snapshot = .{
        .configured = .{ .algorithm = .posw, .difficulty = 16, .parameter = 13, .openings = 16 },
        .selected = 133,
    };
    var buffer: [32768]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&state, &writer);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "PoSW, depth 13") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "Untrusted client") != null);
}
