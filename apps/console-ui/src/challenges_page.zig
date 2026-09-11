const html = @import("html");
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
    timing_received_at: u64 = 0,
};

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.challenges;
    try html.render(w, "<main class=\"sb-main min-h-screen\"><header class=\"sb-header\"><div>" ++
        "<p class=\"sb-subtitle\">SINGLE NODE / PROOF VERIFICATION</p>" ++
        "<h1 id=\"page-heading\" tabindex=\"-1\">Challenges</h1>" ++
        "<p class=\"sb-subtitle\">Understand proof issuance and verification.</p></div>" ++
        "<button class=\"btn\" data-action=\"dashboard\">Back to " ++
        "dashboard</button></header>", .{});
    if (state.message.len != 0) {
        try html.render(w, "<p class=\"sb-error\" role=\"status\">", .{});
        try escape(w, state.message.slice());
        try html.render(w, "</p>", .{});
    }
    if (model.busy) try html.render(
        w,
        "<p role=\"status\">Refreshing challenge observations…</p>",
        .{},
    );
    try html.render(w, "<button class=\"btn mt-4\" data-action=\"challenges-refresh\"", .{});
    if (model.busy) try w.writeAll(" disabled");
    try html.render(w, ">Refresh observations</button>", .{});
    try @import("challenge_summary.zig").render(state, w);
    const snapshot = model.snapshot orelse {
        try html.render(
            w,
            "<p class=\"sb-note mt-4\">No observations received " ++
                "yet.</p></main>",
            .{},
        );
        return;
    };
    try html.render(w, "<p class=\"sb-note mt-4\">{{ v0 }} · Received {{ v1 }} seconds ago. " ++
        "Totals since this boot; live flow updates.</p>", .{
        .v0 = if (model.stale) "Disconnected / stale" else "Live",
        .v1 = state.browser_time -| model.received_at,
    });
    try html.render(w, "<div class=\"sb-panels\">" ++
        "<section class=\"sb-panel mt-6\"><h2>Challenge flow</h2>" ++
        "<table class=\"table\"><tbody>", .{});
    try row(w, "Issued", snapshot.issued);
    try row(w, "Submitted", snapshot.submitted);
    try row(w, "Accepted", snapshot.accepted);
    try row(w, "Rejected", snapshot.rejected);
    try html.render(
        w,
        "</tbody></table><p class=\"sb-note\">Parsed verification " ++
            "requests only. " ++
            "Retries, abandonment and overlapping observations " ++
            "prevent a cohort conversion rate. " ++
            "Counters are individually atomic, so concurrent totals may differ briefly." ++
            "</p></section>",
        .{},
    );
    try parameters(&snapshot, w);
    try html.render(w, "</div><div class=\"sb-panels\">", .{});
    try html.render(w, "<p class=\"sb-note\">Timing partition last observed {{ age }} " ++
        "seconds ago. Refresh observations to update a selected non-default partition.</p>", .{
        .age = state.browser_time -| model.timing_received_at,
    });
    try timing(&snapshot, model.busy, "challenges-bin", w);
    try rejection(&snapshot, w);
    try html.render(w, "</div></main>", .{});
}

pub fn row(w: *Writer, label: []const u8, count: u64) Writer.Error!void {
    try html.render(w, "<tr><th scope=\"row\">{{ v0 }}</th><td>{{ v1 }}</td></tr>", .{
        .v0 = label,
        .v1 = count,
    });
}

fn parameters(snapshot: *const p.challenges.Snapshot, w: *Writer) Writer.Error!void {
    try html.render(w, "<section class=\"sb-panel mt-6\"><h2>Difficulty and parameters</h2>", .{});
    try html.render(w, "<p>Configured default difficulty: {{ v0 }}</p>", .{
        .v0 = snapshot.configured.difficulty,
    });
    try html.render(w, "<p>Default effective parameters: ", .{});
    try parameterText(snapshot.configured, w);
    try html.render(w, "</p><p>Most recently issued parameters: ", .{});
    if (snapshot.last_issued) |last| {
        try parameterText(last, w);
    } else try w.writeAll("No challenge issued during this boot.");
    try html.render(
        w,
        "</p><p class=\"sb-note mt-4\">Rule overrides and adaptive " ++
            "difficulty can " ++
            "change issued parameters. PoSW depth and Hashcash bits describe different work. " ++
            "PoSW uses 2^(depth + 1) − 1 labels; Hashcash expects 2^bits trials.</p></section>",
        .{},
    );
}

fn parameterText(value: p.challenges.Defaults, w: *Writer) Writer.Error!void {
    switch (value.algorithm) {
        .hashcash => try w.print("Hashcash, {d} work bits", .{value.parameter}),
        .posw => try w.print("PoSW, depth {d}, {d} openings", .{
            value.parameter, value.openings,
        }),
    }
}

pub fn timing(
    snapshot: *const p.challenges.Snapshot,
    busy: bool,
    form: []const u8,
    w: *Writer,
) Writer.Error!void {
    try html.render(w, "<section class=\"sb-panel mt-6\"><h2>Accepted client solve timing</h2>" ++
        "<p class=\"sb-note\">Untrusted client telemetry, measured before verification. " ++
        "Missing, invalid and over-one-hour durations are excluded from the histogram.</p>" ++
        "<form id=\"{{ form }}\" class=\"sb-filter-toolbar mt-4\">" ++
        "<div class=\"sb-filter-field\">" ++
        "<label for=\"{{ form }}-select\">Authenticated parameter partition</label>" ++
        "<select id=\"{{ form }}-select\" name=\"bin\" class=\"select w-full\">", .{
        .form = form,
    });
    for (snapshot.bin_accepted, 0..) |count, i| {
        if (count == 0 and i != snapshot.selected) continue;
        try html.render(w, "<option value=\"{{ v0 }}\"{{ v1 }}>", .{
            .v0 = i,
            .v1 = if (i == snapshot.selected) " selected" else "",
        });
        try binText(@intCast(i), w);
        try html.render(w, " · {{ v0 }} accepted</option>", .{
            .v0 = count,
        });
    }
    try html.render(w, "</select></div><button class=\"btn\" type=\"submit\"", .{});
    if (busy) try w.writeAll(" disabled");
    try html.render(w, ">View partition</button></form><table class=\"table mt-4\">" ++
        "<caption>Accepted durations in milliseconds</caption>" ++
        "<thead><tr><th scope=\"col\">Duration</th>" ++
        "<th scope=\"col\">Count</th></tr></thead><tbody>", .{});
    for (snapshot.buckets, 0..) |count, i| {
        try html.render(w, "<tr><th scope=\"row\">", .{});
        if (i == 0) {
            try w.writeAll("0 ≤ ms &lt; 1");
        } else if (i == 15) {
            try w.writeAll("ms ≥ 16384");
        } else {
            const low = @as(u32, 1) << @as(u5, @intCast(i - 1));
            try w.print("{d} ≤ ms &lt; {d}", .{ low, low * 2 });
        }
        try html.render(w, "</th><td>{{ v0 }}</td></tr>", .{
            .v0 = count,
        });
    }
    try row(w, "Timing not supplied", snapshot.missing);
    try row(w, "Invalid timing", snapshot.invalid);
    try row(w, "Reported Wasm solver", snapshot.wasm);
    try row(w, "Reported JavaScript solver", snapshot.javascript);
    try row(w, "Unknown solver", snapshot.unknown_solver);
    try html.render(w, "</tbody></table></section>", .{});
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

pub fn rejection(snapshot: *const p.challenges.Snapshot, w: *Writer) Writer.Error!void {
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
    try html.render(w, "<section class=\"sb-panel mt-6\"><h2>Rejection causes</h2>" ++
        "<table class=\"table\"><tbody>", .{});
    for (names, snapshot.causes) |name, count| try row(w, name, count);
    try html.render(w, "</tbody></table></section>", .{});
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
