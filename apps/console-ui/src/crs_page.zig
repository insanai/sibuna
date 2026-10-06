//! Native HTML snippets and bounded typed data share the authenticated shell.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const State = @import("state.zig").State;
const W = std.Io.Writer;
const Settings = p.crs_management.Settings;

pub fn render(state: *const State, w: *W) W.Error!void {
    const model = &state.crs;
    const disabled = if (model.busy != .idle) " disabled" else "";
    try html.render(w, @embedFile("snippets/crs-header.html"), .{
        .disabled = disabled,
        .message = state.message.slice(),
    });
    const snapshot = model.snapshot orelse {
        try w.writeAll("<p role=\"status\" class=\"sb-note mt-6\">CRS status is unavailable. " ++
            "Refresh to obtain the saved selection and node receipts.</p></main>");
        return;
    };
    if (model.stale) try w.writeAll("<p role=\"status\" class=\"sb-error mt-4\">" ++
        "This view is stale. Refresh before preparing or selecting a candidate.</p>");
    try status(state, snapshot, w);
    try candidates(snapshot, w);
    if (model.reviewed) |reviewed| try review(state, reviewed, disabled, w);
    if (snapshot.available) {
        try @import("crs_test_page.zig").render(state, w);
        try mode(snapshot, disabled, w);
        try editor(state, snapshot, w);
    } else try w.writeAll("<p class=\"sb-note mt-6\">Management is unavailable on this node.</p>");
    try w.writeAll("</main>");
}

fn status(state: *const State, snapshot: p.crs_api.Status, w: *W) W.Error!void {
    try html.render(w, "<section id=\"crs-selection\" class=\"sb-panel mt-6\">" ++
        "<h2>Saved selection " ++
        "and local application" ++
        "</h2><p>Saved revision: {{ revision }} · Last status {{ age }} seconds ago.</p>", .{
        .revision = snapshot.revision,
        .age = state.browser_time -| state.crs.received_at,
    });
    if (snapshot.current) |current| {
        const artifact = current.artifact.?;
        try html.render(w, "<p>CRS {{ release }} · {{ mode }} · {{ profile }} profile</p>" ++
            "<p>Source SHA-256: <code class=\"break-all\">{{ digest }}</code></p>", .{
            .release = artifact.release.slice(),
            .mode = @tagName(artifact.settings.mode),
            .profile = @tagName(artifact.settings.profile),
            .digest = artifact.source_digest.slice(),
        });
    } else try w.writeAll("<p>No signed rules have been selected.</p>");
    if (snapshot.local.selection) |local| {
        try html.render(w, "<p>Serving node: revision {{ revision }} · {{ mode }} · " ++
            "{{ slots }} full-size and {{ small }} small slots · " ++
            "{{ bytes }} reserved bytes.</p>", .{
            .revision = local.revision,
            .mode = @tagName(local.mode),
            .slots = local.slots,
            .small = local.small_slots,
            .bytes = local.reserved_bytes,
        });
        if (local.revision != snapshot.revision) try w.writeAll(
            "<p class=\"sb-note\" role=\"status\">The serving node has not applied the " ++
                "saved revision. Its previous protection remains active.</p>",
        );
        if (local.profile == .headers) try w.writeAll("<p class=\"sb-note\">Headers profile: " ++
            "request bodies and origin responses are not inspected by CRS.</p>");
    } else try w.writeAll("<p>Serving node: CRS has no applied generation.</p>");
    try w.writeAll("<h3 class=\"mt-4\">Node application receipts</h3>" ++
        "<div class=\"overflow-x-auto\">" ++
        "<table class=\"table\"><thead><tr><th>Node</th><th>Revision</th><th>Result</th>" ++
        "<th>Reason</th></tr></thead><tbody>");
    for (snapshot.nodes[0..snapshot.node_count]) |row| {
        const node = row orelse continue;
        try html.render(w, "<tr><td>{{ node }}</td><td>{{ revision }}</td><td>{{ result }}</td>" ++
            "<td>{{ reason }}</td></tr>", .{
            .node = node.node,
            .revision = node.revision,
            .result = receipt(node, snapshot.revision),
            .reason = @tagName(node.reason),
        });
    }
    if (snapshot.node_count == 0) try w.writeAll("<tr><td colspan=\"4\">No current-boot " ++
        "receipts recorded.</td></tr>");
    try w.writeAll("</tbody></table></div><p class=\"sb-note\">" ++
        "Absent receipts are unconfirmed, " ++
        "not successful application. Check Nodes for membership and health.</p></section>");
}

fn candidates(snapshot: p.crs_api.Status, w: *W) W.Error!void {
    try html.render(w, "<section id=\"crs-candidates\" class=\"sb-panel mt-6\">" ++
        "<h2>Candidates</h2>" ++
        "<p>Local preparation: {{ stage }} · {{ reason }}</p>" ++
        "<div class=\"overflow-x-auto\"><table class=\"table\"><thead><tr>" ++
        "<th>Operation</th><th>State</th><th>Release</th><th>Mode</th><th>Review</th>" ++
        "</tr></thead><tbody>", .{
        .stage = @tagName(snapshot.stage),
        .reason = @tagName(snapshot.reason),
    });
    for (snapshot.candidates[0..snapshot.count], 0..) |row, index| {
        const candidate = row.?;
        try html.render(w, "<tr><td>{{ kind }}</td><td>{{ state }} · {{ reason }}</td>" ++
            "<td>{{ release }}</td><td>{{ mode }}</td><td>", .{
            .kind = @tagName(candidate.kind),
            .state = @tagName(candidate.state),
            .reason = @tagName(candidate.reason),
            .release = if (candidate.artifact) |a| a.release.slice() else "Not verified",
            .mode = if (candidate.artifact) |a| @tagName(a.settings.mode) else "Not verified",
        });
        if (candidate.state == .verified) {
            try html.render(w, "<button class=\"btn btn-sm\" " ++
                "data-action=\"crs-review-{{ index }}\">Review</button>", .{ .index = index });
        }
        try w.writeAll("</td></tr>");
    }
    if (snapshot.count == 0) try w.writeAll("<tr><td colspan=\"5\">No candidates.</td></tr>");
    try w.writeAll("</tbody></table></div>");
    // Diagnostics must wrap independently of the comparison table's scroll width.
    for (snapshot.candidates[0..snapshot.count]) |row| {
        if (row.?.diagnostic != null) try failure(w, row.?);
    }
    try w.writeAll("</section>");
}

fn failure(w: *W, candidate: p.crs_api.Candidate) W.Error!void {
    const diagnostic = candidate.diagnostic.?;
    try html.render(w, "<div class=\"sb-error mt-4\">" ++
        "<p>Failed {{ kind }} candidate <code class=\"break-all\">{{ id }}</code></p>", .{
        .kind = @tagName(candidate.kind),
        .id = candidate.id.slice(),
    });
    try @import("crs_diagnostic_page.zig").render(w, diagnostic);
    try w.writeAll("</div>");
}

fn mode(snapshot: p.crs_api.Status, disabled: []const u8, w: *W) W.Error!void {
    const current = snapshot.current orelse return;
    try w.writeAll("<section id=\"crs-mode-panel\" class=\"sb-panel mt-6\">" ++
        "<h2>Change CRS mode</h2>" ++
        "<form id=\"crs-mode\" class=\"sb-settings-form mt-4\"><label for=\"crs-mode-value\">" ++
        "Candidate mode</label><select id=\"crs-mode-value\" name=\"mode\" " ++
        "class=\"select select-bordered w-full\">");
    inline for (std.enums.values(p.crs.Mode)) |value| {
        try html.render(w, "<option value=\"{{ value }}\"{{ selected }}>{{ value }}</option>", .{
            .value = @tagName(value),
            .selected = if (current.artifact.?.settings.mode == value) " selected" else "",
        });
    }
    try html.render(w, "</select><div class=\"flex flex-wrap gap-3 mt-4\">" ++
        "<button class=\"btn btn-primary\" type=\"submit\"{{ disabled }}>Prepare mode change" ++
        "</button><button class=\"btn\" type=\"button\" " ++
        "data-action=\"crs-rollback\"{{ rollback }}>" ++
        "Prepare rollback</button></div></form><p class=\"sb-note mt-3\">" ++
        "Both operations need " ++
        "review and selection. Rollback restores the previous source and settings as a " ++
        "new revision.</p></section>", .{
        .disabled = disabled,
        .rollback = if (snapshot.previous == null) " disabled" else disabled,
    });
}

fn editor(state: *const State, snapshot: p.crs_api.Status, w: *W) W.Error!void {
    const ready = state.crs.editor_loaded and state.crs.editor_revision == snapshot.revision;
    const disabled = if (!ready or state.crs.busy != .idle) " disabled" else "";
    try html.render(w, @embedFile("snippets/crs-editor.html"), .{
        .disabled = disabled,
        .configuration = state.crs.editor.slice(),
        .release = if (snapshot.current) |row| row.artifact.?.release.slice() else "4.30.0",
    });
    if (!ready) try w.writeAll("<p class=\"sb-note\" role=\"status\">The saved revision " ++
        "changed or its operator rules have not loaded. Copy any unsaved edits, then " ++
        "reload the saved operator rules before preparing an update.</p>");
    const settings = if (snapshot.current) |row| row.artifact.?.settings else Settings{};
    try bounds(settings, w);
    try w.writeAll("<div class=\"flex flex-wrap gap-3 mt-4\"><button class=\"btn\" " ++
        "type=\"button\" data-action=\"crs-check\">Check release</button>" ++
        "<button class=\"btn btn-primary\" type=\"button\" data-action=\"crs-update\">" ++
        "Prepare update</button></div></fieldset></form>");
    try html.render(w, "<button class=\"btn btn-sm mt-4\" data-action=\"crs-reload-editor\"" ++
        "{{ disabled }}>Reload saved operator rules</button></section>", .{
        .disabled = if (state.crs.busy != .idle) " disabled" else "",
    });
}

fn bounds(settings: Settings, w: *W) W.Error!void {
    try w.writeAll("<details class=\"mt-4\"><summary>Inspection settings and resource bounds" ++
        "</summary><div class=\"sb-filters\"><div " ++
        "class=\"sb-filter-grid sb-filter-three mt-4\">");
    const names = .{
        "blocking_paranoia",  "detection_paranoia", "inbound_threshold",
        "outbound_threshold", "request_bytes",      "response_bytes",
        "work_budget",        "slots",              "reservation",
    };
    inline for (names) |name| {
        try html.render(w, "<label class=\"form-control\" for=\"crs-{{ name }}\">" ++
            "<span>{{ label }}</span><input id=\"crs-{{ name }}\" name=\"{{ name }}\" " ++
            "type=\"number\" min=\"1\" class=\"input input-bordered w-full\" " ++
            "value=\"{{ value }}\" required></label>", .{
            .name = name,
            .label = label(name),
            .value = @field(settings, name),
        });
    }
    try w.writeAll("<label class=\"form-control\" for=\"crs-profile\"><span>Inspection profile" ++
        "</span><select id=\"crs-profile\" name=\"profile\" " ++
        "class=\"select select-bordered w-full\">");
    inline for (std.enums.values(p.crs.Profile)) |profile| {
        try html.render(w, "<option value=\"{{ profile }}\"{{ selected }}>" ++
            "{{ profile }}</option>", .{
            .profile = @tagName(profile),
            .selected = if (settings.profile == profile) " selected" else "",
        });
    }
    try w.writeAll("</select></label></div></div></details>");
}

fn review(
    state: *const State,
    candidate: p.crs_api.Candidate,
    disabled: []const u8,
    w: *W,
) W.Error!void {
    const snapshot = state.crs.snapshot.?;
    const next = candidate.artifact orelse return;
    const previous = if (snapshot.current) |row| row.artifact else null;
    try html.render(w, "<section id=\"crs-review\" class=\"sb-panel mt-6\" " ++
        "aria-labelledby=\"crs-review-heading\">" ++
        "<h2 id=\"crs-review-heading\" tabindex=\"-1\">Review candidate revision {{ revision }}" ++
        "</h2><p>Expected saved revision: {{ expected }} · " ++
        "Verified conditions: {{ rules }}</p>" ++
        "<div class=\"overflow-x-auto\"><table class=\"table\"><thead><tr><th>Setting</th>" ++
        "<th>Current</th><th>Candidate</th></tr></thead><tbody>", .{
        .revision = next.revision,
        .expected = candidate.expected_revision,
        .rules = next.conditions,
    });
    try diff(w, "Release", if (previous) |a| a.release.slice() else "None", next.release.slice());
    inline for (@typeInfo(Settings).@"struct".field_names) |name| {
        var before: [20]u8 = undefined;
        var after: [20]u8 = undefined;
        const old = if (previous) |a| setting(name, a.settings, &before) else "Not selected";
        try diff(w, label(name), old, setting(name, next.settings, &after));
    }
    try w.writeAll("</tbody></table></div>");
    try @import("crs_identity_page.zig").render(previous, next, w);
    try @import("crs_review_page.zig").render(&state.crs, w);
    if (next.settings.profile == .headers) try w.writeAll("<p class=\"sb-note mt-4\">" ++
        "Headers profile excludes request bodies and origin responses from CRS inspection.</p>");
    try html.render(w, "<p class=\"sb-note mt-4\">Verify exclusions and " ++
        "application traffic before enforcing. Selection commits desired state; each node " ++
        "then compiles and applies it independently.</p>" ++
        "<div class=\"flex flex-wrap gap-3 mt-4\"><button class=\"btn btn-primary\" " ++
        "data-action=\"crs-select\"{{ select_disabled }}>Select candidate</button>" ++
        "<button class=\"btn\" data-action=\"crs-discard\"{{ disabled }}>Discard candidate" ++
        "</button><button class=\"btn\" data-action=\"crs-cancel-review\">Close review</button>" ++
        "</div></section>", .{
        .disabled = disabled,
        .select_disabled = if (state.crs.reviewReady()) disabled else " disabled",
    });
}

fn diff(w: *W, name: []const u8, old: []const u8, next: []const u8) W.Error!void {
    try html.render(w, "<tr><th>{{ name }}</th><td class=\"break-all\">{{ old }}</td>" ++
        "<td class=\"break-all\">{{ next }}</td></tr>", .{
        .name = name,
        .old = old,
        .next = next,
    });
}

fn label(comptime name: []const u8) []const u8 {
    const names = .{
        "mode",
        "profile",
        "blocking_paranoia",
        "detection_paranoia",
        "inbound_threshold",
        "outbound_threshold",
        "request_bytes",
        "response_bytes",
        "work_budget",
        "slots",
        "reservation",
    };
    const labels = .{
        "Mode",               "Profile",
        "Blocking paranoia (1–4)",
        "Detection paranoia (1–4)",
        "Inbound threshold",  "Outbound threshold",
        "Request body bytes", "Response body bytes",
        "Work budget",
        "Transaction slots (1–31)",
        "Reservation bytes",
    };
    inline for (names, labels) |key, text| if (std.mem.eql(u8, name, key)) return text;
    unreachable;
}

fn setting(comptime name: []const u8, value: Settings, buffer: *[20]u8) []const u8 {
    const T = @FieldType(Settings, name);
    if (comptime @typeInfo(T) == .@"enum") return @tagName(@field(value, name));
    return std.fmt.bufPrint(buffer, "{d}", .{@field(value, name)}) catch unreachable;
}

fn receipt(node: p.crs_management.Node, revision: u64) []const u8 {
    if (!node.applied) return "Failed";
    return if (node.revision == revision) "Applied" else "Previous revision";
}

test "CRS diagnostics escape source metadata and wrap outside the scrolling table" {
    const t = std.testing;
    const state = try t.allocator.create(State);
    defer t.allocator.destroy(state);
    state.* = .{};
    @import("crs_fixture.zig").configure(state, false, false);
    const row = &state.crs.snapshot.?.candidates[0].?;
    row.state = .failed;
    row.artifact = null;
    row.reason = .incompatible;
    row.diagnostic = p.crs_management.Diagnostic.capture(
        error.UnknownDirective,
        "rules/<script>.conf",
        2,
        null,
    );
    var bytes: [32 * 1024]u8 = undefined;
    var writer: W = .fixed(&bytes);
    try render(state, &writer);
    const rendered = writer.buffered();
    const source = rendered[std.mem.indexOf(u8, rendered, "id=\"crs-candidates\"").?..];
    const table_end = std.mem.indexOf(u8, source, "</tbody></table></div>").?;
    const error_at = std.mem.indexOf(u8, source, "CRSCOMPILE/unsupported").?;
    try t.expect(error_at > table_end);
    try t.expect(std.mem.indexOf(u8, source, "Source: rules/&lt;script&gt;.conf") != null);
    try t.expect(std.mem.indexOf(u8, source, "Line: 2") != null);
    try t.expect(std.mem.indexOf(u8, source, "<script>") == null);
}
