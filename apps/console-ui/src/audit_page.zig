const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const html = @import("html");
const Writer = std.Io.Writer;
const timestamp = @import("events_page.zig").timestamp;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.audit;
    try html.render(w, @embedFile("snippets/audit-header.html"), .{
        .busy = if (model.busy) " disabled" else "",
    });
    if (!state.fullAccess()) return html.render(
        w,
        "<p>Sign in to read audit history.</p></main>",
        .{},
    );
    if (state.message.len != 0) try html.render(
        w,
        "<p id=\"console-message\" tabindex=\"-1\" role=\"status\">{{ message }}</p>",
        .{ .message = state.message.slice() },
    );
    try html.render(w, @embedFile("snippets/audit-filters.html"), .{
        .busy = if (model.busy) " disabled" else "",
        .actor = model.actor.slice(),
        .action = model.action.slice(),
        .day = if (model.days == 1) " selected" else "",
        .week = if (model.days == 7) " selected" else "",
        .month = if (model.days == 30) " selected" else "",
        .year = if (model.days == 365) " selected" else "",
    });
    try @import("live_status.zig").render(state, .audit, w);
    if (model.busy) try html.render(w, "<p role=\"status\">Loading audit records…</p>", .{});
    if (model.loaded) try catalog(state, w);
    if (model.has_detail) try detail(state, w);
    try html.render(w, "</main>", .{});
}

fn catalog(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.audit;
    try html.render(w, "<section class=\"sb-panel\" id=\"audit-catalog\" tabindex=\"-1\">" ++
        "<h2>Recorded activity</h2><p class=\"sb-note\">Window: ", .{});
    try timestamp(w, model.since);
    try w.writeAll(" – ");
    try timestamp(w, model.until);
    try html.render(w, "</p><div class=\"overflow-x-auto\"><table class=\"table\">" ++
        "<caption class=\"sr-only\">Recorded console actions</caption><thead><tr>" ++
        "<th scope=\"col\">Time (UTC)</th><th scope=\"col\">Actor / role</th>" ++
        "<th scope=\"col\">Action</th><th scope=\"col\">Subject</th>" ++
        "<th scope=\"col\">Record</th></tr></thead><tbody>", .{});
    for (model.rows[0..model.count], 0..) |*row, index| {
        try html.render(w, "<tr><td>", .{});
        try timestamp(w, row.recorded_at);
        try html.render(w, "</td><td>{{ actor }} / {{ role }}</td><td>{{ action }}</td>" ++
            "<td>{{ subject }}</td><td><button class=\"btn btn-sm\" " ++
            "data-action=\"audit-open-{{ index }}\"{{ busy }}>Open {{ id }}</button></td></tr>", .{
            .actor = row.actor,
            .role = if (row.actor_role) |role| @tagName(role) else "Not recorded",
            .action = row.action.slice(),
            .subject = row.subject,
            .index = index,
            .id = row.id,
            .busy = if (model.busy) " disabled" else "",
        });
    }
    if (model.count == 0) try html.render(
        w,
        "<tr><td colspan=\"5\">No recorded actions match these filters.</td></tr>",
        .{},
    );
    try html.render(w, @embedFile("snippets/audit-footer.html"), .{
        .page = model.page + 1,
        .previous = if (model.busy or model.page == 0) " disabled" else "",
        .next = if (model.busy or model.next == null or model.page + 1 == model.pages.len)
            " disabled"
        else
            "",
        .busy = if (model.busy) " disabled" else "",
    });
    if (model.page + 1 == model.pages.len and model.next != null) try html.render(
        w,
        "<p>Narrow the filters to inspect records beyond the 128-page browsing limit.</p>",
        .{},
    );
    try html.render(w, "</section>", .{});
}

fn detail(state: *const State, w: *Writer) Writer.Error!void {
    const value = &state.audit.detail;
    try html.render(w, @embedFile("snippets/audit-detail.html"), .{
        .id = value.row.id,
        .action = value.row.action.slice(),
        .actor = value.row.actor,
        .role = if (value.row.actor_role) |role| @tagName(role) else "Not recorded",
        .subject = value.row.subject,
        .target = if (value.row.target) |*target| target.slice() else "Not recorded",
        .client = if (value.row.client_ip) |*client| client.slice() else "Not recorded",
    });
    inline for (.{ "before", "after" }, .{ "Before", "After" }) |field, label| {
        try html.render(w, "<article><h3>{{ label }}</h3>", .{ .label = label });
        if (@field(value, field)) |summary| {
            try html.render(
                w,
                "<pre class=\"whitespace-pre-wrap break-words\">{{ summary }}</pre>",
                .{ .summary = summary.slice() },
            );
        } else try html.render(w, "<p>Not recorded</p>", .{});
        if (@field(value, field ++ "_truncated"))
            try html.render(w, "<p class=\"sb-note\">Summary text was truncated.</p>", .{});
        if (@field(value, field ++ "_redacted"))
            try html.render(
                w,
                "<p class=\"sb-note\">Sensitive or unsupported fields omitted.</p>",
                .{},
            );
        try html.render(w, "</article>", .{});
    }
    try html.render(w, "</div>", .{});
    if (state.allows(.manage_policy) and value.row.policyRevision() != null) try html.render(
        w,
        "<button class=\"btn my-3\" data-action=\"audit-policy-review\">" ++
            "Review policy revision</button>",
        .{},
    );
    try html.render(w, "</section>", .{});
}
