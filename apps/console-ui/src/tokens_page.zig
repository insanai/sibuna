const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
const html = @import("html");
const time = @import("events_page.zig").timestamp;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.tokens;
    try html.render(w, @embedFile("snippets/tokens-header.html"), .{
        .busy = if (model.busy) " disabled" else "",
    });
    if (!state.allows(.manage_users)) {
        return html.render(w, "<p>Administrator access required.</p></main>", .{});
    }
    if (state.message.len != 0) try html.render(
        w,
        "<p role=\"status\" class=\"alert\">{{ message }}</p>",
        .{ .message = state.message.slice() },
    );
    if (model.secret.len != 0) try html.render(
        w,
        @embedFile("snippets/tokens-secret.html"),
        .{ .id = model.issued_id, .token = model.secret.slice() },
    );
    if (model.busy) try html.render(w, "<p role=\"status\">Token request in progress…</p>", .{});
    if (model.loaded) try catalog(state, w);
    if (model.secret.len == 0) {
        if (model.selected) |index| {
            try editor(state, w, &model.rows[index]);
        } else try create(state, w);
    }
    try html.render(w, "</main>", .{});
}

fn catalog(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.tokens;
    try html.render(w, "<section id=\"tokens-catalog\" tabindex=\"-1\" " ++
        "class=\"sb-panel sb-users\" aria-label=\"Token catalog\">", .{});
    for (model.rows[0..model.count], 0..) |*row, index| {
        try html.render(w, "<article><h2>{{ label }}</h2><p>{{ role }} · {{ status }}</p>" ++
            "<p class=\"sb-note\">ID {{ id }} · Revision {{ revision }} · " ++
            "Issued by {{ actor }}</p>" ++
            "<p>Scopes: ", .{
            .label = row.label.slice(),
            .role = @tagName(row.role),
            .status = if (row.disabled) "Revoked" else if (row.active) "Active" else "Inactive",
            .id = row.id,
            .revision = row.revision,
            .actor = row.created_by,
        });
        inline for (@typeInfo(p.tokens.Scope).@"enum".fields) |field| {
            const scope: p.tokens.Scope = @enumFromInt(field.value);
            if (row.scopes & scope.bit() != 0) try html.render(w, "<code>{{ scope }}</code> ", .{
                .scope = field.name,
            });
        }
        try html.render(w, "</p><p>Created ", .{});
        try time(w, row.created_at);
        try w.writeAll(" · Expires ");
        if (row.expires) |expires| try time(w, expires) else try w.writeAll("Never");
        try html.render(w, "</p><button class=\"btn btn-sm\" " ++
            "data-action=\"tokens-open-{{ index }}\"{{ disabled }}>" ++
            "Manage {{ label }}</button></article>", .{
            .index = index,
            .label = row.label.slice(),
            .disabled = if (model.busy or model.secret.len != 0) " disabled" else "",
        });
    }
    if (model.count == 0) try html.render(w, "<p>No tokens on this page.</p>", .{});
    try html.render(w, "<p>Page {{ page }}</p><button class=\"btn btn-sm\" " ++
        "data-action=\"tokens-previous\"{{ previous }}>Previous tokens</button>" ++
        "<button class=\"btn btn-sm\" data-action=\"tokens-next\"{{ next }}>" ++
        "Next tokens</button></section>", .{
        .page = model.page + 1,
        .previous = if (model.busy or model.page == 0) " disabled" else "",
        .next = if (model.busy or model.next == null or model.page + 1 == model.pages.len)
            " disabled"
        else
            "",
    });
}

fn create(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.tokens;
    try html.render(w, @embedFile("snippets/tokens-create.html"), .{
        .busy = if (model.busy) " disabled" else "",
        .label = model.label.slice(),
        .viewer = if (model.role == .viewer) " selected" else "",
        .operator = if (model.role == .operator) " selected" else "",
        .admin = if (model.role == .admin) " selected" else "",
    });
    const labels = [_][]const u8{
        "Read statistics and challenges", "Read and export incidents", "Read and test policies",
        "Change policies and inspection", "Read GeoIP status",         "Update GeoIP",
        "Read users",                     "Manage users",
    };
    inline for (@typeInfo(p.tokens.Scope).@"enum".fields, labels) |field, label| {
        const scope: p.tokens.Scope = @enumFromInt(field.value);
        try html.render(w, @embedFile("snippets/tokens-scope.html"), .{
            .scope = field.name,
            .label = label,
            .checked = if (model.scopes & scope.bit() != 0) " checked" else "",
            .disabled = if (model.role.allows(scope.action())) "" else " disabled",
        });
    }
    try html.render(w, @embedFile("snippets/tokens-expiry.html"), .{
        .week = if (model.days == 7) " selected" else "",
        .month = if (model.days == 30) " selected" else "",
        .quarter = if (model.days == 90) " selected" else "",
        .never = if (model.days == 0) " selected" else "",
        .confirmed = if (model.confirmed) " checked" else "",
    });
}

fn editor(state: *const State, w: *Writer, row: *const p.tokens.Row) Writer.Error!void {
    try html.render(w, "<section class=\"sb-panel\" id=\"tokens-editor\" tabindex=\"-1\">" ++
        "<h2>Manage {{ label }}</h2>", .{
        .label = row.label.slice(),
    });
    const inactive = "Remove this inactive entry to reclaim capacity. " ++
        "Its audit history is retained.";
    try html.render(w, @embedFile("snippets/tokens-revoke.html"), .{
        .action = if (row.active) "tokens-revoke" else "tokens-remove",
        .title = if (row.active) "Revoke token" else "Remove inactive token",
        .busy = if (state.tokens.busy) " disabled" else "",
        .explanation = if (row.active) "Stop requests using this token immediately." else inactive,
    });
    try html.render(w, "</section>", .{});
}
