const std = @import("std");
const p = @import("console_protocol");
const State = @import("state.zig").State;
const Writer = std.Io.Writer;
const html = @import("html");
const time = @import("events_page.zig").timestamp;

pub fn render(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.users;
    try html.render(w, @embedFile("snippets/users-header.html"), .{
        .busy = if (model.busy) " disabled" else "",
    });
    if (state.message.len != 0) try html.render(
        w,
        "<p role=\"status\" class=\"alert\">{{ message }}</p>",
        .{ .message = state.message.slice() },
    );
    if (model.temporary.len != 0) {
        var buffer: [64]u8 = undefined;
        var writer: Writer = .fixed(&buffer);
        try time(&writer, model.expires);
        try html.render(w, @embedFile("snippets/users-secret.html"), .{
            .username = model.username.slice(),
            .password = model.temporary.slice(),
            .expires = writer.buffered(),
        });
    }
    if (model.busy) {
        try html.render(w, "<p role=\"status\">Account request in progress…</p>", .{});
    }
    if (model.loaded) try catalog(state, w);
    if (state.allows(.manage_users) and model.temporary.len == 0) {
        if (model.selected) |index| {
            try editor(state, w, &model.rows[index]);
        } else {
            try html.render(w, @embedFile("snippets/users-create.html"), .{
                .busy = if (model.busy) " disabled" else "",
                .username = model.username.slice(),
                .viewer = if (model.role == .viewer) " selected" else "",
                .operator = if (model.role == .operator) " selected" else "",
                .admin = if (model.role == .admin) " selected" else "",
                .confirmed = if (model.confirmed) " checked" else "",
            });
        }
    }
    try html.render(w, "</main>", .{});
}

fn catalog(state: *const State, w: *Writer) Writer.Error!void {
    const model = &state.users;
    try html.render(w, "<section id=\"users-catalog\" tabindex=\"-1\" " ++
        "class=\"sb-panel sb-users\" aria-label=\"Account catalog\">", .{});
    for (model.rows[0..model.count], 0..) |*row, index| {
        try html.render(w, "<article><h2>{{ name }}</h2><p>{{ role }} · {{ status }}</p>", .{
            .name = row.username.slice(),
            .role = @tagName(row.role),
            .status = if (row.disabled) "Disabled" else "Enabled",
        });
        try html.render(w, "<p class=\"sb-note\">Revision {{ revision }} · " ++
            "Two-factor {{ factor }} · Password change {{ change }}</p>" ++
            "<p class=\"sb-note\">Last login: ", .{
            .revision = row.revision,
            .factor = if (row.totp_enabled) "enabled" else "not enabled",
            .change = if (row.must_change) "required" else "not required",
        });
        if (row.last_login) |last| try time(w, last) else try w.writeAll("Not recorded");
        try html.render(w, "</p><button class=\"btn btn-sm\" " ++
            "data-action=\"users-open-{{ index }}\"{{ disabled }}>" ++
            "Manage {{ name }}</button></article>", .{
            .index = index,
            .name = row.username.slice(),
            .disabled = if (model.busy or !state.allows(.manage_users)) " disabled" else "",
        });
    }
    if (model.count == 0) try w.writeAll(
        "<p>No accounts on this page. Return to the first page.</p>",
    );
    try html.render(w, "<p>Page {{ page }}</p><button class=\"btn btn-sm\" " ++
        "data-action=\"users-previous\"{{ previous }}>Previous users</button>" ++
        "<button class=\"btn btn-sm\" data-action=\"users-next\"{{ next }}>" ++
        "Next users</button></section>", .{
        .page = model.page + 1,
        .previous = if (model.busy or model.page == 0) " disabled" else "",
        .next = if (model.busy or model.next == null or model.page + 1 == model.pages.len)
            " disabled"
        else
            "",
    });
}

fn editor(state: *const State, w: *Writer, row: *const p.users.Row) Writer.Error!void {
    const model = &state.users;
    try html.render(w, "<section class=\"sb-panel\"><h2>Manage {{ name }}</h2>", .{
        .name = row.username.slice(),
    });
    const own = row.id == state.user_id;
    if (!own) try html.render(w, @embedFile("snippets/users-access.html"), .{
        .busy = if (model.busy) " disabled" else "",
        .viewer = if (model.role == .viewer) " selected" else "",
        .operator = if (model.role == .operator) " selected" else "",
        .admin = if (model.role == .admin) " selected" else "",
        .disabled = if (model.disabled) " checked" else "",
        .confirmed = if (model.confirmed) " checked" else "",
    });
    if (own) try html.render(w, "<p>Use Account to change your password. " ++
        "Another administrator must change your role or disable your account.</p>", .{});
    if (!own) try html.render(w, @embedFile("snippets/users-revoke.html"), .{
        .action = "users-password",
        .title = "Reset password",
        .busy = if (model.busy) " disabled" else "",
        .explanation = "Generate a one-hour temporary password. Existing sessions end; " ++
            "enabled state, role and enrolled two-factor authentication remain in effect.",
    });
    const self_note = "End your sessions and API tokens, including this session. " ++
        "You will be signed out.";
    const other_note = "End all existing sessions and API tokens. The owner can sign in again.";
    try html.render(w, @embedFile("snippets/users-revoke.html"), .{
        .action = "users-revoke",
        .title = "Revoke sessions",
        .busy = if (model.busy) " disabled" else "",
        .explanation = if (own) self_note else other_note,
    });
    try html.render(w, "</section>", .{});
}

test "account forms bind to bridge IDs and protect self access and read-only roles" {
    const t = std.testing;
    var state: State = .{ .phase = .users, .user_id = 1 };
    state.csrf = try p.Bytes(64).init("csrf");
    state.role = try p.Bytes(16).init("admin");
    state.users.rows[0] = .{ .id = 1, .username = try p.Bytes(64).init("admin") };
    state.users.count = 1;
    state.users.loaded = true;
    state.users.selected = 0;
    var buffer: [16 * 1024]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&state, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "id=\"users-revoke\"") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "id=\"users-access\"") == null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "id=\"users-password\"") == null);
    state.users.rows[0].id = 2;
    writer = .fixed(&buffer);
    try render(&state, &writer);
    try t.expectEqual(@as(usize, 3), std.mem.count(u8, writer.buffered(), "<form "));
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "id=\"users-access\"") != null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "id=\"users-password\"") != null);
    state.users.selected = null;
    writer = .fixed(&buffer);
    try render(&state, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "id=\"users-create\"") != null);
    state.role = try p.Bytes(16).init("viewer");
    writer = .fixed(&buffer);
    try render(&state, &writer);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), "<form ") == null);
    try t.expect(std.mem.indexOf(u8, writer.buffered(), " disabled>Manage admin") != null);
}
