const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const Writer = std.Io.Writer;
pub const Form = @import("policy_form.zig").Form;
pub const Model = struct {
    active: bool = false,
    view: enum { catalog, editor, history } = .catalog,
    snapshot: p.Bytes(4096) = .{},
    committed: p.Bytes(20) = .{},
    next: p.Bytes(128) = .{},
    id: p.Bytes(128) = .{},
    historical: p.Bytes(20) = .{},
    form: Form = .{},
};

pub fn render(state: *const @import("state.zig").State, w: *Writer) Writer.Error!void {
    const model = &state.policies.manager;
    try html.render(w, @embedFile("snippets/policy-manager-header.html"), .{});
    try @import("render.zig").message(state, w);
    if (state.policies.busy) try w.writeAll("<p role=\"status\">Loading policy data…</p>");
    if (model.view == .editor) {
        try editor(state, w);
    } else {
        try listing(state, w);
    }
    try w.writeAll("</main>");
}

fn listing(state: *const @import("state.zig").State, w: *Writer) Writer.Error!void {
    const model = &state.policies.manager;
    if (model.snapshot.len == 0) return;
    var memory: [65536]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const root = std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        model.snapshot.slice(),
        .{},
    ) catch return w.writeAll("<p>Could not read managed policies. Refresh to retry.</p>");
    const rows = if (root == .object) root.object.get("rows") else null;
    if (rows == null or rows.? != .array or rows.?.array.items.len > 8)
        return w.writeAll("<p>Invalid managed-policy response. Refresh to retry.</p>");
    try html.render(w, @embedFile("snippets/policy-manager-summary.html"), .{
        .revision = model.committed.slice(),
        .title = if (model.view == .history) "Revision history" else "Managed rules",
    });
    if (model.view == .catalog and state.allows(.manage_policy))
        try button(w, "managed-new", "New rule", state.policies.busy);
    if (rows.?.array.items.len == 0) {
        try w.writeAll("<p class=\"my-4\">No records to display.</p>");
    }
    for (rows.?.array.items) |row| {
        if (model.view == .catalog) {
            try html.render(w, @embedFile("snippets/policy-managed-row.html"), .{
                .id = text(row, "id"),
                .name = text(row, "name"),
                .action = text(row, "action"),
                .priority = integer(row, "priority"),
                .enabled = if (boolean(row, "enabled")) "Enabled" else "Disabled",
            });
        } else {
            try html.render(w, @embedFile("snippets/policy-history-row.html"), .{
                .revision = text(row, "revision"),
                .actor = text(row, "actor"),
                .kind = text(row, "kind"),
            });
            try @import("events_page.zig").timestamp(
                w,
                @intCast(@max(0, integer(row, "recorded_at"))),
            );
            try w.writeAll("</article>");
        }
    }
    try button(w, "managed-next", "Next page", model.next.len == 0 or
        state.policies.busy or state.policies.stale);
    try w.writeAll("</section>");
}

fn editor(state: *const @import("state.zig").State, w: *Writer) Writer.Error!void {
    const model = &state.policies.manager;
    try html.render(w, @embedFile("snippets/policy-editor-header.html"), .{
        .revision = model.committed.slice(),
    });
    if (model.historical.len != 0) {
        try html.render(w, @embedFile("snippets/policy-restore-notice.html"), .{
            .revision = model.historical.slice(),
        });
    }
    try w.writeAll("<form id=\"policy-run\" class=\"sb-settings-form sb-policy-form\">");
    try @import("policy_form.zig").render(w, &model.form, model.id.len != 0);
    const disabled = state.policies.busy or state.policies.testing or state.policies.stale;
    if (state.allows(.manage_policy))
        try button(w, "managed-save", "Save rule", disabled);
    try html.render(w, @embedFile("snippets/policy-preview-fields.html"), .{
        .path = if (state.policies.path.len == 0) "/" else state.policies.path.slice(),
        .ip = if (state.policies.ip.len == 0) "8.8.8.8" else state.policies.ip.slice(),
        .user_agent = state.policies.user_agent.slice(),
        .query = state.policies.query_string.slice(),
        .body = state.policies.body.slice(),
    });
    try w.print("<button type=\"submit\" class=\"btn\"{s}>Preview draft</button></form>", .{
        if (disabled) " disabled" else "",
    });
    var memory: [16384]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    try @import("policies_page.zig").decision(w, &state.policies, arena.allocator());
    try w.writeAll("</section>");
}

fn button(w: *Writer, action: []const u8, label: []const u8, disabled: bool) Writer.Error!void {
    if (std.mem.eql(u8, action, "managed-save")) {
        try w.print("<button type=\"button\" class=\"btn btn-primary my-3\" " ++
            "data-action=\"managed-save\" data-validate=\"true\"{s}>Save rule</button>", .{
            if (disabled) " disabled" else "",
        });
        return;
    }
    try w.print("<button type=\"button\" class=\"btn my-3\" " ++
        "data-action=\"{s}\"{s}>{s}</button>", .{
        action, if (disabled) " disabled" else "", label,
    });
}

pub fn text(value: std.json.Value, key: []const u8) []const u8 {
    if (value != .object) return "";
    const field = value.object.get(key) orelse return "";
    return if (field == .string) field.string else "";
}

fn integer(value: std.json.Value, key: []const u8) i64 {
    if (value != .object) return 0;
    const field = value.object.get(key) orelse return 0;
    return if (field == .integer) field.integer else 0;
}

fn boolean(value: std.json.Value, key: []const u8) bool {
    if (value != .object) return false;
    const field = value.object.get(key) orelse return false;
    return field == .bool and field.bool;
}

test {
    _ = @import("policy_form.zig");
}
