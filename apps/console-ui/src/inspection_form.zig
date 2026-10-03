const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const data = @import("events_state.zig");
const Writer = std.Io.Writer;
const Mode = enum { disabled, audit, enforce };
pub const Modes = struct { path_traversal: Mode, sqli: Mode, xss: Mode, rce: Mode };
pub const Draft = struct { revision: p.Bytes(20), document: p.Bytes(256), modes: Modes };
const labels = .{
    "Path traversal",
    "SQL injection",
    "Cross-site scripting",
    "Command injection",
};

pub fn findings(w: *Writer, optional: ?u8) Writer.Error!void {
    try html.render(w, "<p>Audit findings: ", .{});
    if (optional) |mask| {
        if (mask == 0) try w.writeAll("None.");
        inline for (labels, 0..) |label, index| {
            if (mask & (@as(u8, 1) << index) != 0) try w.writeAll(label ++ ". ");
        }
    } else try w.writeAll("Not recorded.");
    try html.render(w, "</p>", .{});
}

pub fn submit(page: []const u8, fields: std.json.Value) !Draft {
    var memory: [65536]u8 = undefined;
    var allocator = std.heap.FixedBufferAllocator.init(&memory);
    const snapshot = try std.json.parseFromSliceLeaky(
        std.json.Value,
        allocator.allocator(),
        page,
        .{},
    );
    const committed = data.string(snapshot, "committed");
    const applied = data.string(snapshot, "applied");
    _ = try std.fmt.parseInt(u64, committed, 10);
    if (!std.mem.eql(u8, committed, applied)) return error.Conflict;
    if (!std.mem.eql(u8, data.string(fields, "reviewed"), "on")) return error.NotReviewed;
    const modes = try @import("json_value.zig").decode(Modes, fields, allocator.allocator());
    var draft: Draft = .{
        .revision = try p.Bytes(20).init(committed),
        .document = .{},
        .modes = modes,
    };
    var writer: Writer = .fixed(&draft.document.data);
    try std.json.Stringify.value(modes, .{}, &writer);
    draft.document.len = writer.buffered().len;
    return draft;
}

pub fn render(
    state: *const @import("state.zig").State,
    snapshot: std.json.Value,
    w: *Writer,
    allocator: std.mem.Allocator,
) Writer.Error!void {
    const source = data.field(snapshot, "inspection") orelse return;
    const applied_modes = @import("json_value.zig").decode(Modes, source, allocator) catch
        return html.render(w, "<p>Inspection modes unavailable. Refresh to retry.</p>", .{});
    const modes = state.policies.inspection_draft orelse applied_modes;
    const pending = !std.mem.eql(
        u8,
        data.string(snapshot, "committed"),
        data.string(snapshot, "applied"),
    );
    const disabled = state.policies.busy or state.policies.testing or state.policies.stale or
        pending or !state.allows(.manage_policy);
    try html.render(w, @embedFile("snippets/inspection-header.html"), .{});
    if (pending) try html.render(w, "<p role=\"status\">Waiting for this node to apply " ++
        "the committed revision. Refresh before editing.</p>", .{});
    inline for (@typeInfo(Modes).@"struct".field_names, labels) |field_name, label| {
        try html.render(w, "<label class=\"form-control\" for=\"inspection-{{ v0 }}\">{{ v1 }}" ++
            "<select class=\"select\" id=\"inspection-{{ v2 }}\" name=\"{{ v3 }}\"{{ v4 }}>", .{
            .v0 = field_name,
            .v1 = label,
            .v2 = field_name,
            .v3 = field_name,
            .v4 = if (disabled) " disabled" else "",
        });
        inline for (comptime std.enums.values(Mode)) |mode| try html.render(
            w,
            "<option value=\"{{ v0 }}\"{{ v1 }}>{{ v2 }}</option>",
            .{
                .v0 = @tagName(mode),
                .v1 = if (@field(modes, field_name) == mode) " selected" else "",
                .v2 = switch (mode) {
                    .disabled => "Disabled",
                    .audit => "Audit",
                    .enforce => "Enforce",
                },
            },
        );
        try html.render(w, "</select></label>", .{});
    }
    try html.render(w, @embedFile("snippets/inspection-footer.html"), .{
        .disabled = if (disabled) "disabled" else "",
    });
}

test "inspection form requires the complete reviewed matrix and current applied revision" {
    const t = std.testing;
    const source = "{\"path_traversal\":\"enforce\",\"sqli\":\"audit\",\"xss\":\"disabled\"," ++
        "\"rce\":\"enforce\",\"reviewed\":\"on\"}";
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, source, .{});
    defer parsed.deinit();
    const page = "{\"committed\":\"7\",\"applied\":\"7\"}";
    const draft = try submit(page, parsed.value);
    try t.expectEqualStrings("7", draft.revision.slice());
    try t.expect(std.mem.indexOf(u8, draft.document.slice(), "audit") != null);
    try t.expectError(error.Conflict, submit(
        "{\"committed\":\"8\",\"applied\":\"7\"}",
        parsed.value,
    ));
    try t.expectError(error.NotReviewed, submit(page, .null));
}
