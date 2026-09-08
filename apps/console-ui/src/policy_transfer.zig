const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const Form = @import("policy_form.zig").Form;
const State = @import("state.zig").State;
pub const Result = enum { ignored, imported, exported };

pub fn apply(
    state: *State,
    name: []const u8,
    fields: std.json.Value,
    output: *p.Bytes(4096),
) !Result {
    const importing = std.mem.eql(u8, name, "managed-import");
    const exporting = std.mem.eql(u8, name, "managed-export");
    if (!importing and !exporting) return .ignored;
    const model = &state.policies;
    const manager = &model.manager;
    if (!state.fullAccess() or state.phase != .policies or !manager.active or
        manager.view != .editor or model.busy or model.testing) return error.Unavailable;
    if (importing and !state.allows(.manage_policy)) return error.Unavailable;
    if (fields != .object) return error.InvalidDocument;
    if (exporting) {
        try manager.form.capture(fields);
        if (manager.id.len != 0 and
            !std.mem.eql(u8, manager.id.slice(), manager.form.id.slice())) return error.InvalidId;
        try manager.form.document(output);
        return .exported;
    }
    const document = fields.object.get("document") orelse return error.InvalidDocument;
    if (document != .string) return error.InvalidDocument;
    try manager.import_text.set(document.string);
    try validateFields(document.string);
    var form: Form = undefined;
    try form.load(document.string);
    try form.document(output);
    if (manager.id.len != 0 and !std.mem.eql(u8, manager.id.slice(), form.id.slice()))
        return error.InvalidId;
    // Replace only after parsing succeeds. Import never submits a storage mutation.
    manager.form = form;
    manager.historical = .{};
    model.decision = .{};
    return .imported;
}

fn validateFields(source: []const u8) !void {
    var memory: [65536]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const root = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), source, .{});
    if (root != .object) return error.InvalidDocument;
    var keys = root.object.iterator();
    while (keys.next()) |entry| {
        const key = entry.key_ptr.*;
        var known = false;
        inline for (.{
            "id",
            "name",
            "action",
            "priority",
            "enabled",
            "path",
            "user_agent",
            "algorithm",
            "difficulty",
            "weight",
            "headers",
            "cidrs",
            "limits",
        }) |field| {
            if (std.mem.eql(u8, key, field)) known = true;
        }
        if (!known) return error.UnknownField;
    }
    for ([_][]const u8{ "id", "name", "action", "path", "user_agent", "algorithm" }) |key| {
        const value = root.object.get(key) orelse {
            if (std.mem.eql(u8, key, "id") or std.mem.eql(u8, key, "name") or
                std.mem.eql(u8, key, "action")) return error.InvalidDocument;
            continue;
        };
        if (value != .string and value != .null) return error.InvalidDocument;
        if (value == .null and (std.mem.eql(u8, key, "id") or std.mem.eql(u8, key, "name") or
            std.mem.eql(u8, key, "action"))) return error.InvalidDocument;
    }
    const action = root.object.get("action").?.string;
    if (!std.mem.eql(u8, action, "deny") and !std.mem.eql(u8, action, "allow") and
        !std.mem.eql(u8, action, "challenge") and !std.mem.eql(u8, action, "weigh"))
        return error.InvalidDocument;
}

pub fn render(state: *const State, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    if (!state.allows(.manage_policy)) return;
    try html.render(writer, @embedFile("snippets/policy-import.html"), .{
        .document = state.policies.manager.import_text.slice(),
    });
}

test "import rejects ignored fields and preserves the old draft on ID mismatch" {
    const t = std.testing;
    var state: State = .{ .phase = .policies };
    state.csrf = try p.Bytes(64).init("test");
    state.role = try p.Bytes(16).init("admin");
    state.policies.manager.active = true;
    state.policies.manager.view = .editor;
    state.policies.manager.id = try p.Bytes(128).init("original");
    try t.expectError(error.UnknownField, validateFields(
        "{\"id\":\"a\",\"name\":\"a\",\"action\":\"deny\",\"typo\":true}",
    ));
    var output: p.Bytes(4096) = undefined;
    var fields = std.json.Value{ .object = .{} };
    defer fields.object.deinit(t.allocator);
    try fields.object.put(t.allocator, "document", .{
        .string = "{\"id\":\"new\",\"name\":\"Imported\",\"action\":\"deny\"}",
    });
    try t.expectError(error.InvalidId, apply(&state, "managed-import", fields, &output));
    try t.expectEqual(@as(usize, 0), state.policies.manager.form.name.len);
    state.policies.manager.id = .{};
    try t.expectEqual(.imported, try apply(&state, "managed-import", fields, &output));
    try t.expectEqualStrings("Imported", state.policies.manager.form.name.slice());
    try t.expect(!state.policies.busy);
}
