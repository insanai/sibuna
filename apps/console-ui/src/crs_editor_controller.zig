//! Typed bounds are shared with native management; forms never submit a witness.
const std = @import("std");
const p = @import("console_protocol");
const ctx = @import("controller_context.zig");
const fields = @import("events_state.zig");
const controller = @import("crs_controller.zig");

pub fn prepare(c: ctx.Context, name: []const u8, values: std.json.Value) !void {
    const model = &c.state.crs;
    const snapshot = model.snapshot orelse return;
    if (model.stale or !snapshot.available) return;
    const kind = operation(name);
    const source = if (kind == .rollback) snapshot.previous else snapshot.current;
    if ((kind == .rollback or kind == .mode) and source == null) return;
    var settings: p.crs_management.Settings = .{};
    if (source) |row| settings = row.artifact.?.settings;
    // The rollback button lives in the mode form. Its unsent controls must not
    // override the retained previous settings that the operator is restoring.
    if (kind != .rollback) settings = read(values, settings) catch {
        try c.state.message.set("Check the mode, paranoia levels, thresholds and numeric limits.");
        return;
    };
    const editing = kind == .check or kind == .update;
    if (editing) {
        if (!model.editor_loaded or model.editor_revision != snapshot.revision) {
            try c.state.message.set("The saved revision changed. Reload operator rules " ++
                "before preparing an update; copy any unsaved edits first.");
            return;
        }
        try model.editor.set(fields.string(values, "configuration"));
    }
    try controller.ticket(c, .prepare);
    errdefer model.busy = .idle;
    var revision: [20]u8 = undefined;
    const version = fields.string(values, "version");
    try c.out.post(model.ticket.slice(), "/console/api/crs/prepare", .{
        .id = snapshot.next_id.slice(),
        .kind = kind,
        .expected_revision = try std.fmt.bufPrint(&revision, "{d}", .{snapshot.revision}),
        .settings = if (kind == .rollback) @as(?p.crs_management.Settings, null) else settings,
        .version = if (editing and version.len != 0) version else @as(?[]const u8, null),
        .configuration = if (editing) model.editor.slice() else @as(?[]const u8, null),
    });
}

fn operation(name: []const u8) p.crs_management.Kind {
    if (std.mem.eql(u8, name, "crs-mode")) return .mode;
    if (std.mem.eql(u8, name, "crs-rollback")) return .rollback;
    if (std.mem.eql(u8, name, "crs-update")) return .update;
    return .check;
}

fn read(value: std.json.Value, defaults: p.crs_management.Settings) !p.crs_management.Settings {
    var output = defaults;
    inline for (@typeInfo(p.crs_management.Settings).@"struct".field_names) |name| {
        if (fields.field(value, name)) |item| {
            if (item != .string or item.string.len == 0) return error.InvalidLimit;
            const T = @FieldType(p.crs_management.Settings, name);
            if (comptime @typeInfo(T) == .@"enum") {
                @field(output, name) = std.meta.stringToEnum(T, item.string) orelse
                    return error.InvalidLimit;
            } else {
                for (item.string) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidLimit;
                @field(output, name) = try std.fmt.parseInt(T, item.string, 10);
            }
        }
    }
    try output.validate();
    return output;
}

test "CRS editor bounds and enum parsing preserve unspecified cloned settings" {
    const t = std.testing;
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"mode\":\"off\",\"slots\":\"2\"}",
        .{},
    );
    defer parsed.deinit();
    const settings = try read(parsed.value, .{ .inbound_threshold = 9 });
    try t.expectEqual(p.crs.Mode.off, settings.mode);
    try t.expectEqual(@as(u8, 2), settings.slots);
    try t.expectEqual(@as(u16, 9), settings.inbound_threshold);
    const invalid = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"blocking_paranoia\":\"4\",\"detection_paranoia\":\"1\"}",
        .{},
    );
    defer invalid.deinit();
    try t.expectError(error.InvalidLimit, read(invalid.value, .{}));
}

test "rollback ignores adjacent unsent mode controls and restores retained settings" {
    const t = std.testing;
    const state = try t.allocator.create(@import("state.zig").State);
    defer t.allocator.destroy(state);
    state.* = .{};
    @import("crs_fixture.zig").configure(state, false, false);
    var previous = state.crs.snapshot.?.current.?;
    previous.artifact.?.settings.mode = .enforce;
    previous.artifact.?.settings.inbound_threshold = 12;
    state.crs.snapshot.?.previous = previous;
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"mode\":\"off\",\"inbound_threshold\":\"1\"}",
        .{},
    );
    defer parsed.deinit();
    var bytes: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    var count: usize = 0;
    try prepare(.{
        .state = state,
        .out = .{ .writer = &writer, .count = &count, .csrf = "test" },
    }, "crs-rollback", parsed.value);
    const command = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        writer.buffered(),
        .{},
    );
    defer command.deinit();
    const body = command.value.object.get("body").?;
    try t.expectEqualStrings("rollback", fields.string(body, "kind"));
    try t.expectEqual(std.json.Value.null, body.object.get("settings").?);
    try t.expectEqual(std.json.Value.null, body.object.get("configuration").?);
}

test "worst escaped CRS editor fits its command bound and owns the event bytes" {
    const t = std.testing;
    const State = @import("state.zig").State;
    const state = try t.allocator.create(State);
    defer t.allocator.destroy(state);
    state.* = .{};
    try state.role.set("admin");
    try state.csrf.set("test");
    @import("crs_fixture.zig").configure(state, false, false);
    const text = try t.allocator.alloc(u8, p.crs_api.editor_bytes);
    defer t.allocator.free(text);
    @memset(text, 1);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        "{\"configuration\":\"\",\"version\":\"\"}",
        .{},
    );
    defer parsed.deinit();
    var values = parsed.value;
    values.object.getPtr("configuration").?.* = .{ .string = text };
    values.object.getPtr("version").?.* = .{ .string = "4.30.0" };
    const bytes = try t.allocator.alloc(u8, p.crs_api.body_bytes + 4096);
    defer t.allocator.free(bytes);
    var writer: std.Io.Writer = .fixed(bytes);
    var count: usize = 0;
    try prepare(.{
        .state = state,
        .out = .{ .writer = &writer, .count = &count, .csrf = "test" },
    }, "crs-check", values);
    const command = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        writer.buffered(),
        .{},
    );
    defer command.deinit();
    const body = command.value.object.get("body").?;
    try t.expectEqual(p.crs_api.editor_bytes, fields.string(body, "configuration").len);
    @memset(text, 2);
    try t.expect(std.mem.allEqual(u8, state.crs.editor.slice(), 1));
    state.reset();
    try t.expect(std.mem.allEqual(u8, &state.crs.editor.data, 0));
}
