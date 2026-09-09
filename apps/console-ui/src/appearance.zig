//! Browser-local presentation preferences. The bridge reads capabilities and applies
//! commands; this model validates values and resolves the system theme in Wasm.
const std = @import("std");
const Outbox = @import("transport.zig").Outbox;
const values = @import("events_state.zig");
pub const Theme = enum { system, light, dark };
pub const Density = enum { comfortable, compact };
pub const Model = struct {
    theme: Theme = .system,
    density: Density = .comfortable,
    system_dark: bool = false,

    pub fn dark(self: Model) bool {
        return self.theme == .dark or (self.theme == .system and self.system_dark);
    }
};

pub fn environment(model: *Model, value: std.json.Value, load: bool, out: Outbox) !void {
    if (load) {
        model.theme = std.meta.stringToEnum(Theme, values.string(value, "theme")) orelse .system;
        model.density = std.meta.stringToEnum(Density, values.string(value, "density")) orelse
            .comfortable;
    }
    if (values.field(value, "system_dark")) |dark| {
        if (dark == .bool) model.system_dark = dark.bool;
    }
    try apply(model.*, false, out);
}

pub fn action(model: *Model, name: []const u8, out: Outbox) !bool {
    if (std.mem.eql(u8, name, "theme")) {
        model.theme = switch (model.theme) {
            .system => .light,
            .light => .dark,
            .dark => .system,
        };
    } else if (std.mem.eql(u8, name, "density")) {
        model.density = if (model.density == .comfortable) .compact else .comfortable;
    } else return false;
    try apply(model.*, true, out);
    return true;
}

fn apply(model: Model, persist: bool, out: Outbox) !void {
    try out.emit(.{
        .op = "appearance",
        .theme = if (model.dark()) "dark" else "light",
        .preference = model.theme,
        .density = model.density,
        .persist = persist,
    });
}

test "appearance resolves system changes and validates persisted values" {
    const t = std.testing;
    var buffer: [2048]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var count: usize = 0;
    const out: Outbox = .{ .writer = &writer, .count = &count, .csrf = "" };
    var model: Model = .{};
    const saved = try std.json.parseFromSlice(std.json.Value, t.allocator,
        \\{"theme":"system","density":"compact","system_dark":true}
    , .{});
    defer saved.deinit();
    try environment(&model, saved.value, true, out);
    try t.expect(model.dark() and model.density == .compact);
    try t.expect(try action(&model, "theme", out));
    try t.expect(!model.dark() and model.theme == .light);
    try t.expect(try action(&model, "theme", out));
    try t.expect(model.dark() and model.theme == .dark);
    try t.expect(try action(&model, "theme", out));
    try t.expect(model.dark() and model.theme == .system);
    try environment(&model, .null, true, out);
    try t.expect(model.theme == .system and model.density == .comfortable);
}
