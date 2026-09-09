//! Top-level set/remove deltas. Arrays are replaced as a field, never merged by position.
//! Scratch allocation belongs to the caller and is reclaimed after each comparison.
const std = @import("std");

pub fn write(
    allocator: std.mem.Allocator,
    previous: []const u8,
    current: []const u8,
    output: *std.Io.Writer,
) !bool {
    const old = try std.json.parseFromSlice(std.json.Value, allocator, previous, .{});
    defer old.deinit();
    const new = try std.json.parseFromSlice(std.json.Value, allocator, current, .{});
    defer new.deinit();
    if (old.value != .object or new.value != .object) return error.InvalidState;
    var json: std.json.Stringify = .{ .writer = output };
    var changed = false;
    try json.beginObject();
    try json.objectField("set");
    try json.beginObject();
    var items = new.value.object.iterator();
    while (items.next()) |item| {
        if (old.value.object.get(item.key_ptr.*)) |before| {
            if (equal(before, item.value_ptr.*)) continue;
        }
        try json.objectField(item.key_ptr.*);
        try json.write(item.value_ptr.*);
        changed = true;
    }
    try json.endObject();
    try json.objectField("remove");
    try json.beginArray();
    var before = old.value.object.iterator();
    while (before.next()) |item| {
        if (new.value.object.contains(item.key_ptr.*)) continue;
        try json.write(item.key_ptr.*);
        changed = true;
    }
    try json.endArray();
    try json.endObject();
    return changed;
}

fn equal(a: std.json.Value, b: std.json.Value) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .null => true,
        .bool => a.bool == b.bool,
        .integer => a.integer == b.integer,
        .float => a.float == b.float,
        .number_string => std.mem.eql(u8, a.number_string, b.number_string),
        .string => std.mem.eql(u8, a.string, b.string),
        .array => arrays: {
            if (a.array.items.len != b.array.items.len) break :arrays false;
            for (a.array.items, b.array.items) |x, y| if (!equal(x, y)) break :arrays false;
            break :arrays true;
        },
        .object => objects: {
            if (a.object.count() != b.object.count()) break :objects false;
            var items = a.object.iterator();
            while (items.next()) |item| {
                const value = b.object.get(item.key_ptr.*) orelse break :objects false;
                if (!equal(item.value_ptr.*, value)) break :objects false;
            }
            break :objects true;
        },
    };
}

/// Apply only after verifying the enclosing topic, epoch and contiguous sequence. The
/// object's allocator owns the resulting map; nested values borrow the parsed message.
pub fn apply(allocator: std.mem.Allocator, state: *std.json.Value, delta: std.json.Value) !void {
    if (state.* != .object or delta != .object or delta.object.count() != 2)
        return error.InvalidDelta;
    const set = delta.object.get("set") orelse return error.InvalidDelta;
    const remove = delta.object.get("remove") orelse return error.InvalidDelta;
    if (set != .object or remove != .array) return error.InvalidDelta;
    for (remove.array.items) |key| {
        if (key != .string or set.object.contains(key.string)) return error.InvalidDelta;
    }
    // Reserve first so allocation failure cannot leave an incompletely applied delta.
    try state.object.ensureUnusedCapacity(allocator, @intCast(set.object.count()));
    for (remove.array.items) |key| _ = state.object.swapRemove(key.string);
    var items = set.object.iterator();
    while (items.next()) |item| state.object.putAssumeCapacity(item.key_ptr.*, item.value_ptr.*);
}

test "deltas preserve unchanged fields, large counters and explicit nulls" {
    const t = std.testing;
    var bytes: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    const previous = "{\"count\":\"9007199254740993\"," ++
        "\"rows\":[1],\"old\":true}";
    const current = "{\"count\":\"9007199254740994\",\"rows\":[1],\"empty\":null}";
    try t.expect(try write(t.allocator, previous, current, &writer));
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        writer.buffered(),
        .{},
    );
    defer parsed.deinit();
    try t.expect(!parsed.value.object.get("set").?.object.contains("rows"));
    var state = try std.json.parseFromSlice(std.json.Value, t.allocator, previous, .{});
    defer state.deinit();
    try apply(state.arena.allocator(), &state.value, parsed.value);
    const expected = try std.json.parseFromSlice(std.json.Value, t.allocator, current, .{});
    defer expected.deinit();
    try t.expect(equal(state.value, expected.value));
    writer.end = 0;
    try t.expect(!try write(t.allocator, current, current, &writer));
}
