const std = @import("std");
const json = @import("json_acquisition.zig");
const values = @import("acquired_values.zig");
const variables = @import("variables.zig");
const work = @import("work.zig");
const State = struct {
    entries: [64]variables.Entry = undefined,
    bytes: [1024]u8 = undefined,
    value: [128]u8 = undefined,
    path: [128]u8 = undefined,
    bits: [1]u8 = undefined,
    frames: [8]json.Frame = undefined,
    builder: values.Builder = undefined,
    budget: work.Budget = .{ .remaining = 100000 },

    fn init(self: *State) void {
        self.builder = values.Builder.init(&self.entries, &self.bytes);
    }

    fn parse(self: *State, input: []const u8) !void {
        try json.parse(input, &self.builder, .{
            .value = &self.value,
            .path = &self.path,
            .bits = &self.bits,
            .frames = &self.frames,
        }, &self.budget);
    }
};

test "JSON paths preserve duplicate keys, nested array ordinals and reference empty keys" {
    var state: State = .{};
    state.init();
    try state.parse(
        \\{"a":1,"a":2,"list":["first",{"x":"y"},[true,null],{}],"":"empty"}
    );
    const expected = [_]values.Record{
        .{ .key = "json.a", .value = "1" },
        .{ .key = "json.a", .value = "2" },
        .{ .key = "json.list.array_0", .value = "first" },
        .{ .key = "json.list.array_1.x", .value = "y" },
        .{ .key = "json.list.array_2.array_0", .value = "true" },
        .{ .key = "json.list.array_2.array_1", .value = "" },
        .{ .key = "json.empty-key", .value = "empty" },
    };
    for (expected, 0..) |record, index| {
        try std.testing.expectEqualStrings(record.key, state.entries[index * 2].key);
        try std.testing.expectEqualStrings(record.value, state.entries[index * 2].value);
    }
    const view = try state.builder.view();
    try std.testing.expectError(error.UnavailableCollection, view.require(.args_post));
    try std.testing.expectError(error.UnavailableCollection, view.require(.args));
}

test "JSON decoding preserves binary strings, surrogate pairs and numeric spelling" {
    var state: State = .{};
    state.init();
    try state.parse(
        \\{"k\u0000":"a\u0000b","emoji":"\ud83d\ude00","n":-1.25e+02}
    );
    try std.testing.expectEqualSlices(u8, "json.k\x00", state.entries[0].key);
    try std.testing.expectEqualSlices(u8, "a\x00b", state.entries[0].value);
    try std.testing.expectEqualStrings("\xf0\x9f\x98\x80", state.entries[2].value);
    try std.testing.expectEqualStrings("-1.25e+02", state.entries[4].value);
    state.init();
    try state.parse("false");
    try std.testing.expectEqualStrings("json", state.entries[0].key);
    try std.testing.expectEqualStrings("false", state.entries[0].value);
}

test "invalid JSON poisons earlier fields and bounded paths cannot grow" {
    var state: State = .{};
    state.init();
    try std.testing.expectError(error.InvalidJson, state.parse("{\"a\":1,\"b\":}"));
    try std.testing.expectError(error.AcquisitionFailed, state.builder.view());
    state.init();
    try std.testing.expectError(
        error.JsonDepthLimit,
        state.parse("[[[[[[[[[]]]]]]]]]"),
    );
    state.init();
    var tiny_path: [2]u8 = undefined;
    try std.testing.expectError(error.JsonPathLimit, json.parse("true", &state.builder, .{
        .value = &state.value,
        .path = &tiny_path,
        .bits = &state.bits,
        .frames = &state.frames,
    }, &state.budget));
    try std.testing.expectError(error.AcquisitionFailed, state.builder.view());
}
