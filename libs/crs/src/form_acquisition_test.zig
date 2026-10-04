const std = @import("std");
const form = @import("form_acquisition.zig");
const values = @import("acquired_values.zig");
const variables = @import("variables.zig");
const work = @import("work.zig");

test "query and form fields preserve duplicate order, empty values and binary bytes" {
    var entries: [48]variables.Entry = undefined;
    var bytes: [256]u8 = undefined;
    var builder = values.Builder.init(&entries, &bytes);
    var key: [32]u8 = undefined;
    var value: [32]u8 = undefined;
    const scratch: form.Scratch = .{ .key = &key, .value = &value };
    var budget: work.Budget = .{ .remaining = 10000 };
    try form.parse("q=a+b&q=%00%26%3d&empty&=v&&", .query, &builder, scratch, &budget);
    try std.testing.expectEqualStrings("a b", builder.entries[0].value);
    try std.testing.expectEqualSlices(u8, &.{ 0, '&', '=' }, builder.entries[4].value);
    try std.testing.expectEqualStrings("", builder.entries[8].value);
    try std.testing.expectEqualStrings("", builder.entries[12].key);
    try std.testing.expectEqualStrings("v", builder.entries[12].value);
    try std.testing.expectEqualStrings("", builder.entries[16].key);
    try std.testing.expectEqualStrings("", builder.entries[16].value);
    const initial = try builder.view();
    try initial.require(.args_get);
    try std.testing.expectError(error.UnavailableCollection, initial.require(.args));
    try form.parse("q=post&literal=a=b;c", .form, &builder, scratch, &budget);
    const complete = try builder.view();
    try complete.require(.args_post);
    try std.testing.expectEqualStrings("post", builder.entries[21].value);
    try std.testing.expectEqualStrings("a=b;c", builder.entries[25].value);
    try std.testing.expectEqualStrings("31.000000", builder.entries[20].value);
    try builder.complete(&.{ .args, .args_names });
    try (try builder.view()).require(.args);
}

test "malformed escapes, scratch bounds and work limits refuse partial parsed bodies" {
    var entries: [12]variables.Entry = undefined;
    var bytes: [64]u8 = undefined;
    var key: [4]u8 = undefined;
    var value: [4]u8 = undefined;
    const scratch: form.Scratch = .{ .key = &key, .value = &value };
    var budget: work.Budget = .{ .remaining = 10000 };
    var builder = values.Builder.init(&entries, &bytes);
    try std.testing.expectError(
        error.InvalidPercentEscape,
        form.parse("q=ok&x=%gg", .form, &builder, scratch, &budget),
    );
    try std.testing.expectError(error.AcquisitionFailed, builder.view());
    try std.testing.expectEqual(variables.Coverage.unavailable, builder.coverage[
        @backingInt(variables.Collection.args_post)
    ]);
    builder = values.Builder.init(&entries, &bytes);
    try std.testing.expectError(
        error.DecodedValueLimit,
        form.parse("longkey=x", .form, &builder, scratch, &budget),
    );
    builder = values.Builder.init(&entries, &bytes);
    budget.remaining = 0;
    try std.testing.expectError(
        error.WorkLimit,
        form.parse("q=x", .form, &builder, scratch, &budget),
    );
    try std.testing.expectEqual(@as(usize, 0), builder.used);
}
