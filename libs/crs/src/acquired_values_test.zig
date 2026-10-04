const std = @import("std");
const acquired = @import("acquired_values.zig");
const variables = @import("variables.zig");
const work = @import("work.zig");

test "parsed aliases retain duplicates and copied bytes with truthful phase coverage" {
    var entries: [16]variables.Entry = undefined;
    var bytes: [128]u8 = undefined;
    var builder = acquired.Builder.init(&entries, &bytes);
    var budget: work.Budget = .{ .remaining = 10000 };
    var value = [_]u8{ 'x', 0, 'y' };
    try builder.field(.query, .{ .key = "q", .value = &value }, &budget);
    @memset(&value, '!');
    try builder.field(.query, .{ .key = "q", .value = "second" }, &budget);
    try builder.field(.json, .{ .key = "json.name", .value = "ok" }, &budget);
    try builder.sizes(&budget);
    try std.testing.expectEqualStrings("22.000000", builder.entries[10].value);
    const unavailable = try builder.view();
    try std.testing.expectError(error.UnavailableCollection, unavailable.require(.args));
    try builder.complete(&.{ .args, .args_names, .args_get, .args_get_names });
    const complete = try builder.view();
    try complete.require(.args);
    try std.testing.expectEqualSlices(u8, &.{ 'x', 0, 'y' }, complete.entries[0].value);
    try std.testing.expectEqualStrings("q", complete.entries[1].value);
    try std.testing.expectEqualStrings("second", complete.entries[4].value);
    try std.testing.expectEqualStrings("json.name", complete.entries[8].key);
    try std.testing.expectError(error.UnavailableCollection, complete.require(.args_post));
}

test "field reservations fail atomically and poison partial acquisition" {
    var entries: [3]variables.Entry = undefined;
    var bytes: [8]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 1000 };
    var builder = acquired.Builder.init(&entries, &bytes);
    try std.testing.expectError(
        error.AcquisitionEntryLimit,
        builder.field(.form, .{ .key = "q", .value = "x" }, &budget),
    );
    try std.testing.expectEqual(@as(usize, 0), builder.used);
    try std.testing.expectEqual(@as(usize, 0), builder.byte_used);
    try std.testing.expectError(error.AcquisitionFailed, builder.view());
    builder = acquired.Builder.init(&entries, &bytes);
    try std.testing.expectError(
        error.AcquisitionByteLimit,
        builder.field(.json, .{ .value = "123456789" }, &budget),
    );
    try std.testing.expectEqual(@as(usize, 0), builder.used);
    builder = acquired.Builder.init(&entries, &bytes);
    budget.remaining = 0;
    try std.testing.expectError(
        error.WorkLimit,
        builder.field(.json, .{ .value = "x" }, &budget),
    );
    try std.testing.expectEqual(@as(usize, 0), builder.byte_used);
}

test "scalar revisions preserve old views and reserved collections cannot be forged" {
    var entries: [4]variables.Entry = undefined;
    var bytes: [32]u8 = undefined;
    var budget: work.Budget = .{ .remaining = 1000 };
    var builder = acquired.Builder.init(&entries, &bytes);
    try builder.scalar(.reqbody_processor, "URLENCODED", &budget);
    const previous = builder.entries[0].value;
    try builder.scalar(.reqbody_processor, "JSON", &budget);
    try std.testing.expectEqual(@as(usize, 1), builder.used);
    try std.testing.expectEqualStrings("URLENCODED", previous);
    try std.testing.expectEqualStrings("JSON", builder.entries[0].value);
    try std.testing.expectError(
        error.ReservedCollection,
        builder.add(.tx, .{ .key = "score", .value = "0" }, &budget),
    );
    try std.testing.expectError(error.AcquisitionFailed, builder.view());
}
