const std = @import("std");
const t = std.testing;
const api = @import("crs_detail.zig");

test "widest evidence serializes within its detail bound with full signed deltas" {
    var input: api.Detail = .{
        .rule_id = std.math.maxInt(u32),
        .phase = 5,
        .omitted_tags = 65536 - api.tag_capacity,
        .tag_count = api.tag_capacity,
    };
    input.message = api.Preview(96).copy(&@as([4096]u8, @splat(0xff)));
    for (&input.tags) |*tag| tag.* = api.Preview(64).copy(&@as([65536]u8, @splat(0xfe)));
    input.score = .{};
    for (&input.score.?.buckets, 0..) |*bucket, index| bucket.* = .{
        .writes = std.math.maxInt(u32),
        .delta = if (index % 2 == 0) std.math.minInt(i64) else std.math.maxInt(i64),
    };
    try input.validate();
    const bytes = try std.json.Stringify.valueAlloc(t.allocator, input, .{});
    defer t.allocator.free(bytes);
    try t.expect(bytes.len <= api.max_json);
    const parsed = try std.json.parseFromSlice(api.Wire, t.allocator, bytes, .{});
    defer parsed.deinit();
    var output: api.Detail = undefined;
    try parsed.value.into(&output);
    try t.expectEqualDeep(input, output);
    try t.expectEqualStrings("-9223372036854775808", parsed.value.score.?.buckets[0].delta.?);
}

test "evidence rejects dishonest absent scores invalid prefixes and hidden tags" {
    var input: api.Detail = .{ .rule_id = 1, .phase = 2 };
    input.score = .{};
    try t.expectError(error.InvalidEvidence, input.validate());
    input.score.?.buckets[0] = .{ .delta = 0 };
    try t.expectError(error.InvalidEvidence, input.validate());
    input.score.?.buckets[0] = .{ .writes = 1 };
    try input.validate();
    input.tags[3] = api.Preview(64).copy("hidden");
    try t.expectError(error.InvalidEvidence, input.validate());
    input.tags[3] = null;
    input.message = api.Preview(96).copy("safe");
    input.message.?.bytes = 100;
    try t.expectError(error.InvalidEvidence, input.validate());
    input.message = api.Preview(96).copy("safe");
    input.message.?.data[50] = 1;
    try t.expectError(error.InvalidEvidence, input.validate());
}

test "wire validation refuses partial numeric values and malformed binary previews" {
    const input: api.Detail = .{
        .rule_id = 1,
        .phase = 2,
        .message = api.Preview(96).copy("literal %{MATCHED_VAR}"),
        .score = .{ .buckets = @as([1]api.Bucket, .{.{ .writes = 1, .delta = -5 }}) ++
            @as([7]api.Bucket, @splat(.{})) },
    };
    const bytes = try std.json.Stringify.valueAlloc(t.allocator, input, .{});
    defer t.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(api.Wire, t.allocator, bytes, .{});
    defer parsed.deinit();
    var wire = parsed.value;
    var output: api.Detail = undefined;
    wire.score.?.buckets[0].delta = "-5secret";
    try t.expectError(error.InvalidEvidence, wire.into(&output));
    wire = parsed.value;
    wire.message.?.hex = "00";
    try t.expectError(error.InvalidEvidence, wire.into(&output));
}
