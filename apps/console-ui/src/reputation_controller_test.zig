const repeat = @import("text").repeat;
const std = @import("std");
const t = std.testing;
const State = @import("state.zig").State;
const controller = @import("reputation_controller.zig");

test "country apply retains reviewed scope and absolute expiry even after form edits" {
    var state: State = .{ .phase = .policies, .browser_time = 100 };
    defer state.reset();
    try state.csrf.set("csrf");
    try state.role.set("operator");
    try state.reputation.committed.set("7");
    var h: @import("test_transport.zig").Commands = .{};
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const fields = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        "{\"country\":\"us\",\"action\":\"deny\",\"hours\":\"1\"}",
        .{},
    );
    try t.expect(try controller.action(&state, "country-preview", fields, h.out()));
    const body = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        "{\"prefixes\":0,\"review\":\"" ++
            &repeat("a", 64) ++
            "\",\"next_offset\":null}",
        .{},
    );
    try controller.response(&state, state.reputation.ticket.slice(), 200, body, h.out());
    try t.expectEqual(@as(u16, 0), state.reputation.summary_prefixes);
    state.browser_time = 400;
    try state.reputation.committed.set("99");
    const changed = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        "{\"country\":\"de\",\"action\":\"allow\",\"hours\":\"4\"}",
        .{},
    );
    try t.expect(try controller.action(&state, "country-apply", changed, h.out()));
    const request = h.writer.buffered();
    for ([_][]const u8{
        "\"country\":\"US\"", "\"action\":\"deny\"",               "\"expected_revision\":\"7\"",
        "\"until\":\"3700\"", "\"review\":\"" ++ &repeat("a", 64),
    }) |expected| try t.expect(std.mem.indexOf(u8, request, expected) != null);
    try controller.response(&state, state.reputation.ticket.slice(), 409, .null, h.out());
    try t.expect(state.reputation.country_review.len == 0);
}
