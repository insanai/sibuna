//! Unit tests for the zaxon CLI's domain layer (ZDS 0005). The shared
//! terminal mechanics — editor, history, highlighter, renderers — are
//! tested inside the `zaxon_cli_ui` module; this file covers what stayed
//! product-specific: statement routing, the dot-command registry, and the
//! remote result conversion.

const std = @import("std");
const testing = std.testing;

const render = @import("render.zig");
const shell = @import("shell.zig");

test "shell module declarations compile" {
    try testing.expect(shell.isReadStatement("select 1"));
}

test "remote view converts JSON cells" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        "{\"ok\":true,\"columns\":[\"a\",\"b\"]," ++
        "\"rows\":[[1,\"x\"],[2.5,null]]}";
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        body,
        .{},
    );
    defer parsed.deinit();
    const view = (try render.remoteView(arena.allocator(), &parsed.value.object)).?;
    try testing.expectEqual(@as(usize, 2), view.columns.len);
    try testing.expectEqualStrings("1", view.rows[0][0].?);
    try testing.expectEqualStrings("x", view.rows[0][1].?);
    try testing.expectEqualStrings("2.5", view.rows[1][0].?);
    try testing.expectEqual(@as(?[]const u8, null), view.rows[1][1]);
}
