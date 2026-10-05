const std = @import("std");
const local = @import("local_store.zig");
const files = @import("local_files.zig");

test "local store locks serialize selection and fence daemon receipt ownership" {
    const t = std.testing;
    var temporary = t.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const store: local.Store = .{
        .allocator = t.allocator,
        .io = t.io,
        .directory = temporary.dir,
    };
    var first = try store.lock(.shared);
    var second = try store.lock(.shared);
    try t.expectError(error.LocalStoreBusy, store.lock(.exclusive));
    second.deinit();
    first.deinit();
    var writer = try store.lock(.exclusive);
    try t.expectError(error.LocalStoreBusy, store.lock(.shared));
    try t.expectError(error.LocalStoreBusy, store.lock(.exclusive));
    writer.deinit();
    const daemon = try store.claimDaemon();
    try t.expectError(error.LocalStoreBusy, store.claimDaemon());
    daemon.close(t.io);
    const restart = try store.claimDaemon();
    restart.close(t.io);
    var reader = try store.lock(.shared);
    defer reader.deinit();
    try t.expect(try reader.selection() == null);
    try t.expect(try reader.observation() == null);
}

test "local store intent and receipt are distinct and reject stale or malformed state" {
    const t = std.testing;
    var temporary = t.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const store: local.Store = .{
        .allocator = t.allocator,
        .io = t.io,
        .directory = temporary.dir,
    };
    const selection: local.Selection = .{
        .current = .{ .id = @splat(1), .digest = @splat(2), .revision = 1 },
        .previous = null,
        .selected_at = 3,
    };
    try files.write(t.io, temporary.dir, "selection.bin", selection);
    var locked = try store.lock(.shared);
    defer locked.deinit();
    try t.expectEqualDeep(selection, (try locked.selection()).?);
    try t.expect(try locked.observation() == null);
    const receipt: local.Receipt = .{
        .source = selection.current,
        .boot = @splat(4),
        .observed_at = 5,
        .state = .applied,
    };
    try locked.record(receipt);
    try t.expectEqualDeep(receipt, (try locked.observation()).?);
    var restarted = receipt;
    restarted.boot = @splat(6);
    try locked.record(restarted);
    try t.expectEqualDeep(restarted, (try locked.observation()).?);
    var stale = receipt;
    stale.source.revision = 2;
    try t.expectError(error.LocalStoreConflict, locked.record(stale));
    try t.expectEqualDeep(restarted, (try locked.observation()).?);
    try temporary.dir.writeFile(t.io, .{ .sub_path = "selection.bin", .data = "{broken" });
    try t.expectError(error.SyntaxError, locked.selection());
}

test "local store stale revision fails before accessing a candidate or modifying intent" {
    const t = std.testing;
    var temporary = t.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const store: local.Store = .{
        .allocator = t.allocator,
        .io = t.io,
        .directory = temporary.dir,
    };
    const selection: local.Selection = .{
        .current = .{ .id = @splat(1), .digest = @splat(2), .revision = 1 },
        .previous = null,
        .selected_at = 3,
    };
    try files.write(t.io, temporary.dir, "selection.bin", selection);
    var candidate: @import("prepared.zig").Prepared = undefined;
    try t.expectError(error.LocalStoreConflict, store.select(0, undefined, &candidate));
    var locked = try store.lock(.shared);
    defer locked.deinit();
    try t.expectEqualDeep(selection, (try locked.selection()).?);
}
