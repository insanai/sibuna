const std = @import("std");
const t = std.testing;
const p = @import("console").protocol;
const policy = @import("policy");
const fixture = @import("console_store_test.zig");
const auth: p.users.Auth = .{ .session_digest = @splat(1), .csrf_digest = @splat(2) };

/// The caller frees the document's block with `t.allocator.destroy`.
fn read(fx: *fixture.Fixture, kind: p.pages.Kind) !p.pages.Document {
    const result = try fx.run(.{ .page_read = .{ .auth = auth, .kind = kind } });
    try t.expect(result == .page_document);
    return result.page_document;
}

fn edit(fx: *fixture.Fixture, revision: u64, html: []const u8) !p.StorageResult {
    const block = try t.allocator.create(p.pages.Html);
    try block.set(html);
    return fx.run(.{ .page_edit = .{
        .auth = auth,
        .kind = .denied,
        .expected_revision = revision,
        .html = block,
    } });
}

test "page templates validate, commit with audit digests, reject stale edits and reset" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [160]u8 = undefined;
    const fx = try fixture.Fixture.open(
        try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/pages", .{tmp.sub_path}),
    );
    defer fx.close();
    try fixture.policySession(fx);
    const initial = try read(fx, .denied);
    defer t.allocator.destroy(initial.html);
    try t.expect(!initial.customized and initial.revision == 0);
    try t.expect(std.mem.indexOf(u8, initial.html.slice(), "{{ reason }}") != null);
    const invalid = try edit(fx, 0, "<p>{{ reason }}</p><script>alert(1)</script>");
    try t.expect(invalid == .failed and invalid.failed == .invalid_input);
    const unknown = try edit(fx, 0, "<p>{{ nonsense }}</p>");
    try t.expect(unknown == .failed and unknown.failed == .invalid_input);
    const custom = "<!doctype html><p>Blocked: {{ reason }} ({{ status }})</p>";
    try t.expect((try edit(fx, 0, custom)) == .command_recorded);
    const saved = try read(fx, .denied);
    defer t.allocator.destroy(saved.html);
    try t.expect(saved.customized and saved.revision == 1);
    try t.expectEqualStrings(custom, saved.html.slice());
    const stale = try edit(fx, 0, "<p>{{ reason }}</p>");
    try t.expect(stale == .failed and stale.failed == .conflict);
    // The rebuilt engine carries the stored template; other kinds keep their defaults.
    var pages = try t.allocator.create(policy.page_template.Pages);
    defer t.allocator.destroy(pages);
    try @import("console_pages_load.zig").install(fx.owner, pages);
    try t.expect(pages.get(.denied).customized and pages.get(.denied).revision == 1);
    try t.expect(!pages.get(.banned).customized);
    var audit = try @import("console_database.zig").query(fx.owner.db, t.allocator, "SELECT " ++
        "action,after_summary FROM console_audit WHERE action LIKE 'page.%' ORDER BY id", &.{});
    defer audit.deinit();
    try t.expectEqual(@as(usize, 1), audit.rows.len);
    try t.expectEqualStrings("page.edit", audit.rows[0][0].?);
    try t.expect(std.mem.indexOf(u8, audit.rows[0][1].?, "\"sha256\"") != null);
    try t.expect(std.mem.indexOf(u8, audit.rows[0][1].?, "Blocked") == null);
    const reset = try fx.run(.{ .page_edit = .{
        .auth = auth,
        .kind = .denied,
        .expected_revision = 1,
        .reset = true,
    } });
    try t.expect(reset == .command_recorded);
    const restored = try read(fx, .denied);
    defer t.allocator.destroy(restored.html);
    try t.expect(!restored.customized and restored.revision == 0);
    // A stored template that no longer validates keeps the default as a fallback.
    try t.expect((try edit(fx, 0, custom)) == .command_recorded);
    _ = try @import("console_database.zig").exec(
        fx.owner.db,
        t.allocator,
        "UPDATE console_pages SET html='<script>x</script>' WHERE kind='denied'",
        &.{},
    );
    try @import("console_pages_load.zig").install(fx.owner, pages);
    try t.expect(!pages.get(.denied).customized and pages.get(.denied).fallback);
}
