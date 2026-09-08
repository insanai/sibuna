//! Bounded managed-rule and history reads. Documents are complete; summaries are display-only.
const std = @import("std");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const candidates = @import("console_policy_candidate.zig");

pub fn read(owner: *Persistent, input: p.policies.Read) !p.StorageResult {
    try p.policies.validateRead(input);
    const identity = try util.authorize(owner, input.session_digest, input.now);
    if (identity != .authorized or identity.authorized.must_change)
        return .{ .failed = .unauthorized };
    const revision = try candidates.revision(owner);
    if (input.committed) |expected| if (expected != revision) return .{ .failed = .conflict };
    const result = switch (input.selection) {
        .catalog => |after| try catalog(owner, revision, after.slice()),
        .document => |document| try readDocument(owner, revision, document),
        .history => |history| try readHistory(owner, revision, history),
    };
    if (try candidates.revision(owner) != revision) return .{ .failed = .conflict };
    return result;
}

fn catalog(owner: *Persistent, revision: u64, after: []const u8) !p.StorageResult {
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT id,name,priority,enabled,action FROM policies WHERE id>? ORDER BY id LIMIT 9",
        &.{util.text(after)},
    );
    defer rows.deinit();
    var output: p.Bytes(4096) = .{};
    var writer: std.Io.Writer = .fixed(&output.data);
    try writer.print("{{\"committed\":\"{d}\",\"rows\":[", .{revision});
    var count: usize = 0;
    while (count < @min(rows.rows.len, 8)) : (count += 1) {
        const row = rows.rows[count];
        var scratch: [4096]u8 = undefined;
        var item: std.Io.Writer = .fixed(&scratch);
        const id = try p.Bytes(128).init(row[0] orelse return error.InvalidStoredPolicy);
        const name = row[1] orelse "";
        try std.json.Stringify.value(.{
            .id = id.slice(),
            .name = display(name),
            .truncated = name.len > 128 or !std.unicode.utf8ValidateSlice(name),
            .priority = try std.fmt.parseInt(i32, row[2].?, 10),
            .enabled = (try util.number(row[3])) != 0,
            .action = display(row[4] orelse ""),
        }, .{}, &item);
        if (writer.buffered().len + item.buffered().len + 1024 > output.data.len) break;
        if (count != 0) try writer.writeByte(',');
        try writer.writeAll(item.buffered());
    }
    if (count == 0 and rows.rows.len != 0) return error.InvalidStoredPolicy;
    try writer.writeAll("],\"next\":");
    try std.json.Stringify.value(
        if (rows.rows.len > count) rows.rows[count - 1][0] else null,
        .{},
        &writer,
    );
    try writer.writeByte('}');
    output.len = writer.buffered().len;
    return .{ .page = output };
}

fn readDocument(owner: *Persistent, revision: u64, input: anytype) !p.StorageResult {
    if (input.revision) |historical| {
        var rows = try db.query(
            owner.db,
            owner.gpa,
            "SELECT document FROM console_policy_history WHERE policy_id=? AND revision=? LIMIT 1",
            &.{ util.text(input.id.slice()), util.integer(historical) },
        );
        defer rows.deinit();
        if (rows.rows.len == 0) return .{ .failed = .invalid_input };
        return .{ .policy_document = .{
            .revision = revision,
            .document = try p.Bytes(4096).init(rows.rows[0][0].?),
        } };
    }
    const document = try candidates.readDocument(owner, input.id.slice()) orelse
        return .{ .failed = .invalid_input };
    return .{ .policy_document = .{ .revision = revision, .document = document } };
}

fn readHistory(owner: *Persistent, revision: u64, input: anytype) !p.StorageResult {
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT revision,actor,recorded_at,kind FROM console_policy_history " ++
            "WHERE policy_id=? AND revision<? ORDER BY revision DESC LIMIT 9",
        &.{ util.text(input.id.slice()), util.integer(input.before orelse std.math.maxInt(i64)) },
    );
    defer rows.deinit();
    var output: p.Bytes(4096) = .{};
    var writer: std.Io.Writer = .fixed(&output.data);
    try writer.print("{{\"committed\":\"{d}\",\"rows\":[", .{revision});
    const count = @min(rows.rows.len, 8);
    for (rows.rows[0..count], 0..) |row, i| {
        if (i != 0) try writer.writeByte(',');
        try std.json.Stringify.value(.{
            .revision = row[0].?,
            .actor = row[1].?,
            .recorded_at = try util.number(row[2]),
            .kind = row[3].?,
        }, .{}, &writer);
    }
    try writer.writeAll("],\"next\":");
    try std.json.Stringify.value(
        if (rows.rows.len > count) rows.rows[count - 1][0] else null,
        .{},
        &writer,
    );
    try writer.writeByte('}');
    output.len = writer.buffered().len;
    return .{ .page = output };
}

fn display(value: []const u8) []const u8 {
    if (!std.unicode.utf8ValidateSlice(value)) return "[invalid text]";
    var end = @min(value.len, 128);
    while (!std.unicode.utf8ValidateSlice(value[0..end])) end -= 1;
    return value[0..end];
}
