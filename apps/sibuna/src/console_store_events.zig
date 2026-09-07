//! Owner-only bounded incident reads. Historical payloads are not evidence envelopes;
//! do not expose them through richer panels until redaction and capture metadata exist.
const std = @import("std");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const store = @import("console_store.zig");
const text = store.text;
const integer = store.integer;

pub fn query(owner: *Persistent, input: p.events.Query) !p.StorageResult {
    try p.events.validate(input);
    const identity = try store.authorize(owner, input.session_digest, input.now);
    if (identity != .authorized or identity.authorized.must_change)
        return .{ .failed = .unauthorized };
    const before = input.before orelse p.events.Cursor{
        .time = std.math.maxInt(i64),
        .id = std.math.maxInt(i64),
    };
    var result = try db.query(owner.db, owner.gpa, sql, &.{
        integer(input.from),             integer(input.until),
        integer(before.time),            integer(before.time),
        integer(before.id),              integer(input.node),
        integer(input.node),             text(input.category.slice()),
        text(input.category.slice()),    text(input.ip.slice()),
        text(input.ip.slice()),          text(input.path_prefix.slice()),
        text(input.path_prefix.slice()), integer(input.limit + 1),
    });
    defer result.deinit();
    var output: p.Bytes(p.max_message) = .{};
    var writer: std.Io.Writer = .fixed(&output.data);
    try writer.writeAll("{\"rows\":[");
    var count: usize = 0;
    var cursor: ?p.events.Cursor = null;
    for (result.rows) |row| {
        if (count >= input.limit) break;
        const event = try decode(row);
        var scratch: [4096]u8 = undefined;
        var item: std.Io.Writer = .fixed(&scratch);
        try event.write(&item);
        // Reserve space for separators, cursor and closing fields, even at maximum escaping.
        if (item.buffered().len + writer.buffered().len + 160 > output.data.len) break;
        if (count != 0) try writer.writeByte(',');
        try writer.writeAll(item.buffered());
        cursor = .{ .time = event.time, .id = event.id };
        count += 1;
    }
    try writer.writeAll("],\"next\":");
    if (count < result.rows.len and cursor != null) {
        try writer.print("{{\"time\":{d},\"id\":\"{d}\"}}", .{ cursor.?.time, cursor.?.id });
    } else try writer.writeAll("null");
    try writer.writeAll("}");
    output.len = writer.buffered().len;
    return .{ .page = output };
}

fn decode(row: []const ?[]const u8) !p.events.Row {
    var result: p.events.Row = .{
        .id = try store.number(row[0]),
        .node = std.math.cast(u32, try store.number(row[1])) orelse
            return error.InvalidStoredValue,
        .time = try store.number(row[2]),
        .campaign = if (row[8] != null) try store.number(row[8]) else null,
    };
    copy(48, &result.ip, row[3] orelse "", &result.display_truncated);
    copy(8, &result.method, row[4] orelse "", &result.display_truncated);
    const path = row[5] orelse "";
    const end = std.mem.indexOfAny(u8, path, "?#") orelse path.len;
    result.query_redacted = end != path.len;
    copy(256, &result.path, path[0..end], &result.display_truncated);
    copy(32, &result.category, row[6] orelse "", &result.display_truncated);
    copy(128, &result.user_agent, row[7] orelse "", &result.display_truncated);
    return result;
}

fn copy(
    comptime size: usize,
    output: *p.Bytes(size),
    source: []const u8,
    truncated: *bool,
) void {
    // Replace malformed historical bytes and controls with '?'; never split UTF-8 at a bound.
    var position: usize = 0;
    while (position < source.len) {
        const count = std.unicode.utf8ByteSequenceLength(source[position]) catch 1;
        const available = @min(count, source.len - position);
        const bytes = source[position..][0..available];
        const valid = available == count and std.unicode.utf8ValidateSlice(bytes) and
            source[position] >= 32 and source[position] != 127;
        const needed: usize = if (valid) count else 1;
        if (output.len + needed > size) break;
        if (valid) {
            @memcpy(output.data[output.len..][0..needed], bytes);
        } else {
            output.data[output.len] = '?';
        }
        output.len += needed;
        position += if (valid) count else @as(usize, 1);
    }
    truncated.* = truncated.* or position != source.len;
}

const sql =
    "SELECT id,node_id,recorded_at,client_ip,method,path,violation_category,user_agent," ++
    "campaign_id FROM security_incidents WHERE recorded_at BETWEEN ? AND ? " ++
    "AND (recorded_at<? OR (recorded_at=? AND id<?)) AND (?=0 OR node_id=?) " ++
    "AND (?='' OR violation_category=?) AND (?='' OR client_ip=?) " ++
    "AND substr(path,1,length(?))=? ORDER BY recorded_at DESC,id DESC LIMIT ?";
