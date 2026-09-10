//! One indexed scan per request, below native and replicated database result limits.
//! Counter aggregation stays on the storage owner; no raw database handle escapes.
const std = @import("std");
const p = @import("console").protocol;
const wire = p.minute_summary;
const minutes = @import("console_store_minutes.zig");
const settings = @import("console_store_settings.zig");
const access = @import("console_read_authorize.zig");
const Persistent = @import("persistent.zig").Persistent;

pub fn query(owner: *Persistent, input: p.minutes.Query) !p.StorageResult {
    wire.validate(input) catch return .{ .failed = .invalid_input };
    if (try access.check(owner, input.session_digest, input.require_totp, .stats_read)) |reason|
        return .{ .failed = reason };
    const retained = try settings.retention(owner, "retention.minutes");
    var bounded = input;
    bounded.from_minute = @max(input.from_minute, input.observed_at / 60 -|
        (@as(u64, retained.days) * 1440));
    var part: wire.Part = .{ .observed_at = input.observed_at, .window = .{
        .node = input.node.?,
        .from = input.from_minute,
        .until = input.until_minute,
        .retention_days = retained.days,
        .retention_changed = bounded.from_minute != input.from_minute,
    } };
    if (bounded.from_minute <= bounded.until_minute) try scan(owner, bounded, &part);
    part.window.finished = part.window.next == null;
    if (try access.check(owner, input.session_digest, input.require_totp, .stats_read)) |reason|
        return .{ .failed = reason };
    if (!std.meta.eql(retained, try settings.retention(owner, "retention.minutes")))
        return .{ .failed = .conflict };
    return .{ .minute_summary = part };
}

fn scan(owner: *Persistent, input: p.minutes.Query, part: *wire.Part) !void {
    // 97 rows including lookahead: at most 29,488 payload bytes, within the existing
    // 100-row / 64-KiB query envelope. A summary never enlarges mailbox slots.
    var result = try minutes.readQuery(owner, input);
    defer result.deinit();
    const count = @min(result.rows.len, input.limit);
    for (result.rows[0..count]) |row| {
        const record = try minutes.decode(row[0] orelse return error.InvalidStoredValue);
        if (input.before) |cursor| if (!wire.precedes(record.cursor(), cursor))
            return error.InvalidStoredValue;
        if (part.first == null) part.first = record.cursor();
        try part.window.add(record);
    }
    if (result.rows.len > input.limit) part.window.next = part.window.last;
}
