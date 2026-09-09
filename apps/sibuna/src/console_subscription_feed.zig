//! Bounded background reads on Persistent. Subscription handlers never receive the DB.
const std = @import("std");
const p = @import("console").protocol;
const f = p.subscription_feed;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const integer = util.integer;

pub fn read(owner: *Persistent, input: f.Request) !p.StorageResult {
    try f.validate(input);
    const base = @as(u64, input.node) << 40;
    const head = try watermark(owner, input);
    const through = @min(head, input.through orelse head);
    const after = input.after orelse @max(base, through -| f.recent_ids);
    if (after > through) return .{ .failed = .conflict };
    var page: f.Page = .{
        .kind = input.kind,
        .node = input.node,
        .head = head,
        .through = through,
        .next = after,
        .observed_at = owner.nowSeconds(),
        .producer_dropped = if (input.kind == .events and input.node == owner.node_id)
            owner.state.metrics.incidents_dropped.load(.monotonic)
        else
            null,
        .producer_boot = try p.Bytes(32).init(
            &std.fmt.bytesToHex(owner.console_node.boot, .lower),
        ),
        .replica_observed_at = owner.console_node.storage.observed_at,
        .replica_quorum = owner.console_node.storage.quorum,
    };
    var rows = try db.query(owner.db, owner.gpa, switch (input.kind) {
        .events => "SELECT i.id,node_id,recorded_at,client_ip,method,path,violation_category," ++
            "e.version,e.query_bytes FROM security_incidents i LEFT JOIN " ++
            "console_incident_evidence e ON e.incident_id=i.id " ++
            "WHERE i.id>? AND i.id<=? ORDER BY i.id LIMIT 9",
        .audit => "SELECT id,actor,subject,recorded_at,action,target,actor_role " ++
            "FROM console_audit WHERE id>? AND id<=? ORDER BY id LIMIT 9",
    }, &.{ integer(after), integer(through) });
    defer rows.deinit();
    for (rows.rows[0..@min(f.page_rows, rows.rows.len)]) |cells| {
        const id = try util.number(cells[0]);
        page.missing_ids += id - page.next - 1;
        page.rows[page.count] = switch (input.kind) {
            .events => .{ .events = try event(cells) },
            .audit => audit: {
                var row: p.audit.Row = .{};
                try @import("console_store_audit.zig").decode(cells, &row);
                break :audit .{ .audit = row };
            },
        };
        page.count += 1;
        page.next = id;
    }
    page.more = rows.rows.len > f.page_rows;
    if (!page.more) {
        page.missing_ids += through - page.next;
        page.next = through;
    }
    return .{ .subscription_page = page };
}

fn watermark(owner: *Persistent, input: f.Request) !u64 {
    const base = @as(u64, input.node) << 40;
    var key: [48]u8 = undefined;
    const receipt = if (input.kind == .audit) "console_audit_cursor" else try std.fmt.bufPrint(
        &key,
        "incident_cursor_{d}",
        .{input.node},
    );
    var rows = try db.query(owner.db, owner.gpa, switch (input.kind) {
        .events => "SELECT COALESCE(MAX(id),?),COALESCE((SELECT CAST(value AS INTEGER) " ++
            "FROM sibuna_meta WHERE key=?),1) FROM security_incidents WHERE id>? AND id<=?",
        .audit => "SELECT COALESCE(MAX(id),?),COALESCE((SELECT CAST(value AS INTEGER) " ++
            "FROM sibuna_meta WHERE key=?),0) FROM console_audit WHERE id>? AND id<=?",
    }, &.{
        integer(base),
        util.text(receipt),
        integer(base),
        integer(if (input.kind == .audit) std.math.maxInt(i64) else base + (1 << 40) - 1),
    });
    defer rows.deinit();
    const saved = try util.number(rows.rows[0][1]);
    if (input.kind == .events and (saved == 0 or saved > (1 << 40)))
        return error.InvalidStoredValue;
    const durable = if (input.kind == .audit) saved else base + saved - 1;
    return @max(durable, try util.number(rows.rows[0][0]));
}

fn event(cells: []const ?[]const u8) !f.Event {
    const copy = @import("console_store_events.zig").copy;
    var result: f.Event = .{
        .id = try util.number(cells[0]),
        .node = std.math.cast(u32, try util.number(cells[1])) orelse
            return error.InvalidStoredValue,
        .time = try util.number(cells[2]),
    };
    if (result.id >> 40 != result.node) return error.InvalidStoredValue;
    copy(48, &result.ip, cells[3] orelse "", &result.display_truncated);
    copy(8, &result.method, cells[4] orelse "", &result.display_truncated);
    const path = cells[5] orelse "";
    const end = std.mem.indexOfAny(u8, path, "?#") orelse path.len;
    result.query_redacted = end != path.len;
    if (cells[7] != null and try util.number(cells[7]) == 1)
        result.query_redacted = result.query_redacted or try util.number(cells[8]) != 0;
    copy(128, &result.path, path[0..end], &result.display_truncated);
    copy(32, &result.category, cells[6] orelse "", &result.display_truncated);
    return result;
}
