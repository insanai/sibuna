//! Opt-in redacted heads ride in the incident's idempotent transaction and are read one
//! incident at a time into a heap payload, so event pages never grow with them.
const std = @import("std");
const console = @import("console");
const p = console.protocol;
const wire = p.incident_heads;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const access = @import("console_read_authorize.zig");
const Persistent = @import("persistent.zig").Persistent;

pub fn append(
    w: *std.Io.Writer,
    id: u64,
    request: []const u8,
    response: []const u8,
    request_truncated: bool,
    response_truncated: bool,
) !void {
    try w.print(
        "INSERT INTO console_incident_heads(incident_id,version,request_head,response_head," ++
            "request_truncated,response_truncated) SELECT {d},1,'{x}','{x}',{d},{d}",
        .{
            id,                               request,
            response,                         @intFromBool(request_truncated),
            @intFromBool(response_truncated),
        },
    );
}

pub fn read(owner: *Persistent, input: wire.Read) !p.StorageResult {
    if (input.id == 0 or input.id > std.math.maxInt(i64)) return .{ .failed = .invalid_input };
    if (try access.check(owner, input.session_digest, input.require_totp, .events_read)) |reason|
        return .{ .failed = reason };
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT request_head,response_head,request_truncated,response_truncated " ++
            "FROM console_incident_heads WHERE incident_id=? AND version=1",
        &.{util.integer(input.id)},
    );
    defer rows.deinit();
    const payload = try owner.gpa.create(wire.Heads);
    errdefer owner.gpa.destroy(payload);
    payload.* = .{ .id = input.id };
    if (rows.rows.len != 0) {
        const row = rows.rows[0];
        payload.recorded = true;
        payload.request = try p.Bytes(wire.request_hex).init(row[0] orelse "");
        payload.response = try p.Bytes(wire.response_hex).init(row[1] orelse "");
        payload.request_truncated = (try util.number(row[2])) != 0;
        payload.response_truncated = (try util.number(row[3])) != 0;
    }
    if (try access.check(owner, input.session_digest, input.require_totp, .events_read)) |reason| {
        owner.gpa.destroy(payload);
        return .{ .failed = reason };
    }
    return .{ .incident_heads = payload };
}
