//! Storage owns the prepared query and delivers an owned, freshly authorized payload.
const std = @import("std");
const p = @import("console").protocol;
const access = @import("console_read_authorize.zig");
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const wire = p.incident_crs;

pub fn read(owner: *Persistent, input: wire.Read) !p.StorageResult {
    if (input.id == 0 or input.id > std.math.maxInt(i64)) return .{ .failed = .invalid_input };
    if (try access.check(owner, input.session_digest, input.require_totp, .events_read)) |reason|
        return .{ .failed = reason };
    const sql = "SELECT detail,rule_id,phase FROM console_crs_evidence WHERE incident_id=?";
    var rows = try db.query(owner.db, owner.gpa, sql, &.{util.integer(input.id)});
    defer rows.deinit();
    const payload = try owner.gpa.create(wire.Response);
    errdefer owner.gpa.destroy(payload);
    payload.* = .{ .id = input.id };
    if (rows.rows.len != 0) {
        const row = rows.rows[0];
        if (row[0]) |json| {
            if (json.len > wire.api.max_json) return error.InvalidStoredValue;
            const parsed = try std.json.parseFromSlice(wire.api.Wire, owner.gpa, json, .{});
            defer parsed.deinit();
            var detail: wire.api.Detail = undefined;
            try parsed.value.into(&detail);
            if (detail.rule_id != try util.number(row[1]) or
                detail.phase != try util.number(row[2])) return error.InvalidStoredValue;
            payload.detail = detail;
        }
    }
    if (try access.check(owner, input.session_digest, input.require_totp, .events_read)) |reason| {
        owner.gpa.destroy(payload);
        return .{ .failed = reason };
    }
    return .{ .incident_crs = payload };
}
