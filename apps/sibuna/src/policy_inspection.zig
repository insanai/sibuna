//! Persistent owns the optional replicated override; file settings remain the fallback.
const std = @import("std");
const policy = @import("policy");
const Persistent = @import("persistent.zig").Persistent;
pub const table_sql = "CREATE TABLE IF NOT EXISTS policy_inspection(" ++
    "id INTEGER PRIMARY KEY CHECK(id=1)," ++
    "path_traversal TEXT NOT NULL CHECK(path_traversal IN ('disabled','audit','enforce'))," ++
    "sqli TEXT NOT NULL CHECK(sqli IN ('disabled','audit','enforce'))," ++
    "xss TEXT NOT NULL CHECK(xss IN ('disabled','audit','enforce'))," ++
    "rce TEXT NOT NULL CHECK(rce IN ('disabled','audit','enforce')))";

pub fn read(owner: *Persistent) !?policy.inspection.Modes {
    var result = try owner.db.query(
        owner.gpa,
        "SELECT path_traversal,sqli,xss,rce FROM policy_inspection WHERE id=1 LIMIT 1",
    );
    defer result.deinit();
    if (result.rows.len == 0) return null;
    var modes: policy.inspection.Modes = .{};
    inline for (@typeInfo(policy.inspection.Modes).@"struct".fields, 0..) |field, i| {
        const text = result.rows[0][i] orelse return error.InvalidInspectionMode;
        @field(modes, field.name) = std.meta.stringToEnum(policy.inspection.Mode, text) orelse
            return error.InvalidInspectionMode;
    }
    return modes;
}

pub fn apply(owner: *Persistent, engine: *policy.Engine) !void {
    if (try read(owner)) |modes| engine.inspection_modes = modes;
}
