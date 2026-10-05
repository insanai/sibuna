//! One authorized incident detail; pages and subscriptions retain their small scalar rows.
const std = @import("std");
const p = @import("root.zig");
pub const api = @import("security-evidence").detail;
pub const Read = p.incident_heads.Read;
pub const Response = struct {
    id: u64,
    detail: ?api.Detail = null,

    pub fn jsonStringify(self: Response, json: *std.json.Stringify) !void {
        try json.beginObject();
        try json.objectField("id");
        try p.writeCounter(json, self.id);
        try json.objectField("detail");
        try json.write(self.detail);
        try json.endObject();
    }
};
pub const Wire = struct { id: u64, detail: ?api.Wire };
