//! Dispatch-local browser commands. The composing state machine owns buffers and lifetime;
//! this serializer has no application state or browser capability implementation.
const std = @import("std");
pub const Outbox = struct {
    writer: *std.Io.Writer,
    count: *usize,
    csrf: []const u8,

    pub fn emit(self: Outbox, value: anytype) !void {
        if (self.count.* > 0) try self.writer.writeByte(',');
        var json: std.json.Stringify = .{ .writer = self.writer };
        try @import("json_fields.zig").write(&json, value);
        self.count.* += 1;
    }

    pub fn post(self: Outbox, id: []const u8, path: []const u8, body: anytype) !void {
        var json = try self.prefix(id, path);
        try @import("json_fields.zig").write(&json, body);
        try json.endObject();
        self.count.* += 1;
    }

    /// Share the envelope across typed bodies to bound generated Wasm code.
    pub noinline fn prefix(self: Outbox, id: []const u8, path: []const u8) !std.json.Stringify {
        if (self.count.* > 0) try self.writer.writeByte(',');
        var json: std.json.Stringify = .{ .writer = self.writer };
        try json.beginObject();
        const names = .{ "op", "method", "id", "path", "csrf" };
        const values = .{ "request", "POST", id, path, self.csrf };
        inline for (names, values) |name, value| {
            try json.objectField(name);
            try json.write(value);
        }
        try json.objectField("body");
        return json;
    }
};
