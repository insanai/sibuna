//! Dispatch-local browser dependencies and response data. No controller retains either value.
const std = @import("std");
pub const Context = struct {
    state: *@import("state.zig").State,
    out: @import("transport.zig").Outbox,
};
pub const Response = struct {
    id: []const u8,
    status: i64,
    body: std.json.Value,
    allocator: std.mem.Allocator,
};
