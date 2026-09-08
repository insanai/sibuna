//! Route account and automation workflows without coupling either page to its sibling.
const std = @import("std");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const users = @import("users_controller.zig");
const tokens = @import("tokens_controller.zig");

pub fn action(state: *State, name: []const u8, fields: std.json.Value, out: Outbox) !bool {
    if (try users.action(state, name, fields, out)) return true;
    return tokens.action(state, name, fields, out);
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    alloc: std.mem.Allocator,
    out: Outbox,
) !bool {
    if (std.mem.startsWith(u8, id, "tokens-")) {
        try tokens.response(state, id, status, body, alloc, out);
    } else if (std.mem.startsWith(u8, id, "users-")) {
        try users.response(state, id, status, body, alloc, out);
    } else return false;
    return true;
}
