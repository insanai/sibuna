//! Route console management workflows without coupling their page state.
const std = @import("std");
const State = @import("state.zig").State;
const Outbox = @import("transport.zig").Outbox;
const users = @import("users_controller.zig");
const tokens = @import("tokens_controller.zig");
const nodes = @import("nodes_controller.zig");
const audit = @import("audit_controller.zig");
const settings = @import("settings_controller.zig");
const pages = @import("pages_controller.zig");
const reputation = @import("reputation_controller.zig");
const security = @import("security_overview_controller.zig");
const kiosk = @import("kiosk_grant.zig");

pub fn action(state: *State, name: []const u8, fields: std.json.Value, out: Outbox) !bool {
    if (try security.action(state, name, fields, out))
        return true;
    if (try kiosk.action(state, name, fields, out)) return true;
    if (try users.action(state, name, fields, out)) return true;
    if (try tokens.action(state, name, fields, out)) return true;
    if (try audit.action(state, name, fields, out)) return true;
    if (try settings.action(state, name, fields, out)) return true;
    if (try pages.action(state, name, fields, out)) return true;
    if (try reputation.action(state, name, fields, out)) return true;
    return nodes.action(state, name, out);
}

pub fn response(
    state: *State,
    id: []const u8,
    status: i64,
    body: std.json.Value,
    alloc: std.mem.Allocator,
    out: Outbox,
) !bool {
    if (std.mem.startsWith(u8, id, "security-view-")) {
        try security.response(state, id, status, body, alloc, out);
    } else if (std.mem.startsWith(u8, id, "kiosk-grant-")) {
        try kiosk.response(state, id, status, body, alloc, out);
    } else if (std.mem.startsWith(u8, id, "nodes-")) {
        try nodes.response(state, id, status, body, alloc, out);
    } else if (std.mem.startsWith(u8, id, "tokens-")) {
        try tokens.response(state, id, status, body, alloc, out);
    } else if (std.mem.startsWith(u8, id, "users-")) {
        try users.response(state, id, status, body, alloc, out);
    } else if (std.mem.startsWith(u8, id, "audit-")) {
        try audit.response(state, id, status, body, alloc, out);
    } else if (std.mem.startsWith(u8, id, "settings-")) {
        try settings.response(state, id, status, body, alloc, out);
    } else if (std.mem.startsWith(u8, id, "pages-")) {
        try pages.response(state, id, status, body, out);
    } else if (std.mem.startsWith(u8, id, "reputation-")) {
        try reputation.response(state, id, status, body, out);
    } else return false;
    return true;
}
