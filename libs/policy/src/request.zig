//! One borrowed request contract for policy evaluation and both inspection paths.
pub const View = struct {
    path: []const u8,
    query: []const u8 = "",
    client_ip: []const u8 = "",
    user_agent: []const u8 = "",
    headers: []const @import("rule.zig").Header = &.{},
    body: []const u8 = "",
};
