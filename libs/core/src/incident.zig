pub const Incident = struct {
    client_ip: []const u8,
    user_agent: []const u8,
    method: []const u8,
    path: []const u8,
    category: []const u8,
    payload: []const u8,
    now: u64,
};
