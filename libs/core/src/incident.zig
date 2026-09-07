pub const Incident = struct {
    client_ip: []const u8,
    user_agent: []const u8,
    method: []const u8,
    path: []const u8,
    category: []const u8,
    payload: []const u8,
    now: u64,
    evidence: Evidence = .{},
};

/// Metadata for explicitly captured evidence. Version zero means historical/unrecorded.
/// No headers, cookie values, query values or request body bytes belong in this envelope.
pub const Evidence = struct {
    version: u8 = 0,
    selected_status: u16 = 0,
    query_bytes: u32 = 0,
    body_bytes: u32 = 0,
    declared_body_bytes: u32 = 0,
    // Bits: IP, User-Agent, method, path, category, forensic payload, incomplete body,
    // then saturated byte lengths. These describe capture, not later display shortening.
    truncated: u16 = 0,
};
