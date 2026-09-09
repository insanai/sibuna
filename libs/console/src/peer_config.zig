//! Explicit management destinations; replicated URLs never become outbound targets.
const std = @import("std");
const p = @import("console_protocol");
pub const max_peers = 8;
pub const Error = error{
    InvalidPeer,
    DuplicatePeer,
    PeerKeyRequired,
    PeerIngressRequired,
    InvalidPeerOrigin,
};
pub const Target = struct { node: u32 = 0, origin: p.Bytes(255) = .{} };
pub const Origin = struct { host: []const u8, port: u16 };
pub const Config = struct {
    targets: [max_peers]Target = @splat(.{}),
    count: u8 = 0,
    key_file: p.Bytes(1024) = .{},
    /// Optional PEM trust anchors for private management PKI; hostname checks still apply.
    ca_file: p.Bytes(1024) = .{},

    pub fn validate(self: *const Config, node: u32, behind_proxy: bool) Error!void {
        if (self.count > max_peers) return error.InvalidPeer;
        if (self.count == 0) {
            if (self.key_file.len != 0 or self.ca_file.len != 0) return error.InvalidPeer;
            return;
        }
        if (self.key_file.len == 0) return error.PeerKeyRequired;
        if (!behind_proxy) return error.PeerIngressRequired;
        for (self.targets[0..self.count], 0..) |target, index| {
            if (target.node == 0 or target.node >= 1 << 23 or target.node == node)
                return error.InvalidPeer;
            _ = try parseOrigin(target.origin.slice());
            for (self.targets[0..index]) |previous| {
                if (previous.node == target.node or
                    std.mem.eql(u8, previous.origin.slice(), target.origin.slice()))
                    return error.DuplicatePeer;
            }
        }
    }

    pub fn contains(self: *const Config, node: u32) bool {
        for (self.targets[0..self.count]) |target| if (target.node == node) return true;
        return false;
    }
};

pub fn parseOrigin(origin: []const u8) Error!Origin {
    if (origin.len > 255 or !std.mem.startsWith(u8, origin, "https://"))
        return error.InvalidPeerOrigin;
    const authority = origin[8..];
    if (authority.len == 0) return error.InvalidPeerOrigin;
    for (authority) |byte| {
        if (byte <= 32 or byte >= 127 or std.mem.indexOfScalar(u8, "/?#@%\\", byte) != null)
            return error.InvalidPeerOrigin;
    }
    const uri = std.Uri.parse(origin) catch return error.InvalidPeerOrigin;
    const host = uri.host orelse return error.InvalidPeerOrigin;
    var raw = switch (host) {
        .raw => |raw| raw,
        .percent_encoded => |raw| raw,
    };
    if (raw.len > 2 and raw[0] == '[' and raw[raw.len - 1] == ']') raw = raw[1 .. raw.len - 1];
    if (raw.len == 0 or uri.port == 0) return error.InvalidPeerOrigin;
    return .{ .host = raw, .port = uri.port orelse 443 };
}

test "management peers require explicit HTTPS, membership and independent key provisioning" {
    const t = std.testing;
    var config: Config = .{};
    try config.validate(1, false);
    config.count = 1;
    config.targets[0] = .{ .node = 2, .origin = try p.Bytes(255).init("https://peer.test:9443") };
    try t.expectError(error.PeerKeyRequired, config.validate(1, true));
    try config.key_file.set("peer.key");
    try t.expectError(error.PeerIngressRequired, config.validate(1, false));
    try config.validate(1, true);
    try t.expectError(error.InvalidPeer, config.validate(2, true));
    config.targets[1] = config.targets[0];
    config.count = 2;
    try t.expectError(error.DuplicatePeer, config.validate(1, true));
    const ipv6 = try parseOrigin("https://[::1]:443");
    try t.expectEqualStrings("::1", ipv6.host);
    for ([_][]const u8{
        "http://127.0.0.1:443", "https://host/path", "https://user@host",   "https://host:0",
        "https://host?next=x",  "https://host/#x",   "https://host%0aevil", "https://",
    }) |value| try t.expectError(error.InvalidPeerOrigin, parseOrigin(value));
}
