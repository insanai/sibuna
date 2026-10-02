//! Sibuna Net Library
//!
//! Zero-copy HTTP/1.1 request parsing, response builders, and the
//! streaming reverse proxy with audit-header injection.

const std = @import("std");
const core = @import("core");

pub const http = @import("http.zig");
pub const chunked = @import("chunked.zig");
pub const response = @import("response.zig");
pub const proxy = @import("proxy.zig");
pub const outbound = @import("outbound.zig");
pub const connect = @import("connect.zig");
pub const duplex = @import("duplex.zig");
pub const forwarded = @import("forwarded.zig");

pub const Method = http.Method;
pub const Header = http.Header;
pub const Request = http.Request;
pub const MAX_HEADERS = http.MAX_HEADERS;
pub const parseRequest = http.parseRequest;
pub const streamProxy = proxy.streamProxy;

pub const Status = response.Status;
pub const ProxyAudit = proxy.Audit;

test {
    _ = @import("http.zig");
    _ = @import("chunked.zig");
    _ = @import("response.zig");
    _ = @import("proxy.zig");
    _ = @import("connect.zig");
    _ = @import("outbound.zig");
    _ = @import("duplex.zig");
    _ = @import("proxy_upgrade.zig");
    _ = @import("forwarded.zig");
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 8080);
    try std.testing.expectEqual(@as(u16, 8080), addr.ip4.port);
}
