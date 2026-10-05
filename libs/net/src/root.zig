//! Sibuna Net Library
//!
//! Zero-copy HTTP/1.1 request parsing, response builders, and the
//! streaming reverse proxy with audit-header injection.

const std = @import("std");
const core = @import("core");

pub const http = @import("http.zig");
pub const chunked = @import("chunked.zig");
pub const content_coding = @import("content_coding.zig");
pub const entity = @import("entity.zig");
pub const retained_head = @import("retained_head.zig");
pub const response_fields = @import("response_fields.zig");
pub const response_inspection = @import("response_inspection.zig");
pub const response = @import("response.zig");
pub const proxy = @import("proxy.zig");
pub const outbound = @import("outbound.zig");
pub const connect = @import("connect.zig");
pub const fetch = @import("fetch.zig");
pub const refusal = @import("refusal.zig");
pub const duplex = @import("duplex.zig");
pub const forwarded = @import("forwarded.zig");
pub const interrupt = @import("socket").interrupt;
pub const stack = @import("socket").stack;
pub const socket_system = @import("socket_system.zig").system;

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
    _ = entity;
    _ = retained_head;
    _ = content_coding;
    _ = response_fields;
    _ = @import("response.zig");
    _ = @import("proxy.zig");
    _ = @import("connect.zig");
    _ = fetch;
    _ = @import("outbound.zig");
    _ = @import("duplex.zig");
    _ = @import("proxy_upgrade.zig");
    _ = @import("forwarded.zig");
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 8080);
    try std.testing.expectEqual(@as(u16, 8080), addr.ip4.port);
}
