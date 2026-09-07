//! Sibuna Net Library
//!
//! Provides zero-copy HTTP/1.1 and HTTP/2 request/response parsing,
//! streaming reverse proxying, and subrequest forward-auth handlers.

const std = @import("std");
const core = @import("core");

pub const http = @import("http.zig");
pub const response = @import("response.zig");
pub const proxy = @import("proxy.zig");

pub const Method = http.Method;
pub const Header = http.Header;
pub const Request = http.Request;
pub const MAX_HEADERS = http.MAX_HEADERS;
pub const parseRequest = http.parseRequest;
pub const streamProxy = proxy.streamProxy;

pub const HttpStatus = enum(u16) {
    ok = 200,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    internal_error = 500,
    bad_gateway = 502,
};

test {
    _ = @import("http.zig");
    _ = @import("response.zig");
    _ = @import("proxy.zig");
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 8080);
    try std.testing.expectEqual(@as(u16, 8080), addr.ip4.port);
}
