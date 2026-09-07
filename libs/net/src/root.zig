//! Sibuna Net Library
//!
//! Provides zero-copy HTTP/1.1 and HTTP/2 request/response parsing,
//! streaming reverse proxying, and subrequest forward-auth handlers.

const std = @import("std");
const core = @import("core");

pub const HttpStatus = enum(u16) {
    ok = 200,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    internal_error = 500,
    bad_gateway = 502,
};
