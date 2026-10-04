//! Pure HTTP metadata acquisition. The transport supplies validated, length-aware
//! fields and an already resolved client address; no proxy trust is decided here.
const std = @import("std");
const http = @import("text").http_fields;
const values = @import("acquired_values.zig");
const variables = @import("variables.zig");
const form = @import("form_acquisition.zig");
const decode = @import("percent_decode.zig");
const cookies = @import("cookie_acquisition.zig");
const work = @import("work.zig");
const decimal = @import("decimal_format.zig");
pub const Error = form.Error || error{ InvalidHttpMetadata, AmbiguousContentType };
pub const Request = struct {
    method: []const u8,
    target: []const u8,
    protocol: []const u8,
    line: []const u8,
    client: []const u8,
    id: []const u8,
    headers: []const http.Header,
};
pub const Response = struct { status: u16, headers: []const http.Header };

pub fn response(
    input: Response,
    builder: *values.Builder,
    budget: *work.Budget,
) Error!void {
    errdefer builder.poison();
    if (input.status < 100 or input.status > 999) return error.InvalidHttpMetadata;
    var digits: [decimal.capacity(u16)]u8 = undefined;
    try builder.scalar(.response_status, try decimal.write(
        u16,
        input.status,
        &digits,
        budget,
    ), budget);
    for (input.headers) |header| {
        if (header.name.len == 0) return error.InvalidHttpMetadata;
        try builder.named(.response_headers, .response_headers_names, .{
            .key = header.name,
            .value = header.value,
        }, budget);
    }
    try builder.complete(&.{ .response_status, .response_headers, .response_headers_names });
}

pub fn request(
    input: Request,
    builder: *values.Builder,
    scratch: form.Scratch,
    budget: *work.Budget,
) Error!void {
    errdefer builder.poison();
    if (input.method.len == 0 or input.target.len == 0 or input.protocol.len == 0 or
        input.line.len == 0 or input.client.len == 0 or input.id.len == 0)
        return error.InvalidHttpMetadata;
    const scalars = [_]struct { variables.Collection, []const u8 }{
        .{ .request_method, input.method },
        .{ .request_protocol, input.protocol },
        .{ .request_line, input.line },
        .{ .remote_addr, input.client },
        .{ .unique_id, input.id },
    };
    for (scalars) |scalar| {
        try builder.scalar(scalar[0], scalar[1], budget);
        try builder.complete(&.{scalar[0]});
    }
    try uri(input.target, builder, scratch, budget);
    try headers(input.headers, builder, budget);
    // Phase one exposes query arguments. Body arguments replace this empty
    // contribution after complete acquisition, before phase two can evaluate it.
    try builder.complete(&.{
        .args,            .args_names,            .args_post,       .args_post_names,
        .request_headers, .request_headers_names, .request_cookies, .request_cookies_names,
    });
}

fn uri(
    target: []const u8,
    builder: *values.Builder,
    scratch: form.Scratch,
    budget: *work.Budget,
) Error!void {
    try budget.debitLinear(target.len, 3, 1);
    const fragment = std.mem.indexOfScalar(u8, target, '#') orelse target.len;
    const meaningful = target[0..fragment];
    const parts = http.splitTarget(meaningful);
    const path = try decode.decode(parts.path, scratch.key, false, budget);
    const decoded = try decode.decode(meaningful, scratch.value, false, budget);
    try builder.scalar(.request_uri_raw, target, budget);
    try builder.scalar(.request_uri, withoutAuthority(decoded), budget);
    try builder.scalar(.request_filename, path, budget);
    const last = std.mem.lastIndexOfAny(u8, path, "/\\");
    const basename = if (last) |index| path[index + 1 ..] else "";
    try builder.scalar(.request_basename, basename, budget);
    try builder.scalar(.query_string, parts.query, budget);
    try builder.complete(&.{
        .request_uri_raw, .request_uri, .request_filename, .request_basename, .query_string,
    });
    // Query parsing reuses the URI scratch only after every metadata copy finishes.
    try form.parse(parts.query, .query, builder, scratch, budget);
}

fn withoutAuthority(decoded: []const u8) []const u8 {
    if (decoded.len == 0 or decoded[0] == '/') return decoded;
    const colon = std.mem.indexOfScalar(u8, decoded, ':') orelse return decoded;
    const tail = decoded[colon + 1 ..];
    if (!std.mem.startsWith(u8, tail, "//")) return decoded;
    const slash = std.mem.indexOfScalar(u8, tail[2..], '/') orelse return decoded;
    return tail[2 + slash ..];
}

fn headers(
    input: []const http.Header,
    builder: *values.Builder,
    budget: *work.Budget,
) Error!void {
    var content_type: ?[]const u8 = null;
    for (input) |header| {
        try budget.debitLinear(header.name.len, 2, 1);
        if (header.name.len == 0) return error.InvalidHttpMetadata;
        try builder.named(.request_headers, .request_headers_names, .{
            .key = header.name,
            .value = header.value,
        }, budget);
        if (std.ascii.eqlIgnoreCase(header.name, "cookie"))
            try cookies.parse(header.value, builder, budget);
        if (std.ascii.eqlIgnoreCase(header.name, "content-type")) {
            if (content_type != null) return error.AmbiguousContentType;
            content_type = header.value;
        }
    }
    const processor = initialProcessor(content_type orelse "");
    try builder.scalar(.reqbody_processor, processor, budget);
    try builder.complete(&.{.reqbody_processor});
}

/// The reference selects form processors from the media prefix before phase one.
/// Strict MIME validation and any ctl override happen before consuming the entity.
fn initialProcessor(content_type: []const u8) []const u8 {
    if (std.ascii.startsWithIgnoreCase(content_type, "multipart/form-data"))
        return "MULTIPART";
    if (std.ascii.startsWithIgnoreCase(content_type, "application/x-www-form-urlencoded"))
        return "URLENCODED";
    return "";
}

test {
    _ = @import("http_acquisition_test.zig");
}
