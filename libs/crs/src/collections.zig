//! Collections in the initial SecLang profile. Recognizing one does not populate it;
//! body processors and transaction state must separately establish its coverage.
const std = @import("std");

pub const Collection = enum {
    args,
    args_combined_size,
    args_get,
    args_get_names,
    args_names,
    args_post,
    args_post_names,
    files,
    files_combined_size,
    files_names,
    matched_var,
    matched_var_name,
    matched_vars,
    matched_vars_names,
    multipart_part_headers,
    query_string,
    remote_addr,
    reqbody_processor,
    request_basename,
    request_body,
    request_body_length,
    request_cookies,
    request_cookies_names,
    request_filename,
    request_headers,
    request_headers_names,
    request_line,
    request_method,
    request_protocol,
    request_uri,
    request_uri_raw,
    response_body,
    response_headers,
    response_headers_names,
    response_status,
    tx,
    unique_id,
    xml,

    pub fn keyed(self: Collection) bool {
        return switch (self) {
            .args_combined_size => false,
            .files_combined_size => false,
            .matched_var => false,
            .matched_var_name => false,
            .query_string => false,
            .remote_addr => false,
            .reqbody_processor => false,
            .request_basename => false,
            .request_body => false,
            .request_body_length => false,
            .request_filename => false,
            .request_line => false,
            .request_method => false,
            .request_protocol => false,
            .request_uri => false,
            .request_uri_raw => false,
            .response_body => false,
            .response_status => false,
            .unique_id => false,
            else => true,
        };
    }
};

/// Variable identifiers are ASCII case-insensitive; collection keys retain their bytes.
pub fn lookup(bytes: []const u8) ?Collection {
    var lower: [48]u8 = undefined;
    if (bytes.len > lower.len) return null;
    for (bytes, lower[0..bytes.len]) |byte, *out| out.* = std.ascii.toLower(byte);
    return names.get(lower[0..bytes.len]);
}

const names = blk: {
    const info = @typeInfo(Collection).@"enum";
    var entries: [info.field_names.len]struct { []const u8, Collection } = undefined;
    for (info.field_names, info.field_values, 0..) |name, value, index| {
        entries[index] = .{ name, @fromBackingInt(@intCast(value)) };
    }
    break :blk std.StaticStringMap(Collection).initComptime(entries);
};
