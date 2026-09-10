//! Strict matcher compilation shared by managed documents and stored policy materialization.
//! Header slices borrow the caller's parsed input; its arena must outlive the candidate engine.
//! Call with empty matcher fields and discard the candidate on error.
const std = @import("std");
const rule = @import("rule.zig");
pub const Error = error{ InvalidHeader, InvalidCidr, TooManyHeaders, TooManyCidrs };

pub fn validText(value: []const u8) bool {
    if (!std.unicode.utf8ValidateSlice(value)) return false;
    for (value) |byte| if (byte < 32 or byte == 127) return false;
    return true;
}

pub fn headers(value: std.json.Value, output: *rule.PolicyRule) Error!void {
    std.debug.assert(output.header_count == 0);
    if (value == .null) return;
    if (value != .object) return error.InvalidHeader;
    if (value.object.count() > rule.MAX_RULE_HEADERS) return error.TooManyHeaders;
    var iterator = value.object.iterator();
    while (iterator.next()) |entry| {
        const name = entry.key_ptr.*;
        if (name.len == 0 or name.len > 64 or entry.value_ptr.* != .string)
            return error.InvalidHeader;
        for (name) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and
                std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", byte) == null)
                return error.InvalidHeader;
        }
        const pattern = entry.value_ptr.*.string;
        if (pattern.len > 256 or !validText(pattern)) return error.InvalidHeader;
        for (output.headers[0..output.header_count]) |previous| {
            if (std.ascii.eqlIgnoreCase(previous.name, name)) return error.InvalidHeader;
        }
        output.headers[output.header_count] = .{ .name = name, .pattern = pattern };
        output.header_count += 1;
    }
}

pub fn cidrs(values: []const []const u8, output: *rule.PolicyRule) Error!void {
    std.debug.assert(output.cidr_count == 0);
    if (values.len > rule.MAX_RULE_CIDRS) return error.TooManyCidrs;
    for (values, 0..) |cidr, i| {
        if (cidr.len > 48) return error.InvalidCidr;
        output.cidrs[i] = rule.CidrMatcher.parse(cidr) orelse return error.InvalidCidr;
    }
    output.cidr_count = @intCast(values.len);
}
