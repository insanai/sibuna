//! Borrowed HTTP field shapes and request-target splitting. Pure text contracts;
//! transport framing, validation, origin trust and policy remain caller concerns.
const std = @import("std");
pub const Header = struct { name: []const u8, value: []const u8 };
pub const Target = struct { path: []const u8, query: []const u8 = "" };

/// Split on the first literal question mark. Percent-encoded delimiters remain
/// path bytes; decoding before splitting would change the protected request.
pub fn splitTarget(target: []const u8) Target {
    const mark = std.mem.indexOfScalar(u8, target, '?') orelse return .{ .path = target };
    return .{ .path = target[0..mark], .query = target[mark + 1 ..] };
}

test "target splitting preserves encoded separators, empty queries and binary slices" {
    const split = splitTarget("/a%3fb?q=x?y");
    try std.testing.expectEqualStrings("/a%3fb", split.path);
    try std.testing.expectEqualStrings("q=x?y", split.query);
    try std.testing.expectEqualStrings("", splitTarget("/path?").query);
    try std.testing.expectEqualStrings("/path", splitTarget("/path").path);
}

/// RFC 9110 tokens share one predicate across framing and representation parsing.
pub fn tokenChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", c) != null;
}

pub fn validToken(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |c| if (!tokenChar(c)) return false;
    return true;
}
