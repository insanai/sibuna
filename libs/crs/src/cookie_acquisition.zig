//! CRS cookie collections preserve occurrences and bytes. Proof/session cookie
//! interpretation remains separate; this parser does not authenticate a cookie.
const std = @import("std");
const values = @import("acquired_values.zig");
const work = @import("work.zig");

pub fn parse(
    input: []const u8,
    builder: *values.Builder,
    budget: *work.Budget,
) values.Error!void {
    errdefer builder.poison();
    try budget.debitLinear(input.len, 2, 1);
    // Match the pinned connector: trim the string's final whitespace and each
    // key's leading whitespace, preserving interior value and key whitespace.
    const text = std.mem.trimEnd(u8, input, " \t\r\n\x0b\x0c");
    var pairs = std.mem.splitScalar(u8, text, ';');
    while (pairs.next()) |pair| {
        const equal = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
        const key = std.mem.trimStart(u8, pair[0..equal], " \t\r\n\x0b\x0c");
        if (key.len == 0) continue;
        const value = if (equal == pair.len) "" else pair[equal + 1 ..];
        try builder.named(.request_cookies, .request_cookies_names, .{
            .key = key,
            .value = value,
        }, budget);
    }
}
