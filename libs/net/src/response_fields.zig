//! Bounded borrowed fields from an already validated response head. The caller
//! copies required metadata before the origin reader can refill its buffer.
const std = @import("std");
const http = @import("http.zig");
pub const Header = @import("text").http_fields.Header;
pub const Error = error{ ResponseFieldLimit, MalformedResponseFields };

pub fn parse(head: []const u8, output: []Header) Error![]Header {
    if (head.len > 16 * 1024 or !std.mem.endsWith(u8, head, "\r\n\r\n"))
        return error.MalformedResponseFields;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.first();
    var used: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        if (used == output.len or used == 128) return error.ResponseFieldLimit;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse
            return error.MalformedResponseFields;
        if (!http.validToken(line[0..colon])) return error.MalformedResponseFields;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        for (value) |byte| if ((byte < 32 and byte != '\t') or byte == 127)
            return error.MalformedResponseFields;
        output[used] = .{ .name = line[0..colon], .value = value };
        used += 1;
    }
    return output[0..used];
}

test "response fields preserve duplicates and refuse capacity or malformed heads" {
    const t = std.testing;
    var headers: [2]Header = undefined;
    const raw = "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n";
    const fields = try parse(raw, &headers);
    try t.expectEqualStrings("a=1", fields[0].value);
    try t.expectEqualStrings("b=2", fields[1].value);
    try t.expectError(error.ResponseFieldLimit, parse(raw, headers[0..1]));
    const malformed = [_][]const u8{
        "HTTP/1.1 200 OK\r\nX: y\r\n",      "HTTP/1.1 200 OK\r\n X: y\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX : y\r\n\r\n", "HTTP/1.1 200 OK\r\nX: \x01\r\n\r\n",
    };
    for (malformed) |head| try t.expectError(error.MalformedResponseFields, parse(head, &headers));
}
