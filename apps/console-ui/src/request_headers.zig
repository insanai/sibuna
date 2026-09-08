//! Header views borrow the form's owned text only until its request is serialized.
const std = @import("std");
pub const Header = struct { name: []const u8, value: []const u8 };
pub const Error = error{InvalidHeaders};

pub fn parse(source: []const u8, output: *[8]Header) Error![]const Header {
    if (source.len > 2048) return error.InvalidHeaders;
    var lines = std.mem.splitScalar(u8, source, '\n');
    var count: usize = 0;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (count == output.len) return error.InvalidHeaders;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeaders;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (name.len == 0 or name.len > 64 or value.len > 256) return error.InvalidHeaders;
        for (name) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and
                std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", byte) == null)
                return error.InvalidHeaders;
        }
        for (value) |byte| if (byte < 32 or byte == 127) return error.InvalidHeaders;
        if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidHeaders;
        for (output[0..count]) |previous| {
            if (std.ascii.eqlIgnoreCase(previous.name, name)) return error.InvalidHeaders;
        }
        output[count] = .{ .name = name, .value = value };
        count += 1;
    }
    return output[0..count];
}

test "request headers preserve values and reject ambiguous or excessive input" {
    const t = std.testing;
    var output: [8]Header = undefined;
    const headers = try parse("X-Review: match\r\nOrigin: https://example.test\n", &output);
    try t.expectEqual(@as(usize, 2), headers.len);
    try t.expectEqualStrings("https://example.test", headers[1].value);
    for ([_][]const u8{
        "bad name: value",
        "missing colon",
        "a: 1\nA: 2",
        "a: x\rvalue",
        "a: \xff",
        "a:1\nb:2\nc:3\nd:4\ne:5\nf:6\ng:7\nh:8\ni:9",
    }) |source| try t.expectError(error.InvalidHeaders, parse(source, &output));
    try t.expectEqual(@as(usize, 0), (try parse("\n", &output)).len);
}
