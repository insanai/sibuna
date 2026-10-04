//! XML 1.0 character data and CDATA/attribute normalization. No general entities,
//! DTDs or external resources; character references are checked Unicode scalars.
const std = @import("std");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Error = work.Error || error{ InvalidXml, XmlTextLimit };
pub const Kind = enum { text, attribute, cdata };

pub fn decode(
    input: []const u8,
    output: []u8,
    kind: Kind,
    budget: *work.Budget,
) Error![]const u8 {
    const cost = std.math.mul(u64, input.len, 8) catch return error.WorkLimit;
    try budget.debit(std.math.add(u64, cost, 1) catch return error.WorkLimit);
    buffers.assertDisjoint(input, output);
    if (kind == .text and std.mem.indexOf(u8, input, "]]>") != null) return error.InvalidXml;
    var cursor: usize = 0;
    var used: usize = 0;
    while (cursor < input.len) {
        var point: u21 = undefined;
        var reference = false;
        if (input[cursor] == '&' and kind != .cdata) {
            const relative = std.mem.indexOfScalar(u8, input[cursor + 1 ..], ';') orelse
                return error.InvalidXml;
            point = try entity(input[cursor + 1 ..][0..relative]);
            cursor += relative + 2;
            reference = true;
        } else {
            const length = std.unicode.utf8ByteSequenceLength(input[cursor]) catch
                return error.InvalidXml;
            if (length > input.len - cursor) return error.InvalidXml;
            point = std.unicode.utf8Decode(input[cursor..][0..length]) catch
                return error.InvalidXml;
            cursor += length;
        }
        if (!character(point)) return error.InvalidXml;
        if (!reference) {
            if (point == '<' and kind != .cdata) return error.InvalidXml;
            if (point == '\r') {
                if (cursor < input.len and input[cursor] == '\n') cursor += 1;
                point = '\n';
            }
            if (kind == .attribute and (point == '\n' or point == '\t')) point = ' ';
        }
        var bytes: [4]u8 = undefined;
        const length = std.unicode.utf8Encode(point, &bytes) catch return error.InvalidXml;
        if (length > output.len - used) return error.XmlTextLimit;
        @memcpy(output[used..][0..length], bytes[0..length]);
        used += length;
    }
    return output[0..used];
}

pub fn character(point: u21) bool {
    return point == 9 or point == 10 or point == 13 or
        (point >= 0x20 and point <= 0xd7ff) or
        (point >= 0xe000 and point <= 0xfffd) or
        (point >= 0x10000 and point <= 0x10ffff);
}

fn entity(input: []const u8) Error!u21 {
    const predefined = std.StaticStringMap(u21).initComptime(.{
        .{ "amp", '&' }, .{ "lt", '<' }, .{ "gt", '>' }, .{ "apos", '\'' }, .{ "quot", '"' },
    });
    if (predefined.get(input)) |point| return point;
    if (input.len < 2 or input[0] != '#') return error.InvalidXml;
    const hex = input[1] == 'x';
    const digits = input[if (hex) @as(usize, 2) else 1..];
    if (digits.len == 0) return error.InvalidXml;
    const base: u32 = if (hex) 16 else 10;
    var point: u32 = 0;
    for (digits) |byte| {
        const value: u32 = switch (byte) {
            '0'...'9' => byte - '0',
            'a'...'f' => if (hex) byte - 'a' + 10 else return error.InvalidXml,
            'A'...'F' => if (hex) byte - 'A' + 10 else return error.InvalidXml,
            else => return error.InvalidXml,
        };
        point = std.math.mul(u32, point, base) catch return error.InvalidXml;
        point = std.math.add(u32, point, value) catch return error.InvalidXml;
        if (point > 0x10ffff) return error.InvalidXml;
    }
    if (!character(@intCast(point))) return error.InvalidXml;
    return @intCast(point);
}

test "XML normalization distinguishes character references from literal whitespace" {
    var budget: work.Budget = .{ .remaining = 10000 };
    var output: [128]u8 = undefined;
    try std.testing.expectEqualStrings("a  b\tc<é", try decode(
        "a\r\n\tb&#9;c&lt;&#xE9;",
        &output,
        .attribute,
        &budget,
    ));
    try std.testing.expectEqualStrings("a\nb\nc&<", try decode(
        "a\r\nb\rc&amp;&lt;",
        &output,
        .text,
        &budget,
    ));
    try std.testing.expectEqualStrings("&amp;\n<", try decode(
        "&amp;\r\n<",
        &output,
        .cdata,
        &budget,
    ));
    for ([_][]const u8{
        "&#0;", "&#xD800;", "&#x110000;", "&#xFFFF;", "&custom;", "&amp", "<", "a]]>b", "\xff",
    }) |invalid| try std.testing.expectError(
        error.InvalidXml,
        decode(invalid, &output, .text, &budget),
    );
}
