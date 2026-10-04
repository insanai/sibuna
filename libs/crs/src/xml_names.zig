//! XML 1.0 fifth-edition names and namespace-qualified names. Byte offsets borrow
//! the immutable entity; character validity is independent of the CRS UTF-8 quirk.
const std = @import("std");
pub const Error = error{InvalidXml};
pub const Name = struct { prefix: []const u8, local: []const u8 };

pub fn read(input: []const u8, cursor: *usize) Error![]const u8 {
    const start = cursor.*;
    while (cursor.* < input.len) {
        const length = std.unicode.utf8ByteSequenceLength(input[cursor.*]) catch
            return error.InvalidXml;
        if (length > input.len - cursor.*) return error.InvalidXml;
        const point = std.unicode.utf8Decode(input[cursor.*..][0..length]) catch
            return error.InvalidXml;
        if (!nameCharacter(point, cursor.* == start)) break;
        cursor.* += length;
    }
    if (cursor.* == start) return error.InvalidXml;
    const bytes = input[start..cursor.*];
    _ = try split(bytes);
    return bytes;
}

pub fn split(input: []const u8) Error!Name {
    const colon = std.mem.indexOfScalar(u8, input, ':') orelse
        return .{ .prefix = "", .local = input };
    if (colon == 0 or colon + 1 == input.len or
        std.mem.indexOfScalar(u8, input[colon + 1 ..], ':') != null) return error.InvalidXml;
    const local = input[colon + 1 ..];
    const length = std.unicode.utf8ByteSequenceLength(local[0]) catch return error.InvalidXml;
    if (length > local.len) return error.InvalidXml;
    const point = std.unicode.utf8Decode(local[0..length]) catch return error.InvalidXml;
    if (!nameCharacter(point, true)) return error.InvalidXml;
    return .{ .prefix = input[0..colon], .local = local };
}

fn nameCharacter(point: u21, first: bool) bool {
    if (point == ':' or point == '_' or (point >= 'A' and point <= 'Z') or
        (point >= 'a' and point <= 'z')) return true;
    if ((point >= 0xc0 and point <= 0xd6) or (point >= 0xd8 and point <= 0xf6) or
        (point >= 0xf8 and point <= 0x2ff) or (point >= 0x370 and point <= 0x37d) or
        (point >= 0x37f and point <= 0x1fff) or (point >= 0x200c and point <= 0x200d) or
        (point >= 0x2070 and point <= 0x218f) or (point >= 0x2c00 and point <= 0x2fef) or
        (point >= 0x3001 and point <= 0xd7ff) or (point >= 0xf900 and point <= 0xfdcf) or
        (point >= 0xfdf0 and point <= 0xfffd) or (point >= 0x10000 and point <= 0xeffff))
    {
        return true;
    }
    return !first and (point == '-' or point == '.' or (point >= '0' and point <= '9') or
        point == 0xb7 or (point >= 0x300 and point <= 0x36f) or
        (point >= 0x203f and point <= 0x2040));
}

test "XML names accept Unicode and reject malformed namespace qualification" {
    for ([_][]const u8{ "root", "ns:root", "é-1", "名", "_x" }) |name| {
        var cursor: usize = 0;
        try std.testing.expectEqualStrings(name, try read(name, &cursor));
        try std.testing.expectEqual(name.len, cursor);
    }
    for ([_][]const u8{ ":root", "root:", "a:b:c", "a:1root", "1root", "\xff" }) |invalid| {
        var cursor: usize = 0;
        try std.testing.expectError(error.InvalidXml, read(invalid, &cursor));
    }
}
