//! Borrowed MIME values and parameters shared by bounded body inspection. No decoding,
//! allocation or networking; quoted delimiters never become parameter separators.
const std = @import("std");
pub const Error = error{InvalidMime};
pub const Parameter = struct { name: []const u8, value: []const u8 };
pub const Value = struct {
    media: []const u8,
    remaining: []const u8,

    pub fn init(text: []const u8) Error!Value {
        const end = std.mem.indexOfScalar(u8, text, ';') orelse text.len;
        const media = std.mem.trim(u8, text[0..end], " \t");
        if (media.len == 0) return error.InvalidMime;
        for (media) |byte| if (!token(byte) and byte != '/') return error.InvalidMime;
        return .{ .media = media, .remaining = text[end..] };
    }

    pub fn next(self: *Value) Error!?Parameter {
        var text = std.mem.trim(u8, self.remaining, " \t");
        if (text.len == 0) return null;
        if (text[0] != ';') return error.InvalidMime;
        text = std.mem.trimStart(u8, text[1..], " \t");
        var at: usize = 0;
        while (at < text.len and token(text[at])) : (at += 1) {}
        if (at == 0) return error.InvalidMime;
        const name = text[0..at];
        text = std.mem.trimStart(u8, text[at..], " \t");
        if (text.len < 2 or text[0] != '=') return error.InvalidMime;
        text = std.mem.trimStart(u8, text[1..], " \t");
        if (text.len == 0) return error.InvalidMime;
        const quoted = text[0] == '"';
        at = if (quoted) 1 else 0;
        while (at < text.len) : (at += 1) {
            const byte = text[at];
            if (quoted) {
                if (byte == '"') break;
                if (byte < 32 or byte == 127) return error.InvalidMime;
                if (byte == '\\') {
                    at += 1;
                    if (at == text.len or text[at] < 32 or text[at] == 127)
                        return error.InvalidMime;
                }
            } else if (!token(byte)) break;
        }
        if (quoted and at == text.len or !quoted and at == 0) return error.InvalidMime;
        const value = text[@intFromBool(quoted)..at];
        self.remaining = std.mem.trimStart(u8, text[at + @intFromBool(quoted) ..], " \t");
        if (self.remaining.len != 0 and self.remaining[0] != ';') return error.InvalidMime;
        return .{ .name = name, .value = value };
    }
};

pub fn token(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", byte) != null;
}

pub fn binary(media: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(media, "image/svg+xml")) return false;
    for ([_][]const u8{ "image/", "audio/", "video/" }) |prefix| {
        if (std.ascii.startsWithIgnoreCase(media, prefix) and media.len > prefix.len) return true;
    }
    for ([_][]const u8{
        "application/octet-stream",
        "application/pdf",
        "application/zip",
        "application/gzip",
        "application/x-protobuf",
        "application/protobuf",
        "application/x-7z-compressed",
    }) |kind| if (std.ascii.eqlIgnoreCase(media, kind)) return true;
    return false;
}

/// Value also parses Content-Disposition tokens; Content-Type requires type/subtype.
pub fn mediaType(media: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, media, '/') orelse return false;
    return slash > 0 and slash + 1 < media.len and
        std.mem.indexOfScalarPos(u8, media, slash + 1, '/') == null;
}

test "quoted MIME parameters keep semicolons and escapes inside their values" {
    const t = std.testing;
    var value = try Value.init("form-data; name=\"file\"; filename=\"a; b\\\".txt\"");
    try t.expectEqualStrings("file", (try value.next()).?.value);
    try t.expectEqualStrings("a; b\\\".txt", (try value.next()).?.value);
    try t.expect(try value.next() == null);
    value = try Value.init("form-data; name=\"unterminated");
    try t.expectError(error.InvalidMime, value.next());
    try t.expect(binary("application/octet-stream"));
    try t.expect(!binary("image/svg+xml"));
    try t.expect(!binary("application/json"));
    try t.expect(mediaType("image/png"));
    try t.expect(!mediaType("image/"));
    try t.expect(!mediaType("image/png/invalid"));
}
