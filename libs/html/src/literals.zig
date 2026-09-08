//! Fixed-dictionary substitution for trusted HTML literals. No runtime allocation or parser.
//! NUL introduces a dictionary index; literal NUL falls back to the original bytes.
const std = @import("std");
const Writer = std.Io.Writer;
const dictionary = [_][]const u8{
    " type=\"checkbox\"", " type=\"button\"", " type=\"submit\"", " placeholder=\"",
    " data-action=\"",    " aria-label=\"",   " type=\"text\"",   "</textarea>",
    " tabindex=\"",       "</section>",       "</article>",       "<textarea",
    "</button>",          "</option>",        "</select>",        " class=\"",
    "<section",           "<article",         "</label>",         "<button",
    " name=\"",           "</span>",          "<option",          "<select",
    " value=\"",          "<label",           "</div>",           "<input",
    " id=\"",             "<span",            "<div",             "</p>",
};

pub fn write(w: *Writer, comptime source: []const u8) Writer.Error!void {
    @setEvalBranchQuota(10_000_000);
    if (comptime std.mem.indexOfScalar(u8, source, 0) != null) return raw(w, source);
    const size = comptime packedLength(source);
    if (comptime size >= source.len) return raw(w, source);
    const bytes = comptime pack(source, size);
    return unpack(w, &bytes);
}

fn raw(w: *Writer, comptime source: []const u8) Writer.Error!void {
    // Retain only this span. A pointer into the original embedded file would keep that
    // entire file alongside packed spans and defeat the size bound.
    const bytes = comptime source[0..source.len].*;
    return w.writeAll(&bytes);
}

fn match(source: []const u8) ?u8 {
    for (dictionary, 0..) |entry, i| {
        if (std.mem.startsWith(u8, source, entry)) return @intCast(i);
    }
    return null;
}

fn packedLength(source: []const u8) usize {
    var i: usize = 0;
    var length: usize = 0;
    while (i < source.len) {
        if (match(source[i..])) |index| {
            i += dictionary[index].len;
            length += 2;
        } else {
            i += 1;
            length += 1;
        }
    }
    return length;
}

fn pack(source: []const u8, comptime size: usize) [size]u8 {
    var result: [size]u8 = undefined;
    var i: usize = 0;
    var out: usize = 0;
    while (i < source.len) {
        if (match(source[i..])) |index| {
            result[out..][0..2].* = .{ 0, index };
            out += 2;
            i += dictionary[index].len;
        } else {
            result[out] = source[i];
            out += 1;
            i += 1;
        }
    }
    std.debug.assert(out == size);
    return result;
}

// Only compile-time pack() output reaches this decoder. Values are escaped elsewhere.
noinline fn unpack(w: *Writer, bytes: []const u8) Writer.Error!void {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, bytes, i, 0)) |marker| {
        try w.writeAll(bytes[i..marker]);
        std.debug.assert(marker + 1 < bytes.len);
        const index = bytes[marker + 1];
        std.debug.assert(index < dictionary.len);
        try w.writeAll(dictionary[index]);
        i = marker + 2;
    }
    try w.writeAll(bytes[i..]);
}

test "packed HTML preserves every byte, UTF-8 and overlapping dictionary prefixes" {
    const source = "<section class=\"panel\"><label><span>世界</span> " ++
        "<input type=\"checkbox\" name=\"choice\" value=\"one\"></label>" ++
        "<button type=\"submit\" data-action=\"save\">Save</button></section>\n";
    var buffer: [512]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try write(&writer, source);
    try std.testing.expectEqualStrings(source, writer.buffered());
    try std.testing.expect(packedLength(source) < source.len);
    writer = .fixed(&buffer);
    try write(&writer, "literal\x00byte");
    try std.testing.expectEqualStrings("literal\x00byte", writer.buffered());
    var small: [4]u8 = undefined;
    writer = .fixed(&small);
    try std.testing.expectError(error.WriteFailed, write(&writer, source));
}
