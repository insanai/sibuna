//! Strict UTF-8 XML lexical helpers. DTD/entity declarations are handled as
//! forbidden constructs by acquisition, not passed to a general XML library.
const std = @import("std");
const text = @import("xml_text.zig");
const names = @import("xml_names.zig");
const work = @import("work.zig");
pub const Error = text.Error || names.Error || error{UnsupportedXmlEncoding};
pub const Reader = struct {
    input: []const u8,
    cursor: usize = 0,

    pub fn init(input: []const u8, budget: *work.Budget) Error!Reader {
        const cost = std.math.mul(u64, input.len, 16) catch return error.WorkLimit;
        try budget.debit(std.math.add(u64, cost, 1) catch return error.WorkLimit);
        var cursor: usize = 0;
        while (cursor < input.len) {
            const length = std.unicode.utf8ByteSequenceLength(input[cursor]) catch
                return error.InvalidXml;
            if (length > input.len - cursor) return error.InvalidXml;
            const point = std.unicode.utf8Decode(input[cursor..][0..length]) catch
                return error.InvalidXml;
            if (!text.character(point)) return error.InvalidXml;
            cursor += length;
        }
        return .{
            .input = input,
            .cursor = if (std.mem.startsWith(u8, input, "\xef\xbb\xbf")) 3 else 0,
        };
    }

    pub fn take(self: *Reader, literal: []const u8) bool {
        if (!std.mem.startsWith(u8, self.input[self.cursor..], literal)) return false;
        self.cursor += literal.len;
        return true;
    }

    pub fn space(self: *Reader) bool {
        const before = self.cursor;
        while (self.cursor < self.input.len and whitespace(self.input[self.cursor]))
            self.cursor += 1;
        return before != self.cursor;
    }

    pub fn name(self: *Reader) Error![]const u8 {
        return names.read(self.input, &self.cursor);
    }

    pub fn quoted(self: *Reader) Error![]const u8 {
        if (self.cursor == self.input.len) return error.InvalidXml;
        const quote = self.input[self.cursor];
        if (quote != '\'' and quote != '"') return error.InvalidXml;
        self.cursor += 1;
        const remaining = self.input[self.cursor..];
        const end = std.mem.indexOfScalar(u8, remaining, quote) orelse return error.InvalidXml;
        self.cursor += end + 1;
        return remaining[0..end];
    }

    pub fn through(self: *Reader, delimiter: []const u8) Error![]const u8 {
        const remaining = self.input[self.cursor..];
        const end = std.mem.indexOf(u8, remaining, delimiter) orelse return error.InvalidXml;
        self.cursor += end + delimiter.len;
        return remaining[0..end];
    }
};

pub fn whitespace(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '\r' or byte == '\n';
}

/// XML declaration pseudo-attributes have a fixed order and are not ordinary
/// document attributes. Supporting UTF-8 avoids implicit transcoding or fetching.
pub fn declaration(reader: *Reader) Error!void {
    if (!reader.space() or !reader.take("version")) return error.InvalidXml;
    const version = try pseudo(reader);
    if (!std.mem.eql(u8, version, "1.0")) return error.UnsupportedXmlEncoding;
    var separated = reader.space();
    if (reader.take("encoding")) {
        if (!separated) return error.InvalidXml;
        const encoding = try pseudo(reader);
        if (!std.ascii.eqlIgnoreCase(encoding, "UTF-8")) return error.UnsupportedXmlEncoding;
        separated = reader.space();
    }
    if (reader.take("standalone")) {
        if (!separated) return error.InvalidXml;
        const standalone = try pseudo(reader);
        if (!std.mem.eql(u8, standalone, "yes") and !std.mem.eql(u8, standalone, "no"))
            return error.InvalidXml;
        _ = reader.space();
    }
    if (!reader.take("?>")) return error.InvalidXml;
}

fn pseudo(reader: *Reader) Error![]const u8 {
    _ = reader.space();
    if (!reader.take("=")) return error.InvalidXml;
    _ = reader.space();
    return reader.quoted();
}
