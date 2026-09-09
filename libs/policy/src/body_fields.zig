//! Select application text and upload metadata from a bounded body prefix. File payloads
//! stay opaque; this is not a malware scanner. The origin must enforce its declared MIME
//! types. Unknown/ambiguous formats fall back to text inspection, never silently skip it.
const std = @import("std");
const Header = @import("rule.zig").Header;
const mime = @import("mime.zig");
pub const max_prefix = 8 * 1024;
const max_part_headers = 2048;
const max_parts = 32;

pub const Fields = struct {
    body: []const u8,
    boundary: []const u8 = "",
    offset: usize = 0,
    parts: usize = 0,
    pending: ?[]const u8 = null,
    finished: bool = false,

    pub fn init(headers: []const Header, body: []const u8) Fields {
        var result: Fields = .{ .body = body[0..@min(body.len, max_prefix)] };
        const content_type = unique(headers, "content-type") catch return result;
        var value = mime.Value.init(content_type orelse return result) catch return result;
        if (!mime.mediaType(value.media)) return result;
        const multipart = std.ascii.eqlIgnoreCase(value.media, "multipart/form-data");
        var boundary: ?[]const u8 = null;
        while (value.next() catch return result) |parameter| {
            if (!std.ascii.eqlIgnoreCase(parameter.name, "boundary")) continue;
            if (boundary != null) return result;
            boundary = parameter.value;
        }
        if (!multipart) {
            result.finished = mime.binary(value.media);
            return result;
        }
        const delimiter = boundary orelse return result;
        if (!validBoundary(delimiter)) return result;
        if (!std.mem.startsWith(u8, result.body, "--")) return result;
        if (result.body.len < delimiter.len + 4 or
            !std.mem.eql(u8, result.body[2..][0..delimiter.len], delimiter) or
            !std.mem.eql(u8, result.body[2 + delimiter.len ..][0..2], "\r\n")) return result;
        result.boundary = delimiter;
        result.offset = delimiter.len + 4;
        return result;
    }

    pub fn next(self: *Fields) ?[]const u8 {
        if (self.pending) |text| {
            self.pending = null;
            return text;
        }
        if (self.finished) return null;
        if (self.boundary.len == 0 or self.parts == max_parts) return self.fallback();
        const remaining = self.body[self.offset..];
        const end = std.mem.indexOf(u8, remaining, "\r\n\r\n") orelse return self.fallback();
        if (end > max_part_headers) return self.fallback();
        const header = remaining[0..end];
        const file = filePart(header) catch return self.fallback();
        self.parts += 1;
        const start = self.offset + end + 4;
        const marker = self.findBoundary(start);
        const body_end = if (marker) |found| found.start else self.body.len;
        if (!file) self.pending = self.body[start..body_end];
        if (marker) |found| {
            self.offset = found.end;
            self.finished = found.closing;
        } else self.finished = true; // The inspection prefix can end inside a streamed part.
        return header; // Field names and filenames remain subject to ordinary WAF checks.
    }

    fn fallback(self: *Fields) []const u8 {
        self.finished = true;
        return self.body[self.offset..];
    }

    const Boundary = struct { start: usize, end: usize, closing: bool };
    fn findBoundary(self: *const Fields, start: usize) ?Boundary {
        var delimiter: [74]u8 = undefined;
        @memcpy(delimiter[0..4], "\r\n--");
        @memcpy(delimiter[4..][0..self.boundary.len], self.boundary);
        const text = delimiter[0 .. 4 + self.boundary.len];
        var position = start;
        while (std.mem.indexOfPos(u8, self.body, position, text)) |at| {
            const end = at + text.len;
            if (self.body.len - end < 2) return null;
            const suffix = self.body[end..][0..2];
            if (std.mem.eql(u8, suffix, "\r\n")) return .{
                .start = at,
                .end = end + 2,
                .closing = false,
            };
            if (std.mem.eql(u8, suffix, "--") and (end + 2 == self.body.len or
                std.mem.startsWith(u8, self.body[end + 2 ..], "\r\n"))) return .{
                .start = at,
                .end = end + 2,
                .closing = true,
            };
            position = at + 1; // A boundary prefix inside a file is still file data.
        }
        return null;
    }
};

fn validBoundary(text: []const u8) bool {
    if (text.len == 0 or text.len > 70 or text[text.len - 1] == ' ') return false;
    for (text) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            std.mem.indexOfScalar(u8, "'()+_,-./:=? ", byte) == null) return false;
    }
    return true;
}

fn unique(headers: []const Header, name: []const u8) mime.Error!?[]const u8 {
    var value: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, name)) continue;
        if (value != null) return error.InvalidMime;
        value = header.value;
    }
    return value;
}

fn filePart(head: []const u8) mime.Error!bool {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    var disposition: ?[]const u8 = null;
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidMime;
        if (colon == 0) return error.InvalidMime;
        for (line[0..colon]) |byte| if (!mime.token(byte)) return error.InvalidMime;
        for (line) |byte| if (byte < 32 and byte != '\t' or byte == 127)
            return error.InvalidMime;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "content-disposition")) continue;
        if (disposition != null) return error.InvalidMime;
        disposition = std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    var value = try mime.Value.init(disposition orelse return error.InvalidMime);
    if (!std.ascii.eqlIgnoreCase(value.media, "form-data")) return error.InvalidMime;
    var name = false;
    var file = false;
    while (try value.next()) |parameter| {
        if (std.ascii.eqlIgnoreCase(parameter.name, "name")) {
            if (name) return error.InvalidMime;
            name = true;
        } else if (std.ascii.eqlIgnoreCase(parameter.name, "filename")) {
            if (file) return error.InvalidMime;
            file = true;
        }
    }
    if (!name) return error.InvalidMime;
    return file;
}

test "multipart inspection retains metadata and ordinary fields while skipping file bytes" {
    const t = std.testing;
    const body = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"" ++
        "\r\nContent-Type: application/octet-stream\r\n\r\n\x00\r\n--b-fake\r\n" ++
        "\r\n--b\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\nhello\r\n--b--\r\n";
    var fields = Fields.init(&.{.{
        .name = "Content-Type",
        .value = "multipart/form-data; boundary=\"b\"",
    }}, body);
    try t.expect(std.mem.indexOf(u8, fields.next().?, "a.bin") != null);
    try t.expect(std.mem.indexOf(u8, fields.next().?, "caption") != null);
    try t.expectEqualStrings("hello", fields.next().?);
    try t.expect(fields.next() == null);
}

test "ambiguous MIME metadata falls back to text and declared text cannot skip inspection" {
    const t = std.testing;
    const binary_body = "binary\x00bytes";
    var fields = Fields.init(&.{
        .{ .name = "Content-Type", .value = "application/octet-stream" },
        .{ .name = "Content-Type", .value = "application/json" },
    }, binary_body);
    try t.expectEqualStrings(binary_body, fields.next().?);
    fields = Fields.init(&.{.{
        .name = "Content-Type",
        .value = "image/png/invalid",
    }}, binary_body);
    try t.expectEqualStrings(binary_body, fields.next().?);
    fields = Fields.init(&.{.{
        .name = "Content-Type",
        .value = "multipart/form-data; boundary=b; boundary=other",
    }}, binary_body);
    try t.expectEqualStrings(binary_body, fields.next().?);
    const disguised = "--b\r\nContent-Disposition: form-data; name=\"field\"\r\n" ++
        "Content-Type: application/octet-stream\r\n\r\ntext input\r\n--b--\r\n";
    fields = Fields.init(&.{.{
        .name = "Content-Type",
        .value = "multipart/form-data; boundary=b",
    }}, disguised);
    _ = fields.next().?;
    try t.expectEqualStrings("text input", fields.next().?);
    const duplicate = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n" ++
        "Content-Disposition : form-data; name=\"field\"\r\n\r\ntext input\r\n--b--\r\n";
    fields = Fields.init(&.{.{
        .name = "Content-Type",
        .value = "multipart/form-data; boundary=b",
    }}, duplicate);
    try t.expect(std.mem.indexOf(u8, fields.next().?, "text input") != null);
}

test "partial file prefixes are opaque and parsing stays within the inspection byte bound" {
    const t = std.testing;
    const header = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n\r\n";
    var body: [max_prefix + 1024]u8 = @splat(0);
    @memcpy(body[0..header.len], header);
    var fields = Fields.init(&.{.{
        .name = "Content-Type",
        .value = "multipart/form-data; boundary=b",
    }}, &body);
    try t.expectEqual(@as(usize, max_prefix), fields.body.len);
    try t.expect(std.mem.indexOf(u8, fields.next().?, "filename") != null);
    try t.expect(fields.next() == null);
}
