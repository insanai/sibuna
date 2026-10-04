//! Strict multipart metadata. The complete processor retains all raw part-header
//! lines separately; this parser resolves one unambiguous field/file disposition.
const std = @import("std");
const mime = @import("text").mime;
const work = @import("work.zig");
const buffers = @import("buffers.zig");
const percent = @import("percent_decode.zig");
pub const Error = mime.Error || work.Error || percent.Error || error{
    InvalidMultipartHead,
    UnsupportedPartEncoding,
    UnsupportedFilenameEncoding,
    MultipartNameLimit,
};
pub const Scratch = struct { name: []u8, filename: []u8, extended: []u8 = &.{} };
pub const Part = struct { name: []const u8, filename: ?[]const u8 };

pub fn parse(head: []const u8, scratch: Scratch, budget: *work.Budget) Error!Part {
    buffers.assertExclusive(&.{ head, scratch.name, scratch.filename, scratch.extended });
    const cost = std.math.mul(u64, head.len, 4) catch return error.WorkLimit;
    try budget.debit(std.math.add(u64, cost, 1) catch return error.WorkLimit);
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    var disposition: ?[]const u8 = null;
    var media: ?[]const u8 = null;
    var encoded = false;
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse
            return error.InvalidMultipartHead;
        if (colon == 0) return error.InvalidMultipartHead;
        for (line[0..colon]) |byte| if (!mime.token(byte)) return error.InvalidMultipartHead;
        for (line) |byte| {
            if (byte < 32 and byte != '\t' or byte == 127) return error.InvalidMultipartHead;
        }
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(line[0..colon], "Content-Disposition")) {
            if (disposition != null) return error.InvalidMultipartHead;
            disposition = value;
        } else if (std.ascii.eqlIgnoreCase(line[0..colon], "Content-Type")) {
            if (media != null) return error.InvalidMultipartHead;
            media = value;
        } else if (std.ascii.eqlIgnoreCase(line[0..colon], "Content-Transfer-Encoding")) {
            if (encoded) return error.InvalidMultipartHead;
            encoded = true;
            if (!std.ascii.eqlIgnoreCase(value, "binary") and
                !std.ascii.eqlIgnoreCase(value, "8bit") and
                !std.ascii.eqlIgnoreCase(value, "7bit")) return error.UnsupportedPartEncoding;
        }
    }
    if (media) |text| {
        var value = try mime.Value.init(text);
        if (!mime.mediaType(value.media)) return error.InvalidMultipartHead;
        while (try value.next()) |_| {}
    }
    const value = disposition orelse return error.InvalidMultipartHead;
    return parseDisposition(value, scratch, budget);
}

fn parseDisposition(value: []const u8, scratch: Scratch, budget: *work.Budget) Error!Part {
    var disposition = try mime.Value.init(value);
    if (!std.ascii.eqlIgnoreCase(disposition.media, "form-data")) {
        return error.InvalidMultipartHead;
    }
    var name: ?[]const u8 = null;
    var filename: ?[]const u8 = null;
    var extended: ?[]const u8 = null;
    while (try disposition.next()) |parameter| {
        if (std.ascii.eqlIgnoreCase(parameter.name, "name")) {
            if (name != null) return error.InvalidMultipartHead;
            name = try quoted(parameter.value, scratch.name, budget);
        } else if (std.ascii.eqlIgnoreCase(parameter.name, "filename")) {
            if (filename != null) return error.InvalidMultipartHead;
            filename = try quoted(parameter.value, scratch.filename, budget);
        } else if (std.ascii.eqlIgnoreCase(parameter.name, "filename*")) {
            if (extended != null) return error.InvalidMultipartHead;
            extended = parameter.value;
        } else return error.InvalidMultipartHead;
    }
    if (extended) |text| try checkExtended(text, filename, scratch.extended, budget);
    const field = name orelse return error.InvalidMultipartHead;
    if (field.len == 0) return error.InvalidMultipartHead;
    return .{ .name = field, .filename = filename };
}

/// The pinned disposition decoder unescapes quote/backslash pairs and preserves
/// other backslashes sent by older clients. Neither percent nor Unicode decoding
/// applies to ordinary disposition parameters.
fn quoted(input: []const u8, output: []u8, budget: *work.Budget) Error![]const u8 {
    const cost = std.math.mul(u64, input.len, 2) catch return error.WorkLimit;
    try budget.debit(std.math.add(u64, cost, 1) catch return error.WorkLimit);
    if (input.len > output.len) return error.MultipartNameLimit;
    buffers.assertDisjoint(input, output[0..input.len]);
    var index: usize = 0;
    var used: usize = 0;
    while (index < input.len) {
        if (input[index] == '\\' and index + 1 < input.len and
            (input[index + 1] == '\\' or input[index + 1] == '"')) index += 1;
        output[used] = input[index];
        used += 1;
        index += 1;
    }
    return output[0..used];
}

/// Refuse competing filenames. Backends may prefer filename* while the pinned
/// reference keeps filename; accepting different values would hide that name.
fn checkExtended(
    input: []const u8,
    filename: ?[]const u8,
    output: []u8,
    budget: *work.Budget,
) Error!void {
    try budget.debit(input.len * 2 + 1);
    const first = std.mem.indexOfScalar(u8, input, '\'') orelse
        return error.UnsupportedFilenameEncoding;
    if (!std.ascii.eqlIgnoreCase(input[0..first], "UTF-8"))
        return error.UnsupportedFilenameEncoding;
    const tail = input[first + 1 ..];
    const second = std.mem.indexOfScalar(u8, tail, '\'') orelse
        return error.UnsupportedFilenameEncoding;
    for (tail[0..second]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-') return error.InvalidMultipartHead;
    }
    const decoded = try percent.decode(tail[second + 1 ..], output, false, budget);
    try budget.debit(decoded.len * 2 + 1);
    if (!std.unicode.utf8ValidateSlice(decoded)) return error.UnsupportedFilenameEncoding;
    const ordinary = filename orelse return error.InvalidMultipartHead;
    if (!std.mem.eql(u8, decoded, ordinary)) return error.InvalidMultipartHead;
}
