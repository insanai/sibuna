//! Bounded SecLang source reading. Returned slices borrow caller-owned line storage.
//! Reading syntax does not establish that an operator can be executed compatibly.
const std = @import("std");

pub const Error = error{
    NulByte,
    LineTooLong,
    DanglingContinuation,
    UnterminatedQuote,
    UnexpectedQuote,
    TrailingQuotedArgument,
    TooManyArguments,
};

pub const Location = struct {
    line: usize,
    offset: usize,
};

pub const Line = struct {
    bytes: []const u8,
    location: Location,
};

pub const Reader = struct {
    source: []const u8,
    offset: usize = 0,
    line: usize = 1,
    fault: Location = .{ .line = 1, .offset = 0 },

    /// Blank and comment lines are discarded before recognizing continuations.
    /// A backslash followed immediately by LF or CRLF joins physical lines.
    pub fn next(self: *Reader, scratch: []u8) Error!?Line {
        while (self.offset < self.source.len) {
            const start: Location = .{ .line = self.line, .offset = self.offset };
            self.fault = start;
            const end = std.mem.indexOfScalarPos(u8, self.source, self.offset, '\n') orelse
                self.source.len;
            const first = std.mem.trim(u8, self.source[self.offset..end], " \t\r");
            if (first.len == 0 or first[0] == '#') {
                self.advance(end);
                continue;
            }
            const size = try self.logical(scratch);
            return .{ .bytes = scratch[0..size], .location = start };
        }
        return null;
    }

    fn logical(self: *Reader, scratch: []u8) Error!usize {
        var used: usize = 0;
        while (self.offset < self.source.len) {
            const end = std.mem.indexOfScalarPos(u8, self.source, self.offset, '\n') orelse
                self.source.len;
            var bytes = self.source[self.offset..end];
            if (bytes.len > 0 and bytes[bytes.len - 1] == '\r') bytes = bytes[0 .. bytes.len - 1];
            if (std.mem.indexOfScalar(u8, bytes, 0) != null) return error.NulByte;
            const continued = bytes.len > 0 and bytes[bytes.len - 1] == '\\';
            if (continued) bytes = bytes[0 .. bytes.len - 1];
            if (bytes.len > scratch.len - used) return error.LineTooLong;
            @memcpy(scratch[used..][0..bytes.len], bytes);
            used += bytes.len;
            self.advance(end);
            if (!continued) return used;
            if (end == self.source.len or self.offset == self.source.len) {
                return error.DanglingContinuation;
            }
        }
        unreachable;
    }

    fn advance(self: *Reader, end: usize) void {
        self.offset = if (end < self.source.len) end + 1 else end;
        self.line += 1;
    }
};

pub const Token = struct {
    /// Content excludes the outer quote. Regex/config escapes remain intact.
    bytes: []const u8,
    quote: ?u8,
    offset: usize,
};

pub const Arguments = struct {
    bytes: []const u8,
    offset: usize = 0,

    pub fn next(self: *Arguments) Error!?Token {
        while (self.offset < self.bytes.len and space(self.bytes[self.offset])) {
            self.offset += 1;
        }
        if (self.offset == self.bytes.len) return null;
        const start = self.offset;
        const quote: ?u8 = switch (self.bytes[start]) {
            '"', '\'' => self.bytes[start],
            else => null,
        };
        if (quote != null) self.offset += 1;
        const content = self.offset;
        while (self.offset < self.bytes.len) {
            const byte = self.bytes[self.offset];
            if (byte == '\\' and self.offset + 1 < self.bytes.len) {
                self.offset += 2;
                continue;
            }
            if (quote != null and byte == quote.?) {
                const end = self.offset;
                self.offset += 1;
                if (self.offset < self.bytes.len and !space(self.bytes[self.offset])) {
                    return error.TrailingQuotedArgument;
                }
                return .{ .bytes = self.bytes[content..end], .quote = quote, .offset = start };
            }
            if (quote == null and space(byte)) break;
            if (quote == null and (byte == '"' or byte == '\'')) return error.UnexpectedQuote;
            self.offset += 1;
        }
        if (quote != null) return error.UnterminatedQuote;
        return .{ .bytes = self.bytes[content..self.offset], .quote = null, .offset = start };
    }
};

fn space(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '\r';
}

test "continued actions preserve regex escapes and quoted punctuation" {
    var reader: Reader = .{
        .source = " # ignored \\\nSecRule ARGS \"@rx \\b[\\\"']+\" \\\r\n" ++
            "  \"id:1,\\\nmsg:'one, two',chain\"\nSecMarker END\n",
    };
    var scratch: [256]u8 = undefined;
    const line = (try reader.next(&scratch)).?;
    try std.testing.expectEqual(@as(usize, 2), line.location.line);
    var args: Arguments = .{ .bytes = line.bytes };
    try std.testing.expectEqualStrings("SecRule", (try args.next()).?.bytes);
    try std.testing.expectEqualStrings("ARGS", (try args.next()).?.bytes);
    try std.testing.expectEqualStrings("@rx \\b[\\\"']+", (try args.next()).?.bytes);
    try std.testing.expectEqualStrings("id:1,msg:'one, two',chain", (try args.next()).?.bytes);
    try std.testing.expect((try args.next()) == null);
    try std.testing.expectEqual(@as(usize, 5), (try reader.next(&scratch)).?.location.line);
}

test "source errors do not truncate or repair invalid syntax" {
    var scratch: [8]u8 = undefined;
    var large: Reader = .{ .source = "SecRule ARGS\n" };
    try std.testing.expectError(error.LineTooLong, large.next(&scratch));
    var dangling: Reader = .{ .source = "x\\\n" };
    try std.testing.expectError(error.DanglingContinuation, dangling.next(&scratch));
    var nul: Reader = .{ .source = "x\x00y\n" };
    try std.testing.expectError(error.NulByte, nul.next(&scratch));
    var quoted: Arguments = .{ .bytes = "\"never ends" };
    try std.testing.expectError(error.UnterminatedQuote, quoted.next());
    var trailing: Arguments = .{ .bytes = "\"ends\"oops" };
    try std.testing.expectError(error.TrailingQuotedArgument, trailing.next());
}

test "odd and even escape runs determine quote termination" {
    var args: Arguments = .{ .bytes = "\"a\\\\\" \"b\\\"c\"" };
    try std.testing.expectEqualStrings("a\\\\", (try args.next()).?.bytes);
    try std.testing.expectEqualStrings("b\\\"c", (try args.next()).?.bytes);
    try std.testing.expect((try args.next()) == null);
}
