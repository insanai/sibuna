//! Linear multipart delimiter search. Initialize in place: prepared KMP prefixes
//! borrow this iterator's arrays. Invalid delimiter suffixes remain payload bytes.
const std = @import("std");
const substring = @import("substring.zig");
const work = @import("work.zig");
pub const Error = substring.Error || error{InvalidMultipartBoundary};
pub const Delimiter = struct { start: usize, after: usize, closing: bool };
pub const Iterator = struct {
    input: []const u8,
    needle: [74]u8 = undefined,
    prefixes: [74]usize = undefined,
    pattern: substring.Pattern = undefined,
    cursor: usize = 0,
    first: bool = true,
    finished: bool = false,
    budget: *work.Budget,

    pub fn init(
        self: *Iterator,
        input: []const u8,
        boundary: []const u8,
        budget: *work.Budget,
    ) Error!void {
        try budget.debit(boundary.len + 1);
        if (boundary.len == 0 or boundary.len > 70 or boundary[boundary.len - 1] == ' ')
            return error.InvalidMultipartBoundary;
        for (boundary) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and
                std.mem.indexOfScalar(u8, "'()+_,-./:=? ", byte) == null)
                return error.InvalidMultipartBoundary;
        }
        self.* = .{ .input = input, .budget = budget };
        @memcpy(self.needle[0..4], "\r\n--");
        @memcpy(self.needle[4..][0..boundary.len], boundary);
        self.pattern = try substring.prepare(
            self.needle[0 .. boundary.len + 4],
            &self.prefixes,
            budget,
        );
    }

    pub fn next(self: *Iterator) Error!?Delimiter {
        if (self.finished) return null;
        if (self.first) {
            self.first = false;
            const opening = self.pattern.bytes[2..];
            try self.budget.debit(opening.len + 1);
            if (std.mem.startsWith(u8, self.input, opening)) {
                if (try self.suffix(0, opening.len)) |delimiter| return self.accept(delimiter);
            }
        }
        while (try self.pattern.find(self.input[self.cursor..], self.budget)) |relative| {
            const at = self.cursor + relative;
            const end = at + self.pattern.bytes.len;
            self.cursor = end;
            if (try self.suffix(at, end)) |delimiter| return self.accept(delimiter);
        }
        self.finished = true;
        return null;
    }

    fn accept(self: *Iterator, delimiter: Delimiter) Delimiter {
        self.cursor = delimiter.after;
        self.finished = delimiter.closing;
        return delimiter;
    }

    fn suffix(self: *Iterator, start: usize, end: usize) Error!?Delimiter {
        const rest = self.input[end..];
        try self.budget.debit(2);
        const closing = std.mem.startsWith(u8, rest, "--");
        var length: usize = if (closing) 2 else 0;
        while (length < rest.len and (rest[length] == ' ' or rest[length] == '\t')) {
            try self.budget.debit(1);
            length += 1;
        }
        if (length == rest.len and closing) return .{
            .start = start,
            .after = end + length,
            .closing = true,
        };
        try self.budget.debit(2);
        if (!std.mem.startsWith(u8, rest[length..], "\r\n")) return null;
        return .{ .start = start, .after = end + length + 2, .closing = closing };
    }
};

test "delimiter prefixes inside file payload are not boundaries" {
    var budget: work.Budget = .{ .remaining = 10000 };
    var iterator: Iterator = undefined;
    const input = "--boundary\r\nhead\r\n--boundaryx\r\n--boundary--garbage\r\n--boundary--\r\n";
    try iterator.init(input, "boundary", &budget);
    const first = (try iterator.next()).?;
    const last = (try iterator.next()).?;
    try std.testing.expect(!first.closing);
    try std.testing.expect(last.closing);
    try std.testing.expectEqualStrings(
        "head\r\n--boundaryx\r\n--boundary--garbage",
        input[first.after..last.start],
    );
    try std.testing.expect(try iterator.next() == null);
}
