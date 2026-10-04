//! Typed variable selection. The compiler owns source bytes; selectors borrow them.
//! Regex selectors retain their patterns until generation compilation. They cannot be
//! interpreted as literal keys or split at alternation bars inside the expression.
const std = @import("std");
const collections = @import("collections.zig");

pub const Error = std.mem.Allocator.Error || error{
    InvalidSelector,
    UnknownCollection,
    UnsupportedXPath,
    SelectorLimit,
};
pub const Mode = enum { values, count, exclude };
pub const Xml = enum { elements, attributes };
pub const Selection = union(enum) {
    all,
    name: []const u8,
    pattern: []const u8,
    xml: Xml,
};
pub const Selector = struct {
    collection: collections.Collection,
    mode: Mode,
    selection: Selection,
};

pub const Iterator = struct {
    bytes: []const u8,
    offset: usize = 0,

    pub fn next(self: *Iterator) Error!?Selector {
        if (self.offset == self.bytes.len) return null;
        const mode: Mode = switch (self.bytes[self.offset]) {
            '!' => .exclude,
            '&' => .count,
            else => .values,
        };
        if (mode != .values) self.offset += 1;
        const begin = self.offset;
        while (self.offset < self.bytes.len and self.bytes[self.offset] != ':' and
            self.bytes[self.offset] != '|') : (self.offset += 1)
        {}
        const name = self.bytes[begin..self.offset];
        if (name.len == 0 or name[0] == '!' or name[0] == '&') return error.InvalidSelector;
        const collection = collections.lookup(name) orelse return error.UnknownCollection;
        var selection: Selection = .all;
        if (self.offset < self.bytes.len and self.bytes[self.offset] == ':') {
            if (!collection.keyed()) return error.InvalidSelector;
            self.offset += 1;
            selection = try self.key(collection);
        }
        if (self.offset < self.bytes.len) {
            std.debug.assert(self.bytes[self.offset] == '|');
            self.offset += 1;
            if (self.offset == self.bytes.len) return error.InvalidSelector;
        }
        return .{ .collection = collection, .mode = mode, .selection = selection };
    }

    fn key(self: *Iterator, collection: collections.Collection) Error!Selection {
        const begin = self.offset;
        if (begin == self.bytes.len or self.bytes[begin] == '|') return error.InvalidSelector;
        if (collection != .xml and self.bytes[begin] == '/') return self.pattern();
        while (self.offset < self.bytes.len and self.bytes[self.offset] != '|') {
            self.offset += 1;
        }
        const bytes = self.bytes[begin..self.offset];
        if (collection != .xml) return .{ .name = bytes };
        if (std.mem.eql(u8, bytes, "/*")) return .{ .xml = .elements };
        if (std.mem.eql(u8, bytes, "//@*")) return .{ .xml = .attributes };
        return error.UnsupportedXPath;
    }

    fn pattern(self: *Iterator) Error!Selection {
        self.offset += 1;
        const begin = self.offset;
        var escaped = false;
        while (self.offset < self.bytes.len) : (self.offset += 1) {
            const byte = self.bytes[self.offset];
            if (byte == '/' and !escaped) {
                const expression = self.bytes[begin..self.offset];
                self.offset += 1;
                if (self.offset < self.bytes.len and self.bytes[self.offset] != '|') {
                    return error.InvalidSelector;
                }
                return .{ .pattern = expression };
            }
            escaped = byte == '\\' and !escaped;
        }
        return error.InvalidSelector;
    }
};

/// Allocation happens off-path. The returned array is owned by the supplied allocator;
/// text inside each selector continues to borrow the caller's source.
pub fn parse(allocator: std.mem.Allocator, bytes: []const u8, limit: usize) Error![]Selector {
    if (bytes.len == 0) return error.InvalidSelector;
    var iterator: Iterator = .{ .bytes = bytes };
    var result: std.ArrayList(Selector) = .empty;
    errdefer result.deinit(allocator);
    while (try iterator.next()) |selector| {
        if (result.items.len == limit) return error.SelectorLimit;
        try result.append(allocator, selector);
    }
    return result.toOwnedSlice(allocator);
}

test "selection keeps exclusions, counts, regex alternatives and XML distinct" {
    const text = "ARGS|!ARGS:/^(a|b)\\/x$/|&request_headers:Host|XML:/*|XML://@*";
    const parsed = try parse(std.testing.allocator, text, 8);
    defer std.testing.allocator.free(parsed);
    try std.testing.expectEqual(@as(usize, 5), parsed.len);
    try std.testing.expectEqual(collections.Collection.args, parsed[0].collection);
    try std.testing.expectEqual(Mode.exclude, parsed[1].mode);
    try std.testing.expectEqualStrings("^(a|b)\\/x$", parsed[1].selection.pattern);
    try std.testing.expectEqual(Mode.count, parsed[2].mode);
    try std.testing.expectEqualStrings("Host", parsed[2].selection.name);
    try std.testing.expectEqual(Xml.elements, parsed[3].selection.xml);
    try std.testing.expectEqual(Xml.attributes, parsed[4].selection.xml);
}

test "unsupported and incomplete selectors fail instead of broadening coverage" {
    const invalid = [_][]const u8{
        "",             "ARGS|",               "|ARGS", "!&ARGS", "&!ARGS", "ARGS:", "ARGS:/x",
        "ARGS:/x/junk", "REQUEST_METHOD:name",
    };
    for (invalid) |bytes| {
        try std.testing.expectError(error.InvalidSelector, parse(std.testing.allocator, bytes, 8));
    }
    try std.testing.expectError(
        error.UnknownCollection,
        parse(std.testing.allocator, "INVENTED:value", 8),
    );
    try std.testing.expectError(
        error.UnsupportedXPath,
        parse(std.testing.allocator, "XML://node/text()", 8),
    );
    try std.testing.expectError(
        error.SelectorLimit,
        parse(std.testing.allocator, "ARGS|ARGS_NAMES", 1),
    );
}
