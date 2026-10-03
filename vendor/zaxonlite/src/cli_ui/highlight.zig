//! The pure SQL tokenizer (ZDS 0005, M4).
//!
//! Classifies shell input into styled spans and answers the multi-line
//! continuation question (a `;` inside a string does not submit). The
//! keyword set is a comptime-built static map over the SQLite keyword
//! list, so lookup costs no allocation and no runtime table maintenance.
//! One bounded forward pass; no recursion.

const std = @import("std");

pub const Kind = enum {
    text,
    keyword,
    identifier,
    string,
    number,
    comment,
    operator,
    dot,
};

pub const Span = struct {
    start: usize,
    len: usize,
    kind: Kind,

    pub fn bytes(self: Span, source: []const u8) []const u8 {
        return source[self.start .. self.start + self.len];
    }
};

/// The SQLite keyword list, lowercase. Membership is checked against a
/// lowercased copy of the token, so matching is case-insensitive.
const keywords = std.StaticStringMap(void).initComptime(.{
    .{"abort"},         .{"action"},       .{"add"},          .{"after"},
    .{"all"},           .{"alter"},        .{"always"},       .{"analyze"},
    .{"and"},           .{"as"},           .{"asc"},          .{"attach"},
    .{"autoincrement"}, .{"before"},       .{"begin"},        .{"between"},
    .{"by"},            .{"cascade"},      .{"case"},         .{"cast"},
    .{"check"},         .{"collate"},      .{"column"},       .{"commit"},
    .{"conflict"},      .{"constraint"},   .{"create"},       .{"cross"},
    .{"current"},       .{"current_date"}, .{"current_time"}, .{"current_timestamp"},
    .{"database"},      .{"default"},      .{"deferrable"},   .{"deferred"},
    .{"delete"},        .{"desc"},         .{"detach"},       .{"distinct"},
    .{"do"},            .{"drop"},         .{"each"},         .{"else"},
    .{"end"},           .{"escape"},       .{"except"},       .{"exclude"},
    .{"exclusive"},     .{"exists"},       .{"explain"},      .{"fail"},
    .{"filter"},        .{"first"},        .{"following"},    .{"for"},
    .{"foreign"},       .{"from"},         .{"full"},         .{"generated"},
    .{"glob"},          .{"group"},        .{"groups"},       .{"having"},
    .{"if"},            .{"ignore"},       .{"immediate"},    .{"in"},
    .{"index"},         .{"indexed"},      .{"initially"},    .{"inner"},
    .{"insert"},        .{"instead"},      .{"intersect"},    .{"into"},
    .{"is"},            .{"isnull"},       .{"join"},         .{"key"},
    .{"last"},          .{"left"},         .{"like"},         .{"limit"},
    .{"match"},         .{"materialized"}, .{"natural"},      .{"no"},
    .{"not"},           .{"nothing"},      .{"notnull"},      .{"null"},
    .{"nulls"},         .{"of"},           .{"offset"},       .{"on"},
    .{"or"},            .{"order"},        .{"others"},       .{"outer"},
    .{"over"},          .{"partition"},    .{"plan"},         .{"pragma"},
    .{"preceding"},     .{"primary"},      .{"query"},        .{"raise"},
    .{"range"},         .{"recursive"},    .{"references"},   .{"regexp"},
    .{"reindex"},       .{"release"},      .{"rename"},       .{"replace"},
    .{"restrict"},      .{"returning"},    .{"right"},        .{"rollback"},
    .{"row"},           .{"rows"},         .{"savepoint"},    .{"select"},
    .{"set"},           .{"table"},        .{"temp"},         .{"temporary"},
    .{"then"},          .{"ties"},         .{"to"},           .{"transaction"},
    .{"trigger"},       .{"unbounded"},    .{"union"},        .{"unique"},
    .{"update"},        .{"using"},        .{"vacuum"},       .{"values"},
    .{"view"},          .{"virtual"},      .{"when"},         .{"where"},
    .{"window"},        .{"with"},         .{"without"},
});

const longest_keyword = blk: {
    var max: usize = 0;
    for (keywords.keys()) |key| max = @max(max, key.len);
    break :blk max;
};

pub fn isKeyword(token: []const u8) bool {
    if (token.len > longest_keyword) return false;
    var lowered: [longest_keyword]u8 = undefined;
    for (token, 0..) |byte, index| {
        lowered[index] = std.ascii.toLower(byte);
    }
    return keywords.has(lowered[0..token.len]);
}

/// A zero-allocation span iterator. Spans cover the whole input in order:
/// whitespace and unclassified bytes come back as `.text`.
pub const Tokenizer = struct {
    source: []const u8,
    position: usize = 0,

    pub fn init(source: []const u8) Tokenizer {
        // A dot command is one span: the whole line styles as a command.
        return .{ .source = source };
    }

    pub fn next(self: *Tokenizer) ?Span {
        const source = self.source;
        if (self.position >= source.len) return null;
        const start = self.position;
        if (start == 0 and source.len > 0 and source[0] == '.') {
            self.position = source.len;
            return .{ .start = 0, .len = source.len, .kind = .dot };
        }
        const byte = source[start];
        if (byte == '-' and start + 1 < source.len and source[start + 1] == '-') {
            self.position = untilLineEnd(source, start);
            return .{ .start = start, .len = self.position - start, .kind = .comment };
        }
        if (byte == '/' and start + 1 < source.len and source[start + 1] == '*') {
            self.position = untilBlockEnd(source, start);
            return .{ .start = start, .len = self.position - start, .kind = .comment };
        }
        if (byte == '\'') {
            self.position = untilQuoteEnd(source, start, '\'');
            return .{ .start = start, .len = self.position - start, .kind = .string };
        }
        if (byte == '"' or byte == '`') {
            self.position = untilQuoteEnd(source, start, byte);
            return .{ .start = start, .len = self.position - start, .kind = .identifier };
        }
        if (byte == '[') {
            self.position = untilByte(source, start + 1, ']');
            return .{ .start = start, .len = self.position - start, .kind = .identifier };
        }
        if (std.ascii.isDigit(byte)) {
            self.position = untilNumberEnd(source, start);
            return .{ .start = start, .len = self.position - start, .kind = .number };
        }
        if (isIdentifierStart(byte)) {
            self.position = untilIdentifierEnd(source, start);
            const token = source[start..self.position];
            const kind: Kind = if (isKeyword(token)) .keyword else .identifier;
            return .{ .start = start, .len = token.len, .kind = kind };
        }
        if (std.ascii.isWhitespace(byte)) {
            var end = start;
            while (end < source.len and std.ascii.isWhitespace(source[end])) end += 1;
            self.position = end;
            return .{ .start = start, .len = end - start, .kind = .text };
        }
        self.position = start + 1;
        return .{ .start = start, .len = 1, .kind = .operator };
    }
};

fn isIdentifierStart(byte: u8) bool {
    return std.ascii.isAlphabetic(byte) or byte == '_' or byte >= 0x80;
}

fn isIdentifierByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '$' or
        byte >= 0x80;
}

fn untilLineEnd(source: []const u8, start: usize) usize {
    var end = start;
    while (end < source.len and source[end] != '\n') end += 1;
    return end;
}

fn untilBlockEnd(source: []const u8, start: usize) usize {
    var end = start + 2;
    while (end + 1 < source.len) : (end += 1) {
        if (source[end] == '*' and source[end + 1] == '/') return end + 2;
    }
    return source.len;
}

fn untilQuoteEnd(source: []const u8, start: usize, quote: u8) usize {
    var end = start + 1;
    while (end < source.len) : (end += 1) {
        if (source[end] != quote) continue;
        // A doubled quote is an escaped quote inside the literal.
        if (end + 1 < source.len and source[end + 1] == quote) {
            end += 1;
            continue;
        }
        return end + 1;
    }
    return source.len;
}

fn untilByte(source: []const u8, start: usize, target: u8) usize {
    var end = start;
    while (end < source.len) : (end += 1) {
        if (source[end] == target) return end + 1;
    }
    return source.len;
}

fn untilNumberEnd(source: []const u8, start: usize) usize {
    var end = start;
    while (end < source.len) : (end += 1) {
        const byte = source[end];
        const numeric = std.ascii.isHex(byte) or byte == '.' or byte == 'x' or
            byte == 'X';
        const exponent_sign = (byte == '+' or byte == '-') and end > start and
            (source[end - 1] == 'e' or source[end - 1] == 'E');
        if (!numeric and !exponent_sign) return end;
    }
    return source.len;
}

fn untilIdentifierEnd(source: []const u8, start: usize) usize {
    var end = start;
    while (end < source.len and isIdentifierByte(source[end])) end += 1;
    return end;
}

/// Whether the accumulated input is a complete statement: its last
/// meaningful token is `;`, with strings and comments respected. This is
/// the multi-line continuation decision.
pub fn statementComplete(source: []const u8) bool {
    var tokenizer = Tokenizer.init(source);
    var last_semicolon = false;
    while (tokenizer.next()) |span| {
        switch (span.kind) {
            .text => continue,
            .comment => {
                const body = span.bytes(source);
                if (std.mem.startsWith(u8, body, "/*") and
                    !std.mem.endsWith(u8, body, "*/")) return false;
                continue;
            },
            .operator => last_semicolon = source[span.start] == ';',
            .string => {
                // An unterminated string keeps the statement open.
                const body = span.bytes(source);
                if (body.len < 2 or !closedQuote(body, '\'')) return false;
                last_semicolon = false;
            },
            .identifier => {
                const body = span.bytes(source);
                if (body.len > 0) switch (body[0]) {
                    '"', '`' => if (!closedQuote(body, body[0])) return false,
                    '[' => if (body.len < 2 or body[body.len - 1] != ']') return false,
                    else => {},
                };
                last_semicolon = false;
            },
            else => last_semicolon = false,
        }
    }
    return last_semicolon;
}

fn closedQuote(body: []const u8, quote: u8) bool {
    // `body` starts with the quote; it is closed when it ends with an
    // unpaired closing quote.
    if (body.len < 2 or body[body.len - 1] != quote) return false;
    var doubled: usize = 0;
    var index = body.len - 1;
    while (index > 1 and body[index - 1] == quote) : (index -= 1) doubled += 1;
    return doubled % 2 == 0;
}
