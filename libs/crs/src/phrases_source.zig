//! Bounded SecLang phrase inputs. File bytes are supplied by the artifact owner;
//! no file handle, path traversal, network lookup or macro callback reaches matching.
const std = @import("std");
const phrases = @import("phrases.zig");

const Pair = struct { byte: u8 = 0, pending: bool = false };

/// Match the pinned inline parser's escape/binary grammar, including its literal
/// fallback for invalid sequences. Returned bytes borrow source or caller scratch.
fn decode(input: []const u8, scratch: []u8) []const u8 {
    std.debug.assert(scratch.len >= input.len);
    var start: usize = 0;
    while (start < input.len and (input[start] == ' ' or input[start] == '\t')) start += 1;
    if (start == input.len) return input;
    var end = input.len;
    if (end - start >= 2 and input[start] == '"' and input[end - 1] == '"') {
        start += 1;
        end -= 1;
    }
    if (start == end) return input;
    var binary = false;
    var escaped = false;
    var pair: Pair = .{};
    var written: usize = 0;
    for (input[start..end]) |byte| {
        if (byte == '|') {
            binary = !binary;
            continue;
        }
        if (!escaped and byte == '\\') {
            escaped = true;
            continue;
        }
        if (binary) {
            if (!std.ascii.isHex(byte)) return input;
            const value: u8 = if (std.ascii.isDigit(byte))
                byte - '0'
            else
                std.ascii.toLower(byte) - 'a' + 10;
            if (!pair.pending) {
                pair = .{ .byte = value, .pending = true };
                continue;
            }
            scratch[written] = pair.byte * 16 + value;
            pair.pending = false;
        } else {
            if (escaped) {
                if (byte != ':' and byte != ';' and byte != '\\' and byte != '"') return input;
                escaped = false;
            }
            scratch[written] = byte;
        }
        written += 1;
    }
    return scratch[0..written];
}

fn append(
    allocator: std.mem.Allocator,
    words: *std.ArrayList([]const u8),
    word: []const u8,
    limit: usize,
) phrases.Error!void {
    if (words.items.len == limit) return error.PhraseLimit;
    try words.append(allocator, word);
}

pub fn inlineWords(
    allocator: std.mem.Allocator,
    source: []const u8,
    options: phrases.Options,
) phrases.Error!phrases.Program {
    if (source.len > options.bytes) return error.SourceLimit;
    const scratch = try allocator.alloc(u8, source.len);
    defer allocator.free(scratch);
    const bytes = decode(source, scratch);
    var words: std.ArrayList([]const u8) = .empty;
    defer words.deinit(allocator);
    var position: usize = 0;
    while (position < bytes.len) {
        while (position < bytes.len and std.ascii.isWhitespace(bytes[position])) position += 1;
        const start = position;
        while (position < bytes.len and !std.ascii.isWhitespace(bytes[position])) position += 1;
        if (position > start) {
            try append(allocator, &words, bytes[start..position], options.phrases);
        }
    }
    return phrases.compile(allocator, words.items, options);
}

pub fn fileWords(
    allocator: std.mem.Allocator,
    source: []const u8,
    options: phrases.Options,
) phrases.Error!phrases.Program {
    if (source.len > options.bytes) return error.SourceLimit;
    var words: std.ArrayList([]const u8) = .empty;
    defer words.deinit(allocator);
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var first: usize = 0;
        while (first < line.len and std.ascii.isWhitespace(line[first])) first += 1;
        if (first < line.len and line[first] == '#') continue;
        // getline preserves CR and other whitespace. A whitespace-only line
        // without '#' is a literal phrase, unlike an inline token list.
        try append(allocator, &words, line, options.phrases);
    }
    return phrases.compile(allocator, words.items, options);
}

test "inline quoting binary pairs and literal fallback retain pinned source meaning" {
    const cases = [_]struct { source: []const u8, input: []const u8, capture: []const u8 }{
        .{ .source = "\t\"one t|776f|\"", .input = "TWO", .capture = "two" },
        .{ .source = "a\\:b a\\;c", .input = "A;C", .capture = "a;c" },
        .{ .source = "a\\q", .input = "a\\q", .capture = "a\\q" },
        .{ .source = "\"\"", .input = "\"\"", .capture = "\"\"" },
        .{ .source = "|61", .input = "A", .capture = "a" },
    };
    for (cases) |case| {
        var program = try inlineWords(std.testing.allocator, case.source, .{});
        defer program.deinit();
        var budget: @import("work.zig").Budget = .{ .remaining = 1024 };
        const result = (try program.search(case.input, &budget)).?;
        try std.testing.expectEqualStrings(case.capture, result.capture);
    }
}

test "phrase files preserve literal whitespace CR and comments without borrowing input" {
    var program = try fileWords(std.testing.allocator, " # comment\n\n \nABC\r\n", .{});
    defer program.deinit();
    try std.testing.expectEqual(@as(usize, 2), program.words.len);
    try std.testing.expectEqualStrings(" ", program.words[0]);
    try std.testing.expectEqualStrings("ABC\r", program.words[1]);
    try std.testing.expectError(
        error.NulPhrase,
        inlineWords(std.testing.allocator, "a|00|b", .{}),
    );
}

fn allocationScenario(allocator: std.mem.Allocator) !void {
    var program = try inlineWords(allocator, "one |74776f| three", .{});
    defer program.deinit();
    var file = try fileWords(allocator, "# comment\none\ntwo\n", .{});
    defer file.deinit();
}

test "phrase source compilation releases scratch and partial programs on allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{});
}
