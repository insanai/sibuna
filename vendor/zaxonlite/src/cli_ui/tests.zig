//! Unit tests for the shared terminal UI's pure state machines
//! (ZDS 0005). Everything here runs without a TTY: key sequences drive
//! the editor, text drives the tokenizer and history, and the renderers
//! are compared against golden strings, including sanitization of hostile
//! cells.

const std = @import("std");
const testing = std.testing;

const term = @import("term.zig");
const editor_mod = @import("editor.zig");
const history_mod = @import("history.zig");
const highlight = @import("highlight.zig");
const table = @import("table.zig");
const view_mod = @import("view.zig");

const Key = term.Key;
const Editor = editor_mod.Editor;

fn keyOf(text: []const u8) Key {
    const view = std.unicode.Utf8View.init(text) catch unreachable;
    var iterator = view.iterator();
    const codepoint = iterator.nextCodepoint() orelse unreachable;
    return .{ .codepoint = codepoint, .text = text };
}

fn ctrl(letter: u21) Key {
    return .{ .codepoint = letter, .mods = .{ .ctrl = true } };
}

fn alt(letter: u21) Key {
    return .{ .codepoint = letter, .mods = .{ .alt = true } };
}

fn special(codepoint: u21) Key {
    return .{ .codepoint = codepoint };
}

fn type_text(editor: *Editor, text: []const u8) void {
    var iterator = std.mem.window(u8, text, 1, 1);
    while (iterator.next()) |slice| {
        _ = editor.feed(keyOf(slice));
    }
}

// ----------------------------------------------------------------------
// Editor
// ----------------------------------------------------------------------

test "editor inserts printable text and submits" {
    var editor = Editor{};
    type_text(&editor, "select 1");
    try testing.expectEqualStrings("select 1", editor.text());
    try testing.expectEqual(editor_mod.Action.submit, editor.feed(special(Key.enter)));
}

test "editor cursor movement and mid-line insertion" {
    var editor = Editor{};
    type_text(&editor, "selct");
    _ = editor.feed(special(Key.left));
    _ = editor.feed(special(Key.left));
    _ = editor.feed(keyOf("e"));
    try testing.expectEqualStrings("select", editor.text());
    _ = editor.feed(ctrl('a'));
    try testing.expectEqual(@as(usize, 0), editor.cursor);
    _ = editor.feed(ctrl('e'));
    try testing.expectEqual(editor.text().len, editor.cursor);
}

test "editor backspace and delete are grapheme-aware" {
    var editor = Editor{};
    _ = editor.insertText("a\u{1F44D}b"); // a 👍 b
    _ = editor.feed(special(Key.left)); // cursor before b
    _ = editor.feed(special(Key.backspace)); // removes the emoji whole
    try testing.expectEqualStrings("ab", editor.text());
    _ = editor.feed(ctrl('a'));
    _ = editor.feed(special(Key.delete));
    try testing.expectEqualStrings("b", editor.text());
}

test "editor word movement and kill operations" {
    var editor = Editor{};
    type_text(&editor, "select a from t");
    _ = editor.feed(alt('b'));
    try testing.expectEqual(@as(usize, 14), editor.cursor); // before "t"
    _ = editor.feed(ctrl('w'));
    try testing.expectEqualStrings("select a t", editor.text());
    _ = editor.feed(ctrl('u'));
    try testing.expectEqualStrings("t", editor.text());
    _ = editor.feed(ctrl('e'));
    _ = editor.feed(ctrl('u'));
    try testing.expectEqualStrings("", editor.text());
    type_text(&editor, "abc def");
    _ = editor.feed(alt('b'));
    _ = editor.feed(ctrl('k'));
    try testing.expectEqualStrings("abc ", editor.text());
    _ = editor.feed(ctrl('y'));
    try testing.expectEqualStrings("abc def", editor.text());
}

test "editor history replacement preserves UTF-8 boundaries" {
    var editor = Editor{};
    const prefix = &@as([(editor_mod.capacity - 1)]u8, @splat(120));
    editor.setText(prefix ++ "\u{1f44d}");
    try testing.expectEqual(prefix.len, editor.text().len);
    try testing.expect(std.unicode.utf8ValidateSlice(editor.text()));

    editor.setText("bad\xffhistory");
    try testing.expectEqual(@as(usize, 0), editor.text().len);
}

test "editor control actions map to reader actions" {
    var editor = Editor{};
    try testing.expectEqual(editor_mod.Action.eof, editor.feed(ctrl('d')));
    type_text(&editor, "x");
    try testing.expectEqual(editor_mod.Action.cancel, editor.feed(ctrl('c')));
    try testing.expectEqual(editor_mod.Action.history_prev, editor.feed(special(Key.up)));
    try testing.expectEqual(editor_mod.Action.history_next, editor.feed(special(Key.down)));
    try testing.expectEqual(editor_mod.Action.search, editor.feed(ctrl('r')));
    try testing.expectEqual(editor_mod.Action.clear_screen, editor.feed(ctrl('l')));
    // ctrl+d with text deletes instead of leaving.
    _ = editor.feed(ctrl('a'));
    try testing.expectEqual(editor_mod.Action.redraw, editor.feed(ctrl('d')));
    try testing.expectEqualStrings("", editor.text());
}

test "editor bounds hostile oversized input" {
    var editor = Editor{};
    const big = &@as([4096]u8, @splat(120));
    var remaining: usize = editor_mod.capacity / big.len;
    while (remaining > 0) : (remaining -= 1) {
        _ = editor.insertText(big);
    }
    try testing.expectEqual(editor_mod.capacity, editor.text().len);
    // The buffer is full: further input is refused, never overflowed.
    try testing.expectEqual(editor_mod.Action.none, editor.insertText("y"));
    try testing.expectEqual(editor_mod.capacity, editor.text().len);
}

// ----------------------------------------------------------------------
// Highlighter
// ----------------------------------------------------------------------

fn expectKinds(source: []const u8, expected: []const highlight.Kind) !void {
    var tokenizer = highlight.Tokenizer.init(source);
    var index: usize = 0;
    while (tokenizer.next()) |span| {
        if (span.kind == .text) continue; // skip whitespace runs
        try testing.expect(index < expected.len);
        try testing.expectEqual(expected[index], span.kind);
        index += 1;
    }
    try testing.expectEqual(expected.len, index);
}

test "tokenizer classifies keywords, strings, numbers, comments" {
    try expectKinds("select id from t where b = 'x' -- done", &.{
        .keyword,    .identifier, .keyword, .identifier, .keyword,
        .identifier, .operator,   .string,  .comment,
    });
    try expectKinds("SELECT 42, 0x1f", &.{
        .keyword, .number, .operator, .number,
    });
    try expectKinds(".help me", &.{.dot});
}

test "tokenizer respects doubled quotes and block comments" {
    try expectKinds("'it''s' /* a ; comment */ \"col\"", &.{
        .string, .comment, .identifier,
    });
}

test "tokenizer spans cover the input in order" {
    const source = "select 'a' + 1";
    var tokenizer = highlight.Tokenizer.init(source);
    var position: usize = 0;
    while (tokenizer.next()) |span| {
        try testing.expectEqual(position, span.start);
        position += span.len;
    }
    try testing.expectEqual(source.len, position);
}

test "tokenizer never panics on hostile input" {
    const hostile = [_][]const u8{
        "'",                "''",  "'''", "\"", "/*", "--", "[", "0x", "e-", "'\x00\xff",
        "select '\x1b[31m", "/*/", "]",
    };
    for (hostile) |source| {
        var tokenizer = highlight.Tokenizer.init(source);
        while (tokenizer.next()) |_| {}
    }
}

test "statement completion follows quotes and comments" {
    try testing.expect(!highlight.statementComplete("select 1"));
    try testing.expect(highlight.statementComplete("select 1;"));
    try testing.expect(highlight.statementComplete("select 1; -- trailing"));
    try testing.expect(highlight.statementComplete("select ';';"));
    try testing.expect(!highlight.statementComplete("select ';'"));
    try testing.expect(!highlight.statementComplete("select 'a;"));
    try testing.expect(!highlight.statementComplete("insert into t\nvalues (1)"));
    try testing.expect(highlight.statementComplete("insert into t\nvalues (1);"));
    try testing.expect(highlight.statementComplete("select 'it''s fine';"));
    try testing.expect(!highlight.statementComplete("select 1; /* unfinished"));
    try testing.expect(!highlight.statementComplete("select \"unfinished;"));
    try testing.expect(!highlight.statementComplete("select [unfinished;"));
}

test "keyword matching is case-insensitive and bounded" {
    try testing.expect(highlight.isKeyword("SELECT"));
    try testing.expect(highlight.isKeyword("select"));
    try testing.expect(highlight.isKeyword("Where"));
    try testing.expect(!highlight.isKeyword("selectx"));
    try testing.expect(!highlight.isKeyword(&@as([64]u8, @splat(120))));
}

// ----------------------------------------------------------------------
// History
// ----------------------------------------------------------------------

test "history dedupes, skips secrets, and stays bounded" {
    var history = history_mod.History.init(testing.allocator);
    defer history.deinit();
    try history.append("select 1;");
    try history.append("select 1;");
    try history.append(" secret insert;");
    try history.append("");
    try testing.expectEqual(@as(usize, 1), history.count());
    try history.append("select 2;");
    try testing.expectEqual(@as(usize, 2), history.count());
}

test "history persistence representation stays within its file bound" {
    var history = history_mod.History.init(testing.allocator);
    defer history.deinit();
    const entry = &@as([(8 * 1024)]u8, @splat(92));
    for (0..400) |index| {
        var buffer: [32]u8 = undefined;
        const suffix = try std.fmt.bufPrint(&buffer, "{d}", .{index});
        var value: std.Io.Writer.Allocating = .init(testing.allocator);
        defer value.deinit();
        try value.writer.writeAll(entry);
        try value.writer.writeAll(suffix);
        try history.append(value.written());
    }
    try testing.expect(history.count() < 400);

    var persisted: std.Io.Writer.Allocating = .init(testing.allocator);
    defer persisted.deinit();
    for (0..history.count()) |index| {
        for (history.entry(index)) |byte| {
            if (byte == '\\' or byte == '\n') try persisted.writer.writeAll("\\");
            try persisted.writer.writeAll(&.{byte});
        }
        try persisted.writer.writeAll("\n");
    }
    try testing.expect(persisted.written().len <= 4 * 1024 * 1024);
}

test "history navigation preserves the in-progress line" {
    var history = history_mod.History.init(testing.allocator);
    defer history.deinit();
    try history.append("first;");
    try history.append("second;");

    const back_one = (try history.prev("draft")).?;
    try testing.expectEqualStrings("second;", back_one);
    const back_two = (try history.prev("draft")).?;
    try testing.expectEqualStrings("first;", back_two);
    // Walking past the oldest entry stays on it.
    const clamped = (try history.prev("draft")).?;
    try testing.expectEqualStrings("first;", clamped);

    const forward = history.next().?;
    try testing.expectEqualStrings("second;", forward);
    const restored = history.next().?;
    try testing.expectEqualStrings("draft", restored);
    history.resetNav();
}

test "history reverse search walks matches backward" {
    var history = history_mod.History.init(testing.allocator);
    defer history.deinit();
    try history.append("update t set a = 1;");
    try history.append("select 1;");
    try history.append("update t set a = 2;");

    const newest = history.searchBefore("update", null).?;
    try testing.expectEqualStrings("update t set a = 2;", history.entry(newest));
    const older = history.searchBefore("update", newest).?;
    try testing.expectEqualStrings("update t set a = 1;", history.entry(older));
    try testing.expectEqual(@as(?usize, null), history.searchBefore("update", older));
    try testing.expectEqual(@as(?usize, null), history.searchBefore("drop", null));
}

test "history persists multi-line entries with owner-only permissions" {
    const io = testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &path_buffer);
    const dir_path = path_buffer[0..dir_len];
    const path = try std.fmt.allocPrint(
        testing.allocator,
        "{s}/.zaxon_history",
        .{dir_path},
    );
    defer testing.allocator.free(path);

    var history = history_mod.History.init(testing.allocator);
    defer history.deinit();
    try history.append("select id,\n  body\nfrom notes;");
    try history.append("with a\\b as (select 1) select * from a\\b;");
    try history.save(io, path);

    const stat = try std.Io.Dir.cwd().statFile(io, path, .{});
    try testing.expectEqual(
        @as(u32, 0o600),
        @as(u32, @intCast(@backingInt(stat.permissions) & 0o777)),
    );

    var loaded = history_mod.History.init(testing.allocator);
    defer loaded.deinit();
    try loaded.load(io, path);
    try testing.expectEqual(@as(usize, 2), loaded.count());
    try testing.expectEqualStrings("select id,\n  body\nfrom notes;", loaded.entry(0));
    try testing.expectEqualStrings(
        "with a\\b as (select 1) select * from a\\b;",
        loaded.entry(1),
    );
}

test "history save tightens an existing file and skips malformed records" {
    const io = testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &path_buffer);
    const path = try std.fmt.allocPrint(
        testing.allocator,
        "{s}/.zaxon_history",
        .{path_buffer[0..dir_len]},
    );
    defer testing.allocator.free(path);

    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = "bad\\qrecord\nvalid;\n",
        .flags = .{ .permissions = @fromBackingInt(@intCast(0o644)) },
    });
    var history = history_mod.History.init(testing.allocator);
    defer history.deinit();
    try history.load(io, path);
    try testing.expectEqual(@as(usize, 1), history.count());
    try testing.expectEqualStrings("valid;", history.entry(0));
    try history.save(io, path);

    const stat = try std.Io.Dir.cwd().statFile(io, path, .{});
    try testing.expectEqual(
        @as(u32, 0o600),
        @as(u32, @intCast(@backingInt(stat.permissions) & 0o777)),
    );
}

test "history load tolerates a missing file" {
    var history = history_mod.History.init(testing.allocator);
    defer history.deinit();
    try history.load(testing.io, "/nonexistent/zaxon/history");
    try testing.expectEqual(@as(usize, 0), history.count());
}

// ----------------------------------------------------------------------
// Renderers
// ----------------------------------------------------------------------

const golden_view = view_mod.View{
    .columns = &.{ "id", "author", "body" },
    .rows = &.{
        &.{ "1", "vik", "first note" },
        &.{ "2", null, "replicated note" },
    },
};

fn renderToBuffer(
    buffer: []u8,
    view: view_mod.View,
    options: table.Options,
) ![]const u8 {
    var writer = std.Io.Writer.fixed(buffer);
    _ = try table.write(view, options, &writer);
    return writer.buffered();
}

test "aligned unicode table matches the golden layout" {
    var buffer: [1024]u8 = undefined;
    const output = try renderToBuffer(&buffer, golden_view, .{
        .mode = .table,
        .caps = .{ .color = false, .unicode = true },
    });
    const expected =
        "┌────" ++ "┬────────┬" ++
        "─────────────────┐\n" ++
        "│ id │ author │ body            │\n" ++
        "├────" ++ "┼────────┼" ++
        "─────────────────┤\n" ++
        "│  1 │ vik    │ first note      │\n" ++
        "│  2 │ NULL   │ replicated note │\n" ++
        "└────" ++ "┴────────┴" ++
        "─────────────────┘\n";
    try testing.expectEqualStrings(expected, output);
}

test "aligned ascii table keeps the same geometry" {
    var buffer: [1024]u8 = undefined;
    const output = try renderToBuffer(&buffer, golden_view, .{
        .mode = .table,
        .caps = .{ .color = false, .unicode = false },
    });
    const expected =
        "+----+--------+-----------------+\n" ++
        "| id | author | body            |\n" ++
        "+----+--------+-----------------+\n" ++
        "|  1 | vik    | first note      |\n" ++
        "|  2 | NULL   | replicated note |\n" ++
        "+----+--------+-----------------+\n";
    try testing.expectEqualStrings(expected, output);
}

test "expanded mode prints one block per record" {
    var buffer: [1024]u8 = undefined;
    const output = try renderToBuffer(&buffer, golden_view, .{
        .mode = .expanded,
        .caps = .{ .color = false, .unicode = true },
    });
    const expected =
        "-[ RECORD 1 ]-\n" ++
        "id     | 1\n" ++
        "author | vik\n" ++
        "body   | first note\n" ++
        "-[ RECORD 2 ]-\n" ++
        "id     | 2\n" ++
        "author | NULL\n" ++
        "body   | replicated note\n";
    try testing.expectEqualStrings(expected, output);
}

test "auto mode expands when the table exceeds the terminal" {
    try testing.expect(!table.shouldExpand(golden_view, 80));
    try testing.expect(table.shouldExpand(golden_view, 20));
}

test "aligned tables do not truncate wide SQLite result sets" {
    const columns = try testing.allocator.alloc([]const u8, 257);
    defer testing.allocator.free(columns);
    @memset(columns, "x");
    const view = view_mod.View{ .columns = columns, .rows = &.{} };
    var output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer output.deinit();
    _ = try table.write(view, .{
        .mode = .table,
        .caps = .{ .color = false, .unicode = false },
    }, &output.writer);
    try testing.expectEqual(
        @as(usize, 257),
        std.mem.count(u8, output.written(), "| x "),
    );
}

test "csv output quotes and escapes" {
    const view = view_mod.View{
        .columns = &.{ "a", "b" },
        .rows = &.{
            &.{ "plain", "with,comma" },
            &.{ "quote\"inside", null },
        },
    };
    var buffer: [512]u8 = undefined;
    const output = try renderToBuffer(&buffer, view, .{ .mode = .csv });
    const expected =
        "a,b\n" ++
        "plain,\"with,comma\"\n" ++
        "\"quote\"\"inside\",\n";
    try testing.expectEqualStrings(expected, output);
}

test "csv renders line controls visibly" {
    const view = view_mod.View{
        .columns = &.{"payload"},
        .rows = &.{&.{"first\nsecond\r"}},
    };
    var buffer: [128]u8 = undefined;
    const output = try renderToBuffer(&buffer, view, .{ .mode = .csv });
    try testing.expectEqualStrings("payload\n\"first^Jsecond^M\"\n", output);
}

test "hostile cells cannot inject escape sequences" {
    const view = view_mod.View{
        .columns = &.{"payload"},
        .rows = &.{&.{"\x1b[2J\x07boo"}},
    };
    var buffer: [512]u8 = undefined;
    const output = try renderToBuffer(&buffer, view, .{
        .mode = .table,
        .caps = .{ .color = false, .unicode = false },
    });
    try testing.expect(std.mem.indexOfScalar(u8, output, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, output, 0x07) == null);
    try testing.expect(std.mem.indexOf(u8, output, "^[[2J^Gboo") != null);
}

test "wide characters align by display width" {
    const view = view_mod.View{
        .columns = &.{"name"},
        .rows = &.{ &.{"日本語"}, &.{"ab"} },
    };
    var buffer: [512]u8 = undefined;
    const output = try renderToBuffer(&buffer, view, .{
        .mode = .table,
        .caps = .{ .color = false, .unicode = false },
    });
    const expected =
        "+--------+\n" ++
        "| name   |\n" ++
        "+--------+\n" ++
        "| 日本語 |\n" ++
        "| ab     |\n" ++
        "+--------+\n";
    try testing.expectEqualStrings(expected, output);
}

test "legacy plain table stays byte-identical" {
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try view_mod.writePlainTable(golden_view, &writer);
    const expected =
        "id | author | body\n" ++
        "---+--------+-----\n" ++
        "1 | vik | first note\n" ++
        "2 | NULL | replicated note\n";
    try testing.expectEqualStrings(expected, writer.buffered());
}

// ----------------------------------------------------------------------
// Width math
// ----------------------------------------------------------------------

test "display width counts graphemes and East Asian width" {
    try testing.expectEqual(@as(u16, 5), term.displayWidth("hello"));
    try testing.expectEqual(@as(u16, 6), term.displayWidth("日本語"));
    try testing.expectEqual(@as(u16, 2), term.displayWidth("\u{1F44D}"));
}

test "sanitized width counts caret escapes" {
    try testing.expectEqual(@as(u16, 2), table.sanitizedWidth("\x1b"));
    try testing.expectEqual(@as(u16, 6), table.sanitizedWidth("a\x07b\x7f"));
}
