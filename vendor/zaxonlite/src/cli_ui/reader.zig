//! The interactive line reader (ZDS 0005; shared CLI extraction).
//!
//! Owns one edited line: raw-mode entry and exit around the edit, repaint
//! per keystroke with SQL highlighting, history navigation, `ctrl+r`
//! reverse incremental search, and bracketed paste. The caller supplies
//! the prompt text per call and owns everything above the line — statement
//! accumulation, dot commands, execution, and rendering. Results and
//! diagnostics always print in cooked mode: `readLine` returns with raw
//! mode suspended on every path.

const std = @import("std");
const term_mod = @import("term.zig");
const editor_mod = @import("editor.zig");
const history_mod = @import("history.zig");
const highlight = @import("highlight.zig");
const table = @import("table.zig");

const Key = term_mod.Key;

pub const LineReader = struct {
    gpa: std.mem.Allocator,
    terminal: *term_mod.Term,
    history: *history_mod.History,
    editor: editor_mod.Editor = .{},
    /// When true (the default) the edited line repaints through the SQL
    /// tokenizer; when false it repaints sanitized but unstyled.
    highlight_sql: bool = true,
    painted_cursor_row: u16 = 0,

    pub const Error = error{
        OutOfMemory,
        WriteFailed,
        ReadFailed,
        TtyUnavailable,
    };

    /// How one `readLine` call ended. On `.submitted` the line is in
    /// `text()`; `.canceled` (`ctrl+c`) cleared the editor and left history
    /// navigation, and the caller should discard any accumulated statement;
    /// `.eof` (`ctrl+d` on an empty line, or a closed terminal) ends the
    /// session.
    pub const Outcome = enum { submitted, canceled, eof };

    /// The submitted line. Valid until the next `readLine` call.
    pub fn text(self: *const LineReader) []const u8 {
        return self.editor.text();
    }

    /// Forgets the painted-row state after the caller printed to the
    /// terminal outside the reader (banners, results between lines).
    pub fn resetPaint(self: *LineReader) void {
        self.painted_cursor_row = 0;
    }

    /// Edits one line in raw mode. On return the terminal is back in
    /// cooked mode on every path.
    pub fn readLine(self: *LineReader, prompt: []const u8) Error!Outcome {
        const terminal = self.terminal;
        terminal.resumeRaw() catch return error.TtyUnavailable;
        var raw_active = true;
        defer if (raw_active) terminal.suspendRaw() catch {};
        self.editor.clear();
        self.painted_cursor_row = 0;
        try self.paint(prompt);
        var paste_buffer: [editor_mod.capacity]u8 = undefined;
        var paste_len: usize = 0;
        var paste_overflow = false;
        var pasting = false;

        while (true) {
            const event = terminal.nextEvent() catch |err| switch (err) {
                error.EndOfStream => {
                    terminal.suspendRaw() catch return error.TtyUnavailable;
                    raw_active = false;
                    return .eof;
                },
                else => return error.ReadFailed,
            };
            switch (event) {
                .key_press => |key| {
                    if (pasting) {
                        if (pastedKeyBytes(key)) |bytes| {
                            if (paste_len + bytes.len <= paste_buffer.len) {
                                @memcpy(
                                    paste_buffer[paste_len .. paste_len + bytes.len],
                                    bytes,
                                );
                                paste_len += bytes.len;
                            } else {
                                paste_overflow = true;
                            }
                        }
                        continue;
                    }
                    if (try self.handleAction(prompt, self.editor.feed(key))) |outcome| {
                        terminal.suspendRaw() catch return error.TtyUnavailable;
                        raw_active = false;
                        return outcome;
                    }
                },
                .paste_start => {
                    pasting = true;
                    paste_len = 0;
                    paste_overflow = false;
                },
                .paste_end => {
                    if (pasting and !paste_overflow) {
                        _ = self.editor.insertText(paste_buffer[0..paste_len]);
                    }
                    pasting = false;
                    try self.paint(prompt);
                },
                .paste => |bytes| {
                    defer self.gpa.free(bytes);
                    _ = self.editor.insertText(bytes);
                    try self.paint(prompt);
                },
                .winsize => try self.paint(prompt),
                else => {},
            }
        }
    }

    fn handleAction(
        self: *LineReader,
        prompt: []const u8,
        action: editor_mod.Action,
    ) Error!?Outcome {
        const terminal = self.terminal;
        switch (action) {
            .none => return null,
            .redraw => try self.paint(prompt),
            .submit => {
                try finishLine(terminal);
                return .submitted;
            },
            .cancel => {
                terminal.writer().writeAll("^C") catch return error.WriteFailed;
                try finishLine(terminal);
                self.editor.clear();
                self.history.resetNav();
                self.painted_cursor_row = 0;
                return .canceled;
            },
            .eof => {
                try finishLine(terminal);
                return .eof;
            },
            .history_prev => {
                const recalled = self.history.prev(self.editor.text()) catch
                    return error.OutOfMemory;
                if (recalled) |recalled_text| {
                    self.editor.setText(recalled_text);
                    try self.paint(prompt);
                }
            },
            .history_next => {
                if (self.history.next()) |next_text| {
                    self.editor.setText(next_text);
                    try self.paint(prompt);
                }
            },
            .search => {
                try self.runSearch();
                try self.paint(prompt);
            },
            .clear_screen => {
                terminal.writer().writeAll("\x1b[2J\x1b[H") catch
                    return error.WriteFailed;
                self.painted_cursor_row = 0;
                try self.paint(prompt);
            },
        }
        return null;
    }

    /// Repaints the edited line: return to the paint origin, clear, write
    /// the prompt and the highlighted buffer, then park the cursor. The
    /// simplest correct strategy — full repaint per keystroke — keeps the
    /// math easy to verify; wrapped lines are handled by tracking the
    /// cursor's row.
    fn paint(self: *LineReader, prompt: []const u8) Error!void {
        const terminal = self.terminal;
        const out = terminal.writer();
        const width = terminal.width();
        const style = term_mod.Style{ .color = terminal.caps.color };
        const prompt_width = table.sanitizedWidth(prompt);
        const line = self.editor.text();

        out.writeAll("\r") catch return error.WriteFailed;
        if (self.painted_cursor_row > 0) {
            out.print("\x1b[{d}A", .{self.painted_cursor_row}) catch
                return error.WriteFailed;
        }
        out.writeAll("\x1b[J") catch return error.WriteFailed;

        style.write(out, term_mod.Style.bold) catch return error.WriteFailed;
        out.writeAll(prompt) catch return error.WriteFailed;
        style.write(out, term_mod.Style.reset) catch return error.WriteFailed;
        if (self.highlight_sql) {
            writeHighlighted(out, line, style) catch return error.WriteFailed;
        } else {
            table.writeSanitized(out, line) catch return error.WriteFailed;
        }

        const total = prompt_width +| table.sanitizedWidth(line);
        const before = prompt_width +|
            table.sanitizedWidth(line[0..self.editor.cursor]);
        const end_row = total / width;
        const cursor_row = before / width;
        const cursor_col = before % width;
        if (end_row > cursor_row) {
            out.print("\x1b[{d}A", .{end_row - cursor_row}) catch
                return error.WriteFailed;
        }
        out.print("\r\x1b[{d}G", .{cursor_col + 1}) catch return error.WriteFailed;
        self.painted_cursor_row = cursor_row;
        out.flush() catch return error.WriteFailed;
    }

    /// `ctrl+r` reverse incremental search: a bounded sub-mode of the
    /// editor. Accepting copies the match into the editor; cancel restores
    /// nothing.
    fn runSearch(self: *LineReader) Error!void {
        const terminal = self.terminal;
        const out = terminal.writer();
        var query: [256]u8 = undefined;
        var query_len: usize = 0;
        var match: ?usize = null;

        while (true) {
            const match_text: []const u8 =
                if (match) |index| self.history.entry(index) else "";
            out.writeAll("\r\x1b[J(reverse-i-search)`") catch
                return error.WriteFailed;
            table.writeSanitized(out, query[0..query_len]) catch
                return error.WriteFailed;
            out.writeAll("': ") catch return error.WriteFailed;
            table.writeSanitized(out, match_text) catch return error.WriteFailed;
            out.flush() catch return error.WriteFailed;

            const event = terminal.nextEvent() catch return error.ReadFailed;
            const key = switch (event) {
                .key_press => |key| key,
                .paste => |bytes| {
                    self.gpa.free(bytes);
                    continue;
                },
                else => continue,
            };
            if (key.matches(Key.enter, .{}) or key.matches('j', .{ .ctrl = true })) {
                if (match) |index| self.editor.setText(self.history.entry(index));
                return;
            }
            if (key.matches(Key.escape, .{}) or key.matches('g', .{ .ctrl = true }) or
                key.matches('c', .{ .ctrl = true }))
            {
                return;
            }
            if (key.matches('r', .{ .ctrl = true })) {
                match = self.history.searchBefore(query[0..query_len], match) orelse
                    match;
                continue;
            }
            if (key.matches(Key.backspace, .{})) {
                if (query_len > 0) {
                    query_len = editor_mod.prevBoundary(query[0..query_len], query_len);
                    match = self.history.searchBefore(query[0..query_len], null);
                }
                continue;
            }
            const key_text = key.text orelse continue;
            if (key.mods.ctrl or key.mods.alt) continue;
            if (query_len + key_text.len > query.len) continue;
            @memcpy(query[query_len .. query_len + key_text.len], key_text);
            query_len += key_text.len;
            match = self.history.searchBefore(query[0..query_len], null);
        }
    }
};

fn pastedKeyBytes(key: Key) ?[]const u8 {
    if (key.matches(Key.enter, .{}) or key.matches('j', .{ .ctrl = true })) {
        return "\n";
    }
    if (key.matches(Key.tab, .{})) return "\t";
    return key.text;
}

fn finishLine(terminal: *term_mod.Term) LineReader.Error!void {
    terminal.writer().writeAll("\r\n") catch return error.WriteFailed;
    terminal.writer().flush() catch return error.WriteFailed;
}

fn writeHighlighted(
    out: *std.Io.Writer,
    text: []const u8,
    style: term_mod.Style,
) !void {
    var tokenizer = highlight.Tokenizer.init(text);
    while (tokenizer.next()) |span| {
        const sequence: ?[]const u8 = switch (span.kind) {
            .keyword => term_mod.Style.fg_keyword,
            .string => term_mod.Style.fg_string,
            .number => term_mod.Style.fg_number,
            .comment => term_mod.Style.fg_comment,
            .dot => term_mod.Style.fg_dot,
            .text, .identifier, .operator => null,
        };
        if (sequence) |escape| try style.write(out, escape);
        try table.writeSanitized(out, span.bytes(text));
        if (sequence != null) try style.write(out, term_mod.Style.reset);
    }
}
