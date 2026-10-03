//! The pure line-editor state machine (ZDS 0005, M2).
//!
//! Owns the input buffer and cursor and nothing else: it never touches a
//! file descriptor, so every editing behavior is testable from key
//! sequences alone. The shell loop owns all I/O and repaints from the
//! state exposed here. The cursor always rests on a grapheme boundary.

const std = @import("std");
const term = @import("term.zig");

const Key = term.Key;

/// Matches the shell's historical bounded input line.
pub const capacity = 64 * 1024;

/// What the shell loop should do after feeding one key.
pub const Action = enum {
    none,
    redraw,
    submit,
    cancel,
    eof,
    history_prev,
    history_next,
    search,
    clear_screen,
};

pub const Editor = struct {
    buffer: [capacity]u8 = undefined,
    len: usize = 0,
    cursor: usize = 0,
    yank_buffer: [capacity]u8 = undefined,
    yank_len: usize = 0,

    pub fn text(self: *const Editor) []const u8 {
        return self.buffer[0..self.len];
    }

    pub fn clear(self: *Editor) void {
        self.len = 0;
        self.cursor = 0;
    }

    /// Replaces the buffer (history recall). Oversized text is truncated at
    /// the capacity without splitting UTF-8; invalid UTF-8 is rejected so the
    /// cursor invariant remains true.
    pub fn setText(self: *Editor, new_text: []const u8) void {
        var n = @min(new_text.len, capacity);
        while (n > 0 and n < new_text.len and
            new_text[n] & 0xc0 == 0x80)
        {
            n -= 1;
        }
        if (!std.unicode.utf8ValidateSlice(new_text[0..n])) {
            self.clear();
            return;
        }
        @memcpy(self.buffer[0..n], new_text[0..n]);
        self.len = n;
        self.cursor = n;
    }

    /// One key, one action: the flat dispatch required by the style guide.
    /// Every arm is a single editing operation.
    pub fn feed(self: *Editor, key: Key) Action {
        if (key.matches(Key.enter, .{})) return .submit;
        // ctrl+j is accept-line in readline; raw mode delivers a bare
        // newline this way, which also keeps piped PTY input working.
        if (key.matches('j', .{ .ctrl = true })) return .submit;
        if (key.matches('c', .{ .ctrl = true })) return .cancel;
        if (key.matches('d', .{ .ctrl = true })) {
            if (self.len == 0) return .eof;
            return self.deleteAtCursor();
        }
        if (key.matches(Key.up, .{}) or key.matches('p', .{ .ctrl = true }))
            return .history_prev;
        if (key.matches(Key.down, .{}) or key.matches('n', .{ .ctrl = true }))
            return .history_next;
        if (key.matches('r', .{ .ctrl = true })) return .search;
        if (key.matches('l', .{ .ctrl = true })) return .clear_screen;
        if (key.matches(Key.left, .{}) or key.matches('b', .{ .ctrl = true }))
            return self.moveLeft();
        if (key.matches(Key.right, .{}) or key.matches('f', .{ .ctrl = true }))
            return self.moveRight();
        if (key.matches(Key.home, .{}) or key.matches('a', .{ .ctrl = true }))
            return self.moveHome();
        if (key.matches(Key.end, .{}) or key.matches('e', .{ .ctrl = true }))
            return self.moveEnd();
        if (key.matches('b', .{ .alt = true })) return self.moveWordLeft();
        if (key.matches('f', .{ .alt = true })) return self.moveWordRight();
        if (key.matches(Key.backspace, .{})) return self.backspace();
        if (key.matches(Key.delete, .{})) return self.deleteAtCursor();
        if (key.matches('w', .{ .ctrl = true })) return self.killPrevWord();
        if (key.matches('u', .{ .ctrl = true })) return self.killToStart();
        if (key.matches('k', .{ .ctrl = true })) return self.killToEnd();
        if (key.matches('y', .{ .ctrl = true })) return self.yank();
        if (isTextKey(key)) return self.insertText(key.text.?);
        return .none;
    }

    /// Printable input: a key with text and no chord modifiers. Control and
    /// alt chords never insert; special codepoints carry no text.
    fn isTextKey(key: Key) bool {
        const key_text = key.text orelse return false;
        if (key_text.len == 0) return false;
        return !key.mods.ctrl and !key.mods.alt and !key.mods.super and
            !key.mods.hyper and !key.mods.meta;
    }

    pub fn insertText(self: *Editor, bytes: []const u8) Action {
        if (!std.unicode.utf8ValidateSlice(bytes)) return .none;
        if (self.len + bytes.len > capacity) return .none;
        std.mem.copyBackwards(
            u8,
            self.buffer[self.cursor + bytes.len .. self.len + bytes.len],
            self.buffer[self.cursor..self.len],
        );
        @memcpy(self.buffer[self.cursor .. self.cursor + bytes.len], bytes);
        std.debug.assert(self.len < capacity);
        self.len += bytes.len;
        self.cursor += bytes.len;
        std.debug.assert(self.len <= capacity);
        return .redraw;
    }

    fn backspace(self: *Editor) Action {
        if (self.cursor == 0) return .none;
        const start = prevBoundary(self.text(), self.cursor);
        self.removeRange(start, self.cursor);
        self.cursor = start;
        return .redraw;
    }

    fn deleteAtCursor(self: *Editor) Action {
        if (self.cursor >= self.len) return .none;
        const end = nextBoundary(self.text(), self.cursor);
        self.removeRange(self.cursor, end);
        return .redraw;
    }

    fn moveLeft(self: *Editor) Action {
        if (self.cursor == 0) return .none;
        self.cursor = prevBoundary(self.text(), self.cursor);
        return .redraw;
    }

    fn moveRight(self: *Editor) Action {
        if (self.cursor >= self.len) return .none;
        self.cursor = nextBoundary(self.text(), self.cursor);
        return .redraw;
    }

    fn moveHome(self: *Editor) Action {
        if (self.cursor == 0) return .none;
        self.cursor = 0;
        return .redraw;
    }

    fn moveEnd(self: *Editor) Action {
        if (self.cursor >= self.len) return .none;
        self.cursor = self.len;
        return .redraw;
    }

    fn moveWordLeft(self: *Editor) Action {
        if (self.cursor == 0) return .none;
        self.cursor = prevWordStart(self.text(), self.cursor);
        return .redraw;
    }

    fn moveWordRight(self: *Editor) Action {
        if (self.cursor >= self.len) return .none;
        self.cursor = nextWordEnd(self.text(), self.cursor);
        return .redraw;
    }

    fn killPrevWord(self: *Editor) Action {
        if (self.cursor == 0) return .none;
        const start = prevWordStart(self.text(), self.cursor);
        self.rememberKill(start, self.cursor);
        self.removeRange(start, self.cursor);
        self.cursor = start;
        return .redraw;
    }

    fn killToStart(self: *Editor) Action {
        if (self.cursor == 0) return .none;
        self.rememberKill(0, self.cursor);
        self.removeRange(0, self.cursor);
        self.cursor = 0;
        return .redraw;
    }

    fn killToEnd(self: *Editor) Action {
        if (self.cursor >= self.len) return .none;
        self.rememberKill(self.cursor, self.len);
        self.len = self.cursor;
        return .redraw;
    }

    fn yank(self: *Editor) Action {
        if (self.yank_len == 0) return .none;
        return self.insertText(self.yank_buffer[0..self.yank_len]);
    }

    fn rememberKill(self: *Editor, start: usize, end: usize) void {
        std.debug.assert(start <= end and end <= self.len);
        std.debug.assert(self.yank_len <= capacity);
        self.yank_len = end - start;
        std.debug.assert(self.yank_len <= capacity);
        @memcpy(self.yank_buffer[0..self.yank_len], self.buffer[start..end]);
    }

    fn removeRange(self: *Editor, start: usize, end: usize) void {
        std.debug.assert(start <= end and end <= self.len);
        std.mem.copyForwards(
            u8,
            self.buffer[start .. self.len - (end - start)],
            self.buffer[end..self.len],
        );
        std.debug.assert(self.len <= capacity);
        self.len -= end - start;
        std.debug.assert(self.cursor <= capacity and self.len <= capacity);
    }
};

/// The grapheme boundary at or before `index`, scanning from the start.
/// One bounded pass over at most 64 KiB per keystroke; no incremental
/// index is worth the state it would add.
pub fn prevBoundary(bytes: []const u8, index: usize) usize {
    var iterator = term.GraphemeIterator.init(bytes);
    var previous: usize = 0;
    while (iterator.next()) |grapheme| {
        if (grapheme.start + grapheme.len >= index) return grapheme.start;
        previous = grapheme.start + grapheme.len;
    }
    return previous;
}

/// The grapheme boundary strictly after `index`.
pub fn nextBoundary(bytes: []const u8, index: usize) usize {
    var iterator = term.GraphemeIterator.init(bytes);
    while (iterator.next()) |grapheme| {
        const end = grapheme.start + grapheme.len;
        if (end > index) return end;
    }
    return bytes.len;
}

fn isWordByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_' or byte >= 0x80;
}

fn prevWordStart(bytes: []const u8, index: usize) usize {
    var position = index;
    while (position > 0 and !isWordByte(bytes[position - 1])) position -= 1;
    while (position > 0 and isWordByte(bytes[position - 1])) position -= 1;
    return position;
}

fn nextWordEnd(bytes: []const u8, index: usize) usize {
    var position = index;
    while (position < bytes.len and !isWordByte(bytes[position])) position += 1;
    while (position < bytes.len and isWordByte(bytes[position])) position += 1;
    return position;
}
