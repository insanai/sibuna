//! The minimal alternate-screen pager (ZDS 0005, M5; shared CLI
//! extraction): arrows and page keys scroll, `q` returns. Renders from
//! already-materialized text; lines wider than the terminal are truncated
//! by display width. Raw mode is entered for the pager's lifetime and
//! restored on every path.

const std = @import("std");
const term_mod = @import("term.zig");
const table = @import("table.zig");

const Key = term_mod.Key;

pub const Error = error{ WriteFailed, ReadFailed, TtyUnavailable };

pub fn page(
    gpa: std.mem.Allocator,
    terminal: *term_mod.Term,
    text: []const u8,
) Error!void {
    const out = terminal.writer();
    terminal.resumeRaw() catch return error.TtyUnavailable;
    var raw_active = true;
    defer if (raw_active) terminal.suspendRaw() catch {};

    var line_count: usize = 0;
    var lines_iterator = std.mem.splitScalar(u8, text, '\n');
    while (lines_iterator.next()) |_| line_count += 1;

    var top: usize = 0;
    out.writeAll("\x1b[?1049h") catch return error.WriteFailed;
    defer {
        out.writeAll("\x1b[?1049l") catch {};
        out.flush() catch {};
    }

    while (true) {
        const height: usize = @max(terminal.height(), 2) - 1;
        const width = terminal.width();
        const max_top = line_count -| height;
        top = @min(top, max_top);

        try renderFrame(terminal, text, top, height, width, line_count);

        const event = terminal.nextEvent() catch return error.ReadFailed;
        const key = switch (event) {
            .key_press => |key| key,
            .paste => |bytes| {
                gpa.free(bytes);
                continue;
            },
            .winsize => continue,
            else => continue,
        };
        if (key.matches('q', .{}) or key.matches(Key.escape, .{}) or
            key.matches('c', .{ .ctrl = true }))
        {
            terminal.suspendRaw() catch return error.TtyUnavailable;
            raw_active = false;
            return;
        }
        if (key.matches(Key.up, .{}) or key.matches('k', .{})) {
            top -|= 1;
        } else if (key.matches(Key.down, .{}) or key.matches('j', .{}) or
            key.matches(Key.enter, .{}))
        {
            top = @min(top + 1, max_top);
        } else if (key.matches(Key.page_up, .{}) or key.matches('b', .{})) {
            top -|= height;
        } else if (key.matches(Key.page_down, .{}) or
            key.matches(' ', .{}) or key.matches('f', .{ .ctrl = true }))
        {
            top = @min(top + height, max_top);
        } else if (key.matches('g', .{})) {
            top = 0;
        } else if (key.matches('G', .{ .shift = true }) or key.matches('G', .{})) {
            top = max_top;
        }
    }
}

fn renderFrame(
    terminal: *term_mod.Term,
    text: []const u8,
    top: usize,
    height: usize,
    width: u16,
    line_count: usize,
) Error!void {
    const out = terminal.writer();
    out.writeAll("\x1b[H\x1b[J") catch return error.WriteFailed;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var index: usize = 0;
    var shown: usize = 0;
    while (lines.next()) |line| : (index += 1) {
        if (index < top) continue;
        if (shown == height) break;
        try writeTruncated(out, line, width);
        out.writeAll("\r\n") catch return error.WriteFailed;
        shown += 1;
    }
    const style = term_mod.Style{ .color = terminal.caps.color };
    style.write(out, term_mod.Style.dim) catch return error.WriteFailed;
    out.print(
        "-- line {d}-{d} of {d} (q quit, arrows/space scroll) --",
        .{ top + 1, @min(top + height, line_count), line_count },
    ) catch return error.WriteFailed;
    style.write(out, term_mod.Style.reset) catch return error.WriteFailed;
    out.flush() catch return error.WriteFailed;
}

fn writeTruncated(out: *std.Io.Writer, line: []const u8, width: u16) Error!void {
    if (table.sanitizedWidth(line) <= width) {
        table.writeSanitized(out, line) catch return error.WriteFailed;
        return;
    }
    var written: u32 = 0;
    var iterator = term_mod.GraphemeIterator.init(line);
    while (iterator.next()) |grapheme| {
        const bytes = grapheme.bytes(line);
        const grapheme_width = table.sanitizedWidth(bytes);
        if (written + grapheme_width >= width) break;
        table.writeSanitized(out, bytes) catch return error.WriteFailed;
        written += grapheme_width;
    }
    out.writeAll("\u{2026}") catch return error.WriteFailed;
}
