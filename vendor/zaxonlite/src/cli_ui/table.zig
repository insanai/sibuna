//! The rich result renderer (ZDS 0005, M4).
//!
//! Data-width column alignment, Unicode or ASCII rules, styled headers and
//! NULLs, an expanded per-record mode, and CSV output. Every cell passes
//! through sanitization before it reaches the terminal: query results are
//! untrusted bytes, and a hostile row must not be able to inject escape
//! sequences into an operator's session. The legacy unaligned format used
//! by scripts lives in `view.zig` and is not touched here.

const std = @import("std");
const term = @import("term.zig");
const view_mod = @import("view.zig");

pub const View = view_mod.View;

pub const Mode = enum {
    table,
    expanded,
    auto,
    json,
    csv,

    pub fn parse(text: []const u8) ?Mode {
        return std.meta.stringToEnum(Mode, text);
    }
};

const null_text = "NULL";

/// Caret notation for C0 controls and DEL: `ESC` renders as `^[`, so the
/// byte is visible instead of interpreted. This is the escape-injection
/// control and applies in every mode, including CSV.
fn isControlByte(byte: u8) bool {
    return byte < 0x20 or byte == 0x7f;
}

pub fn writeSanitized(out: *std.Io.Writer, bytes: []const u8) !void {
    for (bytes) |byte| {
        if (isControlByte(byte)) {
            try out.writeAll(&.{ '^', byte ^ 0x40 });
        } else {
            try out.writeAll(&.{byte});
        }
    }
}

pub fn sanitizedWidth(bytes: []const u8) u16 {
    var width: u16 = 0;
    var start: usize = 0;
    for (bytes, 0..) |byte, index| {
        if (!isControlByte(byte)) continue;
        width +|= term.displayWidth(bytes[start..index]) +| 2;
        start = index + 1;
    }
    return width +| term.displayWidth(bytes[start..]);
}

fn cellWidth(cell: ?[]const u8) u16 {
    return sanitizedWidth(cell orelse null_text);
}

fn cellNumeric(cell: []const u8) bool {
    if (cell.len == 0) return false;
    _ = std.fmt.parseFloat(f64, cell) catch return false;
    return true;
}

// SQLite's default and compiled-in maximum. Keeping the fixed layout at the
// database bound avoids allocation while never silently dropping valid result
// columns (the former 256-column cap did exactly that).
const max_columns = 2000;

const Layout = struct {
    widths: [max_columns]u16,
    numeric: [max_columns]bool,
    column_count: usize,

    fn measure(view: View) Layout {
        var layout = Layout{
            .widths = @splat(0),
            .numeric = @splat(true),
            .column_count = view.columns.len,
        };
        std.debug.assert(layout.column_count <= max_columns);
        for (view.columns[0..layout.column_count], 0..) |column, index| {
            layout.widths[index] = sanitizedWidth(column);
        }
        for (view.rows) |row| {
            for (row, 0..) |cell, index| {
                if (index >= layout.column_count) break;
                layout.widths[index] = @max(layout.widths[index], cellWidth(cell));
                if (cell) |text| {
                    if (!cellNumeric(text)) layout.numeric[index] = false;
                }
            }
        }
        return layout;
    }

    fn totalWidth(self: *const Layout) u32 {
        // Border glyph + per-column " cell |".
        var total: u32 = 1;
        for (self.widths[0..self.column_count]) |width| {
            total += @as(u32, width) + 3;
        }
        return total;
    }
};

/// Whether `auto` mode should fall back to the expanded per-record layout.
pub fn shouldExpand(view: View, terminal_width: u16) bool {
    if (view.columns.len > max_columns) return true;
    const layout = Layout.measure(view);
    return layout.totalWidth() > terminal_width;
}

const Rules = struct {
    top_left: []const u8,
    top_join: []const u8,
    top_right: []const u8,
    mid_left: []const u8,
    mid_join: []const u8,
    mid_right: []const u8,
    bottom_left: []const u8,
    bottom_join: []const u8,
    bottom_right: []const u8,
    horizontal: []const u8,
    vertical: []const u8,

    const unicode = Rules{
        .top_left = "┌",
        .top_join = "┬",
        .top_right = "┐",
        .mid_left = "├",
        .mid_join = "┼",
        .mid_right = "┤",
        .bottom_left = "└",
        .bottom_join = "┴",
        .bottom_right = "┘",
        .horizontal = "─",
        .vertical = "│",
    };

    const ascii = Rules{
        .top_left = "+",
        .top_join = "+",
        .top_right = "+",
        .mid_left = "+",
        .mid_join = "+",
        .mid_right = "+",
        .bottom_left = "+",
        .bottom_join = "+",
        .bottom_right = "+",
        .horizontal = "-",
        .vertical = "|",
    };
};

pub const Options = struct {
    mode: Mode = .auto,
    caps: term.Caps = .{ .color = false, .unicode = false },
    terminal_width: u16 = 80,
};

/// Renders a result view in the selected mode. `auto` resolves to `table`
/// or `expanded` from the measured width. Returns the number of data rows.
pub fn write(view: View, options: Options, out: *std.Io.Writer) !usize {
    const mode: Mode = switch (options.mode) {
        .auto => if (shouldExpand(view, options.terminal_width))
            Mode.expanded
        else
            Mode.table,
        else => options.mode,
    };
    switch (mode) {
        .table => {
            if (view.columns.len > max_columns) return error.TooManyColumns;
            try writeAligned(view, options, out);
        },
        .expanded => try writeExpanded(view, options, out),
        .csv => try writeCsv(view, out),
        .json => try view_mod.writeJsonResult(view, out),
        .auto => unreachable,
    }
    return view.rows.len;
}

fn writeAligned(view: View, options: Options, out: *std.Io.Writer) !void {
    const layout = Layout.measure(view);
    const rules = if (options.caps.unicode) Rules.unicode else Rules.ascii;
    const style = term.Style{ .color = options.caps.color };

    try writeRule(&layout, rules, rules.top_left, rules.top_join, rules.top_right, out);
    try out.writeAll(rules.vertical);
    for (view.columns[0..layout.column_count], 0..) |column, index| {
        try out.writeAll(" ");
        try style.write(out, term.Style.bold);
        try writeSanitized(out, column);
        try style.write(out, term.Style.reset);
        try writePadding(out, layout.widths[index] - sanitizedWidth(column));
        try out.writeAll(" ");
        try out.writeAll(rules.vertical);
    }
    try out.writeAll("\n");
    try writeRule(&layout, rules, rules.mid_left, rules.mid_join, rules.mid_right, out);

    for (view.rows) |row| {
        try out.writeAll(rules.vertical);
        for (0..layout.column_count) |index| {
            const cell: ?[]const u8 = if (index < row.len) row[index] else null;
            try out.writeAll(" ");
            try writeCell(cell, layout.widths[index], layout.numeric[index], style, out);
            try out.writeAll(" ");
            try out.writeAll(rules.vertical);
        }
        try out.writeAll("\n");
    }
    try writeRule(&layout, rules, rules.bottom_left, rules.bottom_join, rules.bottom_right, out);
}

fn writeCell(
    cell: ?[]const u8,
    width: u16,
    numeric: bool,
    style: term.Style,
    out: *std.Io.Writer,
) !void {
    const text = cell orelse null_text;
    const pad = width - cellWidth(cell);
    if (numeric) try writePadding(out, pad);
    if (cell == null) {
        try style.write(out, term.Style.dim);
        try out.writeAll(null_text);
        try style.write(out, term.Style.reset);
    } else {
        try writeSanitized(out, text);
    }
    if (!numeric) try writePadding(out, pad);
}

fn writeRule(
    layout: *const Layout,
    rules: Rules,
    left: []const u8,
    join: []const u8,
    right: []const u8,
    out: *std.Io.Writer,
) !void {
    try out.writeAll(left);
    for (layout.widths[0..layout.column_count], 0..) |width, index| {
        if (index > 0) try out.writeAll(join);
        for (0..@as(u32, width) + 2) |_| try out.writeAll(rules.horizontal);
    }
    try out.writeAll(right);
    try out.writeAll("\n");
}

fn writePadding(out: *std.Io.Writer, count: u16) !void {
    for (0..count) |_| try out.writeAll(" ");
}

/// The `psql \x` answer to wide rows: one block per record.
fn writeExpanded(view: View, options: Options, out: *std.Io.Writer) !void {
    const style = term.Style{ .color = options.caps.color };
    var name_width: u16 = 0;
    for (view.columns) |column| {
        name_width = @max(name_width, sanitizedWidth(column));
    }
    for (view.rows, 1..) |row, record| {
        try style.write(out, term.Style.dim);
        try out.print("-[ RECORD {d} ]-\n", .{record});
        try style.write(out, term.Style.reset);
        for (view.columns, 0..) |column, index| {
            try style.write(out, term.Style.bold);
            try writeSanitized(out, column);
            try style.write(out, term.Style.reset);
            try writePadding(out, name_width - sanitizedWidth(column));
            try out.writeAll(" | ");
            const cell: ?[]const u8 = if (index < row.len) row[index] else null;
            if (cell) |text| {
                try writeSanitized(out, text);
            } else {
                try style.write(out, term.Style.dim);
                try out.writeAll(null_text);
                try style.write(out, term.Style.reset);
            }
            try out.writeAll("\n");
        }
    }
}

fn writeCsv(view: View, out: *std.Io.Writer) !void {
    try writeCsvRow(view.columns, out);
    for (view.rows) |row| {
        for (row, 0..) |cell, index| {
            if (index > 0) try out.writeAll(",");
            if (cell) |text| try writeCsvField(text, out);
        }
        try out.writeAll("\n");
    }
}

fn writeCsvRow(fields: []const []const u8, out: *std.Io.Writer) !void {
    for (fields, 0..) |field, index| {
        if (index > 0) try out.writeAll(",");
        try writeCsvField(field, out);
    }
    try out.writeAll("\n");
}

fn writeCsvField(text: []const u8, out: *std.Io.Writer) !void {
    const quote = std.mem.indexOfAny(u8, text, ",\"\n\r") != null;
    if (!quote) {
        try writeSanitized(out, text);
        return;
    }
    try out.writeAll("\"");
    for (text) |byte| {
        if (byte == '"') {
            try out.writeAll("\"\"");
        } else if (isControlByte(byte)) {
            try out.writeAll(&.{ '^', byte ^ 0x40 });
        } else {
            try out.writeAll(&.{byte});
        }
    }
    try out.writeAll("\"");
}
