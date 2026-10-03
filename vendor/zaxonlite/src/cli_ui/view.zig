//! The neutral query-result view and its plain writers (ZDS 0005; shared
//! CLI extraction).
//!
//! `View` is the domain-free shape both products render: column names and
//! rows of optional text cells. The writers here are the byte-exact legacy
//! formats used by scripts and contract tests; the rich aligned formats
//! live in `table.zig`. Nothing in this file knows where a result came
//! from — callers build a `View` from their own result types.

const std = @import("std");

/// A borrowed view of a query result. Cells are `null` for SQL NULL;
/// everything else is text.
pub const View = struct {
    columns: []const []const u8,
    rows: []const []const ?[]const u8,
};

/// The legacy unaligned table: header-width rules, no alignment. Kept
/// byte-identical for scripts and the non-TTY shell fallback.
pub fn writePlainTable(view: View, out: *std.Io.Writer) !void {
    for (view.columns, 0..) |column, index| {
        if (index > 0) try out.writeAll(" | ");
        try out.writeAll(column);
    }
    try out.writeAll("\n");
    for (view.columns, 0..) |column, index| {
        if (index > 0) try out.writeAll("-+-");
        for (0..column.len) |_| try out.writeAll("-");
    }
    try out.writeAll("\n");
    for (view.rows) |row| {
        for (row, 0..) |cell, index| {
            if (index > 0) try out.writeAll(" | ");
            try out.writeAll(cell orelse "NULL");
        }
        try out.writeAll("\n");
    }
}

pub fn writeJsonResult(view: View, out: *std.Io.Writer) !void {
    try out.writeAll("{\"columns\":[");
    for (view.columns, 0..) |column, index| {
        if (index > 0) try out.writeAll(",");
        try writeJsonString(out, column);
    }
    try out.writeAll("],\"rows\":[");
    for (view.rows, 0..) |row, row_index| {
        if (row_index > 0) try out.writeAll(",");
        try out.writeAll("[");
        for (row, 0..) |cell, index| {
            if (index > 0) try out.writeAll(",");
            if (cell) |text| {
                try writeJsonString(out, text);
            } else {
                try out.writeAll("null");
            }
        }
        try out.writeAll("]");
    }
    try out.writeAll("]}\n");
}

pub fn writeJsonString(out: *std.Io.Writer, text: []const u8) !void {
    try out.writeAll("\"");
    for (text) |byte| {
        switch (byte) {
            '"' => try out.writeAll("\\\""),
            '\\' => try out.writeAll("\\\\"),
            '\n' => try out.writeAll("\\n"),
            '\r' => try out.writeAll("\\r"),
            '\t' => try out.writeAll("\\t"),
            else => {
                if (byte < 0x20) {
                    try out.print("\\u{x:0>4}", .{byte});
                } else {
                    try out.writeAll(&.{byte});
                }
            },
        }
    }
    try out.writeAll("\"");
}
