//! Shared field markup keeps filters aligned without coupling forms to browser behavior.
const std = @import("std");
const html = @import("html");

pub const Input = struct {
    name: []const u8,
    label: []const u8,
    value: []const u8,
    limit: usize,
    placeholder: []const u8 = "",
    hint: []const u8 = "",
    wide: bool = false,
};

pub fn input(w: *std.Io.Writer, field: Input) std.Io.Writer.Error!void {
    try html.render(w, @embedFile("snippets/filter-input.html"), .{
        .name = field.name,
        .label = field.label,
        .value = field.value,
        .limit = field.limit,
        .placeholder = field.placeholder,
        .hint = field.hint,
        .wide = if (field.wide) " sb-filter-wide" else "",
    });
}
