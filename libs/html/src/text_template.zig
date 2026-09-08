//! Shared execution for text and scalar snippets. Instructions and slot indexes come exclusively
//! from trusted compile-time templates; runtime values remain escaped, borrowed text.
const std = @import("std");
const root = @import("root.zig");
const literals = @import("literals.zig");
const Writer = std.Io.Writer;
const Program = struct { bytes: [64 * 1024]u8 = undefined, len: usize = 0 };

pub fn supports(comptime T: type) bool {
    for (@typeInfo(T).@"struct".fields) |field| {
        if (@typeInfo(field.type) == .bool or @typeInfo(field.type) == .comptime_int) continue;
        if (@typeInfo(field.type) == .array and @typeInfo(field.type).array.child == u8) continue;
        if (@typeInfo(field.type) == .int and @typeInfo(field.type).int.bits <= 64) continue;
        if (@typeInfo(field.type) != .pointer) return false;
        const pointer = @typeInfo(field.type).pointer;
        if (pointer.size == .slice and pointer.child == u8) continue;
        if (pointer.size != .one or @typeInfo(pointer.child) != .array) return false;
        if (@typeInfo(pointer.child).array.child != u8) return false;
    }
    return @typeInfo(T).@"struct".fields.len <= 128;
}

const Scalar = union(enum) { text: []const u8, unsigned: u64, signed: i64 };

pub fn render(w: *Writer, comptime source: []const u8, values: anytype) Writer.Error!void {
    const fields = @typeInfo(@TypeOf(values)).@"struct".fields;
    var items: [fields.len]Scalar = undefined;
    inline for (fields, &items) |field, *item| {
        const value = @field(values, field.name);
        item.* = switch (@typeInfo(field.type)) {
            .bool => .{ .text = if (value) "true" else "false" },
            .array => .{ .text = &@field(values, field.name) },
            .comptime_int => if (value < 0) .{ .signed = value } else .{ .unsigned = value },
            .int => |info| if (info.signedness == .signed)
                .{ .signed = value }
            else
                .{ .unsigned = value },
            else => .{ .text = value },
        };
    }
    const program = comptime compile(source, @TypeOf(values));
    const bytes = comptime program.bytes[0..program.len].*;
    return execute(w, &bytes, &items);
}

// NUL + a dictionary index names an entry, the next 128 indexes a slot, and 255 a literal
// NUL. The program is private compiler output, never accepted from a client or file.
fn compile(comptime source: []const u8, comptime T: type) Program {
    @setEvalBranchQuota(10_000_000);
    std.debug.assert(literals.dictionary.len <= 127);
    var program: Program = .{};
    var cursor: usize = 0;
    var slots: usize = 0;
    while (cursor < source.len) {
        if (std.mem.startsWith(u8, source[cursor..], "{{")) {
            const end = std.mem.indexOfPos(u8, source, cursor + 2, "}}") orelse
                @compileError("HTML003: unclosed placeholder; add }}");
            const name = std.mem.trim(u8, source[cursor + 2 .. end], " \r\n\t");
            root.validateName(name);
            const slot: u8 = for (@typeInfo(T).@"struct".fields, 0..) |field, i| {
                if (std.mem.eql(u8, field.name, name)) break @intCast(i);
            } else @compileError(
                "HTML004: missing value '" ++ name ++ "'; supply the named field",
            );
            program.bytes[program.len..][0..2].* = .{ 0, slot + literals.dictionary.len };
            program.len += 2;
            cursor = end + 2;
            slots += 1;
            if (slots > 128)
                @compileError("HTML005: more than 128 placeholders; split the snippet");
        } else if (literals.match(source[cursor..])) |index| {
            program.bytes[program.len..][0..2].* = .{ 0, index };
            program.len += 2;
            cursor += literals.dictionary[index].len;
        } else {
            program.bytes[program.len] = source[cursor];
            program.len += 1;
            if (source[cursor] == 0) {
                program.bytes[program.len] = 255;
                program.len += 1;
            }
            cursor += 1;
        }
    }
    return program;
}

noinline fn execute(w: *Writer, bytes: []const u8, values: []const Scalar) Writer.Error!void {
    var cursor: usize = 0;
    while (std.mem.indexOfScalarPos(u8, bytes, cursor, 0)) |marker| {
        try w.writeAll(bytes[cursor..marker]);
        std.debug.assert(marker + 1 < bytes.len);
        const index = bytes[marker + 1];
        if (index == 255) {
            try w.writeByte(0);
        } else if (index < literals.dictionary.len) {
            try w.writeAll(literals.dictionary[index]);
        } else {
            const slot = index - literals.dictionary.len;
            std.debug.assert(slot < values.len);
            var buffer: [20]u8 = undefined;
            const text = switch (values[slot]) {
                .text => |value| value,
                .unsigned => |value| try number(buffer[0..20], value, false),
                .signed => |value| try number(buffer[0..20], @abs(value), value < 0),
            };
            try root.escape(w, text);
        }
        cursor = marker + 2;
    }
    try w.writeAll(bytes[cursor..]);
}

noinline fn number(buffer: *[20]u8, magnitude: u64, negative: bool) Writer.Error![]const u8 {
    var writer: Writer = .fixed(buffer);
    if (negative) try writer.writeByte('-');
    try writer.print("{d}", .{magnitude});
    return writer.buffered();
}
