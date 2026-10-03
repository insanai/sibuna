//! First-party HTML snippets: compile-time syntax, runtime values, caller-owned output.
//! Inspired by Kynetica's ZMPL escaping and strict lookup contract, not its CMS parser.
//! Only trusted source may be a template. Values belong in text or quoted ordinary
//! attributes, never script/style, tag/attribute names, or unvalidated URLs. There is
//! no raw HTML value or filter. Compose snippets and bounded loops explicitly in Zig.
const std = @import("std");
const Writer = std.Io.Writer;

/// Templates and values are borrowed for this call. The caller chooses output capacity;
/// WriteFailed can leave partial output, which must not be published as a complete page.
pub fn render(w: *Writer, comptime source: []const u8, values: anytype) Writer.Error!void {
    @setEvalBranchQuota(100_000);
    comptime {
        if (source.len > 32 * 1024) {
            @compileError("HTML001: snippet exceeds 32 KiB; split it into smaller snippets");
        }
        if (std.mem.indexOf(u8, source, "{%") != null or
            std.mem.indexOf(u8, source, "{#") != null)
        {
            @compileError("HTML002: unsupported tag; use Zig control flow and composition");
        }
    }
    if (comptime @import("text_template.zig").supports(@TypeOf(values)))
        return @import("text_template.zig").render(w, source, values);
    comptime var cursor: usize = 0;
    comptime var slots: usize = 0;
    inline while (comptime std.mem.indexOfPos(u8, source, cursor, "{{")) |start| {
        const end = comptime std.mem.indexOfPos(u8, source, start + 2, "}}") orelse
            @compileError("HTML003: unclosed placeholder; add }}");
        const name = comptime std.mem.trim(u8, source[start + 2 .. end], " \r\n\t");
        comptime validateName(name);
        if (comptime !@hasField(@TypeOf(values), name)) {
            @compileError("HTML004: missing value '" ++ name ++ "'; supply the named field");
        }
        try @import("literals.zig").write(w, source[cursor..start]);
        try writeValue(w, @field(values, name));
        comptime {
            cursor = end + 2;
            slots += 1;
            if (slots > 128) {
                @compileError("HTML005: more than 128 placeholders; split the snippet");
            }
        }
    }
    try @import("literals.zig").write(w, source[cursor..]);
}

pub fn validateName(comptime name: []const u8) void {
    if (name.len == 0) @compileError("HTML006: empty placeholder; supply a field name");
    for (name, 0..) |byte, i| {
        const valid = std.ascii.isAlphabetic(byte) or byte == '_' or
            (i != 0 and std.ascii.isDigit(byte));
        if (!valid) {
            @compileError("HTML006: invalid placeholder; only simple field names are supported");
        }
    }
}

fn writeValue(w: *Writer, value: anytype) Writer.Error!void {
    switch (@typeInfo(@TypeOf(value))) {
        .int, .comptime_int => try w.print("{d}", .{value}),
        .bool => try w.writeAll(if (value) "true" else "false"),
        .pointer => |pointer| {
            const text = pointer.child == u8 or switch (@typeInfo(pointer.child)) {
                .array => |array| array.child == u8,
                else => false,
            };
            if (!text) @compileError("HTML007: value must be text, an integer or a boolean");
            try escape(w, value);
        },
        else => @compileError("HTML007: format this value as text before rendering"),
    }
}

pub fn escape(w: *Writer, value: []const u8) Writer.Error!void {
    for (value) |byte| switch (byte) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        '"' => try w.writeAll("&quot;"),
        '\'' => try w.writeAll("&#39;"),
        else => try w.writeByte(byte),
    };
}

test "text and quoted attributes escape values without interpreting injected templates" {
    var buffer: [512]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&writer, "<p title=\"{{ title }}\">{{ body }}: {{ id }}</p>", .{
        .title = "\" onclick='bad' &",
        .body = "<script>{{ id }}</script>",
        .id = @as(u64, 9007199254740993),
    });
    try std.testing.expectEqualStrings(
        "<p title=\"&quot; onclick=&#39;bad&#39; &amp;\">" ++
            "&lt;script&gt;{{ id }}&lt;/script&gt;: 9007199254740993</p>",
        writer.buffered(),
    );
}

test "escaping expansion respects the caller's fixed output capacity" {
    var buffer: [8]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try std.testing.expectError(error.WriteFailed, render(&writer, "{{ text }}", .{
        .text = "&&",
    }));
}

test "compiled text slots preserve repeated names, whitespace, literal NUL and injected syntax" {
    var buffer: [512]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&writer, "<p>\n    {{ second }} / {{ first }} / {{ second }}\x00</p>", .{
        .first = "世界<&",
        .second = "{{ first }}\"'",
    });
    try std.testing.expectEqualStrings(
        "<p>\n    {{ first }}&quot;&#39; / 世界&lt;&amp; / {{ first }}&quot;&#39;\x00</p>",
        writer.buffered(),
    );
    writer = .fixed(&buffer);
    try render(&writer, "<p>no slots</p>", .{});
    try std.testing.expectEqualStrings("<p>no slots</p>", writer.buffered());
}

test "shared scalar formatting preserves signed minima, unsigned maxima and booleans" {
    var buffer: [128]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&writer, "{{ low }} {{ high }} {{ yes }} {{ no }}", .{
        .low = @as(i64, std.math.minInt(i64)),
        .high = @as(u64, std.math.maxInt(u64)),
        .yes = true,
        .no = false,
    });
    try std.testing.expectEqualStrings(
        "-9223372036854775808 18446744073709551615 true false",
        writer.buffered(),
    );
}

test {
    _ = @import("instructions.zig");
}

test "extended snippet value indexes retain escaping and literal control bytes" {
    const Values = comptime blk: {
        @setEvalBranchQuota(100_000);
        var names: [128][:0]const u8 = undefined;
        for (&names, 0..) |*name, i| name.* = std.fmt.comptimePrint("f{d}", .{i});
        break :blk @Struct(.auto, null, &names, &@splat([]const u8), &@splat(.{}));
    };
    var values: Values = undefined;
    inline for (@typeInfo(Values).@"struct".field_names) |field_name|
        @field(values, field_name) = "<&";
    var buffer: [128]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&writer, "\x00\x7f世界{{ f0 }}|{{ f127 }}", values);
    try std.testing.expectEqualStrings("\x00\x7f世界&lt;&amp;|&lt;&amp;", writer.buffered());
}
