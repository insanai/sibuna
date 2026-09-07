//! CSV is a display export: formula-like cells get a visible "Text: " prefix.
//! Quoting alone is insufficient (https://owasp.org/www-community/attacks/CSV_Injection).
//! JSON remains available for unchanged string values and exact typed identifiers.
const std = @import("std");
const Error = error{ InvalidResponse, TooLarge };
const Row = struct {
    id: []const u8 = "",
    node: u64 = 0,
    time: u64 = 0,
    ip: []const u8 = "",
    category: []const u8 = "",
    method: []const u8 = "",
    path: []const u8 = "",
    user_agent: []const u8 = "",
    campaign: ?[]const u8 = null,
    grouped: bool = false,
    count: u64 = 0,
    first_seen: u64 = 0,
    country: ?[]const u8 = null,
    response_status: ?u16 = null,
    matched_rule: ?[]const u8 = null,
    evidence_version: ?u16 = null,
    capture: ?@import("console_protocol").events.Capture = null,
    display_truncated: bool = false,
    query_redacted: bool = false,
};

pub fn csv(source: []const u8, output: *[4096]u8) Error![]const u8 {
    var memory: [64 * 1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = std.json.parseFromSlice(
        struct { rows: []const Row },
        fixed.allocator(),
        source,
        .{ .ignore_unknown_fields = true },
    ) catch return error.InvalidResponse;
    defer parsed.deinit();
    const rows = parsed.value.rows;
    if (rows.len > 10) return error.InvalidResponse;
    var writer: std.Io.Writer = .fixed(output);
    inline for (std.meta.fields(Row), 0..) |column, i| {
        if (i != 0) writer.writeByte(',') catch return error.TooLarge;
        try cell(&writer, column.name);
    }
    writer.writeAll("\r\n") catch return error.TooLarge;
    for (rows) |row| {
        inline for (std.meta.fields(Row), 0..) |column, i| {
            if (i != 0) writer.writeByte(',') catch return error.TooLarge;
            try value(&writer, @field(row, column.name));
        }
        writer.writeAll("\r\n") catch return error.TooLarge;
    }
    return writer.buffered();
}

fn value(w: *std.Io.Writer, item: anytype) Error!void {
    switch (@typeInfo(@TypeOf(item))) {
        .pointer => try cell(w, item),
        .int => w.print("{d}", .{item}) catch return error.TooLarge,
        .bool => w.writeAll(if (item) "true" else "false") catch return error.TooLarge,
        .optional => if (item) |present| try value(w, present) else try cell(w, "Not recorded"),
        .@"struct" => {
            var bytes: [512]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&bytes);
            std.json.Stringify.value(item, .{}, &writer) catch return error.TooLarge;
            try cell(w, writer.buffered());
        },
        else => @compileError("unsupported CSV field type"),
    }
}

fn cell(w: *std.Io.Writer, text: []const u8) Error!void {
    w.writeByte('"') catch return error.TooLarge;
    const trimmed = std.mem.trimStart(u8, text, " \t\r\n");
    const dangerous = (text.len != 0 and text[0] < 32) or
        (trimmed.len != 0 and std.mem.indexOfScalar(u8, "=+-@", trimmed[0]) != null) or
        std.mem.startsWith(u8, trimmed, "＝") or std.mem.startsWith(u8, trimmed, "＋") or
        std.mem.startsWith(u8, trimmed, "－") or std.mem.startsWith(u8, trimmed, "＠") or
        std.mem.startsWith(u8, trimmed, "\xef\xbb\xbf");
    if (dangerous) w.writeAll("Text: ") catch return error.TooLarge;
    for (text) |byte| {
        if (byte == '"') w.writeByte('"') catch return error.TooLarge;
        w.writeByte(byte) catch return error.TooLarge;
    }
    w.writeByte('"') catch return error.TooLarge;
}

test "CSV quotes separators and visibly neutralizes spreadsheet formulas" {
    var output: [4096]u8 = undefined;
    const result = try csv(
        "{\"rows\":[{\"id\":\"9007199254740993\",\"user_agent\":\" =1+2\\\";x\"}]}",
        &output,
    );
    try std.testing.expect(std.mem.indexOf(u8, result, "\"9007199254740993\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"Text:  =1+2\"\";x\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Not recorded") != null);
}

test "CSV formula-like prefixes include controls, full-width characters and BOM" {
    for ([_][]const u8{ "\t=1", "＝1", "＠SUM(1)", "\xef\xbb\xbf=1", " +1" }) |text| {
        var output: [128]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&output);
        try cell(&writer, text);
        try std.testing.expect(std.mem.startsWith(u8, writer.buffered(), "\"Text: "));
    }
}
