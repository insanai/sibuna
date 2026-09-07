const std = @import("std");
const zx = @import("zaxonlite");

/// Embedded.call uses the supported authenticated protocol and its leader routing.
/// Remote queries retain server-side bounds (10k rows, 16 MiB, 10m VM steps); our fixed
/// indexed statements also use LIMIT, then apply the stricter console result bounds here.
fn call(
    embedded: *zx.Embedded,
    gpa: std.mem.Allocator,
    op: []const u8,
    sql: []const u8,
    values: []const zx.Value,
) !std.json.Parsed(std.json.Value) {
    var buffer: [32 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writer.print("{{\"op\":\"{s}\",\"format\":\"typed-v1\"," ++
        "\"level\":\"linearizable\",\"sql\":", .{op});
    try std.json.Stringify.value(sql, .{}, &writer);
    try writer.writeAll(",\"params\":[");
    for (values, 0..) |value, i| {
        if (i != 0) try writer.writeByte(',');
        switch (value) {
            .integer => |n| try writer.print("{{\"t\":\"int\",\"i\":{d}}}", .{n}),
            .text => |text| {
                try writer.writeAll("{\"t\":\"text\",\"v\":");
                try std.json.Stringify.value(text, .{}, &writer);
                try writer.writeByte('}');
            },
            .null_value => try writer.writeAll("{\"t\":\"null\"}"),
            else => return error.UnsupportedParameter,
        }
    }
    try writer.writeAll("]}");
    const response = try embedded.call(writer.buffered(), true);
    defer gpa.free(response);
    if (response.len > 65536) return error.ResultTooLarge;
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, response, .{
        .allocate = .alloc_always,
    });
    errdefer parsed.deinit();
    if (parsed.value != .object) return error.InvalidResponse;
    const ok = parsed.value.object.get("ok") orelse return error.InvalidResponse;
    if (ok != .bool or !ok.bool) return error.StorageUnavailable;
    return parsed;
}

pub fn exec(
    embedded: *zx.Embedded,
    gpa: std.mem.Allocator,
    sql: []const u8,
    values: []const zx.Value,
) !i64 {
    const parsed = try call(embedded, gpa, "exec", sql, values);
    defer parsed.deinit();
    const changes = parsed.value.object.get("changes") orelse return error.InvalidResponse;
    if (changes != .integer) return error.InvalidResponse;
    return changes.integer;
}

pub fn query(
    embedded: *zx.Embedded,
    gpa: std.mem.Allocator,
    sql: []const u8,
    values: []const zx.Value,
) !zx.QueryResult {
    const parsed = try call(embedded, gpa, "query", sql, values);
    defer parsed.deinit();
    const rows = parsed.value.object.get("rows") orelse return error.InvalidResponse;
    if (rows != .array or rows.array.items.len > 100) return error.ResultTooLarge;
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const alloc = arena.allocator();
    const output = try alloc.alloc([]const ?[]const u8, rows.array.items.len);
    for (rows.array.items, output) |row, *dest| {
        if (row != .array or row.array.items.len > 32) return error.InvalidResponse;
        const cells = try alloc.alloc(?[]const u8, row.array.items.len);
        for (row.array.items, cells) |cell, *text| text.* = try copyCell(alloc, cell);
        dest.* = cells;
    }
    return .{ .arena = arena, .columns = &.{}, .rows = output };
}

fn copyCell(gpa: std.mem.Allocator, cell: std.json.Value) !?[]const u8 {
    if (cell == .null) return null;
    if (cell != .object) return error.InvalidResponse;
    const tag = cell.object.get("t") orelse return error.InvalidResponse;
    if (tag != .string) return error.InvalidResponse;
    if (std.mem.eql(u8, tag.string, "null")) return null;
    if (std.mem.eql(u8, tag.string, "t")) {
        const value = cell.object.get("v") orelse return error.InvalidResponse;
        if (value != .string) return error.InvalidResponse;
        return try gpa.dupe(u8, value.string);
    }
    if (std.mem.eql(u8, tag.string, "i")) {
        const value = cell.object.get("i") orelse return error.InvalidResponse;
        if (value != .integer) return error.InvalidResponse;
        return try std.fmt.allocPrint(gpa, "{d}", .{value.integer});
    }
    return error.InvalidResponse;
}
