//! Editable header rows retain duplicate or incomplete input until document validation.
const std = @import("std");
const p = @import("console_protocol");
const html = @import("html");
const Writer = std.Io.Writer;
const Pair = struct { name: []const u8 = "", pattern: []const u8 = "" };

pub fn capture(fields: std.json.Value) !p.Bytes(4096) {
    var pairs: [4]Pair = @splat(.{});
    inline for (0..4) |i| {
        const suffix = std.fmt.comptimePrint("{d}", .{i});
        pairs[i] = .{
            .name = text(fields, "rule_header_name_" ++ suffix),
            .pattern = text(fields, "rule_header_pattern_" ++ suffix),
        };
        if (pairs[i].name.len > 64 or pairs[i].pattern.len > 256) return error.InvalidHeaders;
    }
    return encode(&pairs);
}

pub fn loadHeaders(root: std.json.Value) !p.Bytes(4096) {
    const source_headers = root.object.get("headers") orelse return encode(&.{});
    if (source_headers == .null) return encode(&.{});
    if (source_headers != .object or source_headers.object.count() > 4)
        return error.InvalidHeaders;
    var pairs: [4]Pair = @splat(.{});
    var items = source_headers.object.iterator();
    var count: usize = 0;
    while (items.next()) |item| : (count += 1) {
        if (item.value_ptr.* != .string) return error.InvalidHeaders;
        pairs[count] = .{ .name = item.key_ptr.*, .pattern = item.value_ptr.string };
    }
    return encode(pairs[0..count]);
}

pub fn headers(source: []const u8, allocator: std.mem.Allocator) !std.json.Value {
    const pairs = try decode(source, allocator);
    var object: std.json.Value = .{ .object = .{} };
    for (pairs) |pair| {
        if (pair.name.len == 0 and pair.pattern.len == 0) continue;
        if (pair.name.len == 0 or pair.name.len > 64 or pair.pattern.len > 256)
            return error.InvalidHeaders;
        var keys = object.object.iterator();
        while (keys.next()) |key| {
            if (std.ascii.eqlIgnoreCase(key.key_ptr.*, pair.name)) return error.InvalidHeaders;
        }
        try object.object.put(allocator, pair.name, .{ .string = pair.pattern });
    }
    return object;
}

pub fn loadNetworks(root: std.json.Value) !p.Bytes(512) {
    var result: p.Bytes(512) = .{};
    const value = root.object.get("cidrs") orelse return result;
    if (value == .null) return result;
    if (value != .array or value.array.items.len > 8) return error.InvalidNetworks;
    var w: Writer = .fixed(&result.data);
    for (value.array.items, 0..) |item, index| {
        if (item != .string or item.string.len == 0 or item.string.len > 48 or
            std.mem.indexOfAny(u8, item.string, "\r\n") != null) return error.InvalidNetworks;
        if (index != 0) try w.writeByte('\n');
        try w.writeAll(item.string);
    }
    result.len = w.buffered().len;
    return result;
}

pub fn networks(source: []const u8, allocator: std.mem.Allocator) !std.json.Value {
    var result: std.json.Value = .{ .array = std.json.Array.init(allocator) };
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0) continue;
        if (line.len > 48 or result.array.items.len == 8) return error.InvalidNetworks;
        try result.array.append(.{ .string = line });
    }
    return result;
}

pub fn render(w: *Writer, source: []const u8, cidrs: []const u8) Writer.Error!void {
    var memory: [16384]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&memory);
    const pairs = decode(source, fixed.allocator()) catch return error.WriteFailed;
    try w.writeAll("<fieldset class=\"sb-rule-wide\"><legend class=\"font-bold\">" ++
        "Header matchers</legend><p class=\"sb-note\">All configured headers must match. " ++
        "Leave unused rows blank.</p><div class=\"sb-rule-grid\">");
    for (0..4) |i| {
        const pair: Pair = if (i < pairs.len) pairs[i] else .{};
        try html.render(w, @embedFile("snippets/policy-header-fields.html"), .{
            .index = i,
            .number = i + 1,
            .name = pair.name,
            .pattern = pair.pattern,
        });
    }
    try w.writeAll("</div></fieldset>");
    try html.render(w, @embedFile("snippets/policy-network-fields.html"), .{ .networks = cidrs });
}

fn encode(pairs: []const Pair) !p.Bytes(4096) {
    var result: p.Bytes(4096) = .{};
    var w: Writer = .fixed(&result.data);
    try std.json.Stringify.value(pairs, .{}, &w);
    result.len = w.buffered().len;
    return result;
}

fn decode(source: []const u8, allocator: std.mem.Allocator) ![]Pair {
    if (source.len == 0) return &.{};
    const value = try std.json.parseFromSliceLeaky(std.json.Value, allocator, source, .{});
    if (value != .array or value.array.items.len > 4) return error.InvalidHeaders;
    const result = try allocator.alloc(Pair, value.array.items.len);
    for (value.array.items, result) |item, *pair| {
        pair.* = .{ .name = text(item, "name"), .pattern = text(item, "pattern") };
    }
    return result;
}

fn text(value: std.json.Value, key: []const u8) []const u8 {
    if (value != .object) return "";
    const item = value.object.get(key) orelse return "";
    return if (item == .string) item.string else "";
}

test "duplicate header rows remain editable but cannot become a policy document" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const source = try encode(&.{
        .{ .name = "X-Review", .pattern = "one" },
        .{ .name = "x-review", .pattern = "two" },
    });
    try t.expectError(error.InvalidHeaders, headers(source.slice(), arena.allocator()));
    const rows = try decode(source.slice(), arena.allocator());
    try t.expectEqualStrings("two", rows[1].pattern);
    const empty = try headers("", arena.allocator());
    try t.expectEqual(@as(usize, 0), empty.object.count());
    const addresses = try networks("8.8.8.0/24\n2001:db8::/32", arena.allocator());
    try t.expectEqual(@as(usize, 2), addresses.array.items.len);
}
