//! Audit summaries are an allowlisted view, never arbitrary stored JSON or policy secrets.
const std = @import("std");
const p = @import("console").protocol;
pub const Coverage = struct { truncated: bool = false, redacted: bool = false };

pub fn copy(output: *p.Bytes(1024), source: []const u8, coverage: *Coverage) !void {
    if (source.len > 8192 or !std.unicode.utf8ValidateSlice(source))
        return error.InvalidStoredValue;
    var memory: [32768]u8 = undefined;
    defer std.crypto.secureZero(u8, &memory);
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        source,
        .{},
    );
    if (parsed != .object) return error.InvalidStoredValue;
    output.len = 0;
    errdefer std.crypto.secureZero(u8, &output.data);
    var writer: std.Io.Writer = .fixed(&output.data);
    var json: std.json.Stringify = .{ .writer = &writer };
    try json.beginObject();
    var fields = parsed.object.iterator();
    while (fields.next()) |field| {
        const key = field.key_ptr.*;
        const value = field.value_ptr.*;
        if (textField(key) and value == .string) {
            var buffer: [64]u8 = undefined;
            const text = bounded(&buffer, value.string, coverage);
            try json.objectField(key);
            try json.write(text);
        } else if (numberField(key) and
            (value == .integer or value == .bool or value == .null))
        {
            try json.objectField(key);
            try json.write(value);
        } else coverage.redacted = true;
    }
    try json.endObject();
    output.len = writer.buffered().len;
}

fn textField(key: []const u8) bool {
    for ([_][]const u8{ "username", "label", "role", "command", "state" }) |name|
        if (std.mem.eql(u8, key, name)) return true;
    return false;
}

fn numberField(key: []const u8) bool {
    for ([_][]const u8{
        "disabled", "must_change", "revision", "scopes", "expires", "cleared_entries",
    }) |name|
        if (std.mem.eql(u8, key, name)) return true;
    return false;
}

fn bounded(buffer: *[64]u8, source: []const u8, coverage: *Coverage) []const u8 {
    var length = @min(buffer.len, source.len);
    while (length != 0 and !std.unicode.utf8ValidateSlice(source[0..length])) length -= 1;
    @memcpy(buffer[0..length], source[0..length]);
    for (buffer[0..length]) |*byte| {
        if (byte.* < 32 or byte.* == 127) {
            byte.* = '?';
            coverage.redacted = true;
        }
    }
    coverage.truncated = coverage.truncated or length != source.len;
    return buffer[0..length];
}

test "audit summary redaction drops secrets and truncates complete UTF-8 characters" {
    const t = std.testing;
    var output: p.Bytes(1024) = undefined;
    var coverage: Coverage = .{};
    try copy(&output, "{\"label\":\"" ++ "a" ** 63 ++ "é\",\"revision\":2," ++
        "\"password\":\"private\",\"token\":\"private\",\"nested\":{\"secret\":true}}", &coverage);
    try t.expect(coverage.redacted and coverage.truncated);
    try t.expect(std.unicode.utf8ValidateSlice(output.slice()));
    try t.expect(std.mem.indexOf(u8, output.slice(), "private") == null);
    try t.expect(std.mem.indexOf(u8, output.slice(), "\"revision\":2") != null);
}
