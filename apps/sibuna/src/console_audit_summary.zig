//! Audit summaries are an allowlisted view, never arbitrary stored JSON or policy secrets.
const repeat = @import("text").repeat;
const std = @import("std");
const p = @import("console").protocol;
pub const Coverage = struct { truncated: bool = false, redacted: bool = false };

pub fn copy(
    output: *p.Bytes(1024),
    source: []const u8,
    coverage: *Coverage,
    action: []const u8,
) !void {
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
        if (std.mem.eql(u8, key, "selectors_redacted") and
            value == .integer and value.integer != 0) coverage.redacted = true;
        if ((textField(key) or notificationField(action, key, .text)) and value == .string) {
            var buffer: [64]u8 = undefined;
            const text = bounded(&buffer, value.string, coverage);
            try json.objectField(key);
            try json.write(text);
        } else if ((numberField(key) or notificationField(action, key, .number)) and
            (value == .integer or value == .bool or value == .null))
        {
            try json.objectField(key);
            try json.write(value);
        } else coverage.redacted = true;
    }
    try json.endObject();
    output.len = writer.buffered().len;
}

/// These fields describe deliveries, never arbitrary user JSON. Keep the extension scoped
/// to notification records so a similarly named field elsewhere does not become public.
fn notificationField(action: []const u8, key: []const u8, kind: enum { text, number }) bool {
    if (!std.mem.startsWith(u8, action, "notification.")) return false;
    const names: []const []const u8 = switch (kind) {
        .text => &.{ "operation", "outcome", "detail", "transport" },
        .number => &.{ "event", "destination", "attempt", "cooldown" },
    };
    for (names) |name| if (std.mem.eql(u8, key, name)) return true;
    return false;
}

fn textField(key: []const u8) bool {
    for ([_][]const u8{
        "username",       "label", "role", "command", "state",  "action", "algorithm",
        "path_traversal", "sqli",  "xss",  "rce",     "sha256", "kind",   "host",
        "secret",
    }) |name|
        if (std.mem.eql(u8, key, name)) return true;
    return false;
}

fn numberField(key: []const u8) bool {
    for ([_][]const u8{
        "disabled",    "must_change",        "revision",   "scopes", "expires", "cleared_entries",
        "enabled",     "priority",           "difficulty", "weight", "rate",    "window_seconds",
        "ban_seconds", "selectors_redacted", "algorithm",  "bytes",  "events",  "cooldown_seconds",
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
    try copy(
        &output,
        "{\"label\":\"" ++ &repeat("a", 63) ++ "é\",\"revision\":2," ++
            "\"password\":\"private\",\"token\":\"private\",\"nested\":{\"secret\":true}}",
        &coverage,
        "",
    );
    try t.expect(coverage.redacted and coverage.truncated);
    try t.expect(std.unicode.utf8ValidateSlice(output.slice()));
    try t.expect(std.mem.indexOf(u8, output.slice(), "private") == null);
    try t.expect(std.mem.indexOf(u8, output.slice(), "\"revision\":2") != null);
}

test "notification receipts expose correlation and outcome without arbitrary secret fields" {
    var output: p.Bytes(1024) = undefined;
    var coverage: Coverage = .{};
    const source = "{\"operation\":\"0123456789abcdef0123456789abcdef\"," ++
        "\"outcome\":\"delivered\",\"detail\":\"status 204\",\"revision\":1," ++
        "\"secret_envelope\":\"private\"}";
    try copy(&output, source, &coverage, "notification.test_result");
    try std.testing.expect(coverage.redacted and !coverage.truncated);
    try std.testing.expect(std.mem.indexOf(u8, output.slice(), "0123456789abcdef") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.slice(), "status 204") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.slice(), "private") == null);
    try copy(&output, source, &coverage, "user.update");
    try std.testing.expectEqualStrings("{\"revision\":1}", output.slice());
}
