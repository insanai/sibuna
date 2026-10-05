//! Stored metadata decodes into an owned envelope before result teardown.
const std = @import("std");
const p = @import("console").protocol;
pub const capacity = 2048;
const Error = error{ InvalidStoredValue, OutOfMemory };

pub fn encode(value: ?p.crs_management.Diagnostic, bytes: *[capacity]u8) ?[]const u8 {
    const diagnostic = value orelse return null;
    var writer: std.Io.Writer = .fixed(bytes);
    std.json.Stringify.value(diagnostic, .{}, &writer) catch unreachable;
    return writer.buffered();
}

pub fn decode(gpa: std.mem.Allocator, bytes: ?[]const u8) Error!?p.crs_management.Diagnostic {
    const source = bytes orelse return null;
    if (source.len > capacity) return error.InvalidStoredValue;
    const scratch = try gpa.alloc(u8, 32 * 1024);
    defer gpa.free(scratch);
    defer std.crypto.secureZero(u8, scratch);
    var bounded = std.heap.FixedBufferAllocator.init(scratch);
    const parsed = std.json.parseFromSlice(std.json.Value, bounded.allocator(), source, .{
        .allocate = .alloc_always,
        .max_value_len = capacity,
    }) catch return error.InvalidStoredValue;
    defer parsed.deinit();
    var result: p.crs_management.Diagnostic = undefined;
    p.json_value.into(&result, parsed.value, bounded.allocator()) catch
        return error.InvalidStoredValue;
    result.validate() catch return error.InvalidStoredValue;
    return result;
}

test "stored diagnostics remain owned after parsing and reject malformed locations" {
    const t = std.testing;
    const expected = p.crs_management.Diagnostic.capture(
        error.UnknownOperator,
        "sibuna-operator.conf",
        2,
        null,
    );
    var bytes: [capacity]u8 = undefined;
    const decoded = (try decode(t.allocator, encode(expected, &bytes))).?;
    @memset(&bytes, 0);
    try t.expectEqualDeep(expected, decoded);
    try t.expectEqual(@as(?p.crs_management.Diagnostic, null), try decode(t.allocator, null));
    try t.expectError(error.InvalidStoredValue, decode(
        t.allocator,
        "{\"code\":\"syntax\",\"path\":\"x\",\"line\":0,\"cause\":\"InvalidSyntax\"}",
    ));
}
