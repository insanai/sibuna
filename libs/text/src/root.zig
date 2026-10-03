//! Compile-time text fixtures, shared by native and Wasm consumers without allocation.
const std = @import("std");

/// Return an owned array; a caller taking its address at comptime borrows static storage.
/// The result's size is checked by the compiler before any output is instantiated.
pub fn repeat(comptime source: []const u8, comptime count: usize) [source.len * count]u8 {
    var result: [source.len * count]u8 = undefined;
    for (0..count) |index| @memcpy(result[index * source.len ..][0..source.len], source);
    return result;
}

test "repeated text preserves bytes and handles empty input" {
    try std.testing.expectEqualStrings("ababab", &repeat("ab", 3));
    try std.testing.expectEqualStrings("éé", &repeat("é", 2));
    try std.testing.expectEqualStrings("", &repeat("", 8));
    try std.testing.expectEqualStrings("", &repeat("abc", 0));
}
