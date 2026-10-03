//! Bearer parsing returns only a digest. Never fall back to cookie authentication when an
//! Authorization header is present; callers reject a simultaneous Cookie header.
const repeat = @import("text").repeat;
const std = @import("std");
pub const Error = error{InvalidRequest};

pub fn parse(header: []const u8) Error![32]u8 {
    if (header.len < 7 or header.len > 1024 or
        !std.ascii.eqlIgnoreCase(header[0..6], "Bearer") or header[6] != ' ')
        return error.InvalidRequest;
    const value = std.mem.trim(u8, header[6..], " ");
    if (value.len != 64) return error.InvalidRequest;
    var raw: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw);
    _ = std.fmt.hexToBytes(&raw, value) catch return error.InvalidRequest;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&raw, &digest, .{});
    return digest;
}

test "bearer schemes accept bounded spaces but never malformed or partial credentials" {
    const t = std.testing;
    const value = &repeat("a", 64);
    const expected = try parse("Bearer " ++ value);
    try t.expectEqual(expected, try parse("bEaReR   " ++ value ++ " "));
    try t.expectEqual(expected, try parse("Bearer " ++ &repeat("A", 64)));
    for ([_][]const u8{
        "",
        "Bearer",
        "Bearer " ++ &repeat("a", 63),
        "Basic " ++ value,
        "Bearer\t" ++ value,
        "Bearer " ++ &repeat("z", 64),
        "Bearer " ++ value ++ ",other",
    }) |invalid| try t.expectError(error.InvalidRequest, parse(invalid));
    try t.expectError(error.InvalidRequest, parse("Bearer " ++
        &repeat(" ", 1024) ++
        value));
}
