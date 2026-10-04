//! Canonical stock release versions, shared by URLs, archive roots and manifests.
//! No tag or filename can contain separators, prerelease text or leading zeros.
const std = @import("std");
pub const Error = error{ InvalidReleaseVersion, VersionOutputLimit };
pub const Version = struct {
    major: u16,
    minor: u16,
    patch: u16,

    pub fn parse(text: []const u8) Error!Version {
        if (text.len > 17) return error.InvalidReleaseVersion;
        var parts = std.mem.splitScalar(u8, text, '.');
        var values: [3]u16 = undefined;
        for (&values) |*value| {
            const part = parts.next() orelse return error.InvalidReleaseVersion;
            if (part.len == 0 or part.len > 5 or (part.len != 1 and part[0] == '0'))
                return error.InvalidReleaseVersion;
            for (part) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidReleaseVersion;
            value.* = std.fmt.parseInt(u16, part, 10) catch return error.InvalidReleaseVersion;
        }
        if (parts.next() != null) return error.InvalidReleaseVersion;
        return .{ .major = values[0], .minor = values[1], .patch = values[2] };
    }

    pub fn write(self: Version, output: []u8) Error![]const u8 {
        return std.fmt.bufPrint(output, "{d}.{d}.{d}", .{
            self.major, self.minor, self.patch,
        }) catch return error.VersionOutputLimit;
    }

    pub fn order(self: Version, other: Version) std.math.Order {
        const left = [_]u16{ self.major, self.minor, self.patch };
        const right = [_]u16{ other.major, other.minor, other.patch };
        for (left, right) |a, b| if (a != b) return std.math.order(a, b);
        return .eq;
    }
};

test "canonical release versions cannot redirect downloads or alias an older tag" {
    const version = try Version.parse("4.30.0");
    var output: [17]u8 = undefined;
    try std.testing.expectEqualStrings("4.30.0", try version.write(&output));
    try std.testing.expectEqual(std.math.Order.lt, version.order(try Version.parse("4.31.0")));
    try std.testing.expectEqual(std.math.Order.gt, version.order(try Version.parse("3.99.9")));
    for ([_][]const u8{
        "",        "v4.30.0",   "4.030.0",    "4.30",    "4.30.0.1", "4.30.0-rc1", "4.30.0/../x",
        "+4.30.0", "65536.0.0", "4.30.0\x00", "4.30.-1",
    }) |text| try std.testing.expectError(error.InvalidReleaseVersion, Version.parse(text));
}
