//! Operator-declared server coordinates, independent of country-only client GeoIP data.
const std = @import("std");
pub const Location = struct {
    lat: f64,
    lon: f64,

    pub const Error = error{InvalidLocation};

    pub fn valid(self: Location) bool {
        return std.math.isFinite(self.lat) and std.math.isFinite(self.lon) and
            @abs(self.lat) <= 90 and @abs(self.lon) <= 180;
    }

    /// CLI order follows conventional latitude,longitude. No lookup or inferred default.
    pub fn parse(text: []const u8) Error!Location {
        if (text.len > 64) return error.InvalidLocation;
        const comma = std.mem.indexOfScalar(u8, text, ',') orelse return error.InvalidLocation;
        const value: Location = .{
            .lat = std.fmt.parseFloat(f64, text[0..comma]) catch return error.InvalidLocation,
            .lon = std.fmt.parseFloat(f64, text[comma + 1 ..]) catch return error.InvalidLocation,
        };
        if (!value.valid()) return error.InvalidLocation;
        return value;
    }
};

test "server coordinates preserve boundaries and reject nonfinite or malformed input" {
    const t = std.testing;
    for ([_][]const u8{ "0,0", "90,180", "-90,-180", "1.3521,103.8198" }) |value|
        try t.expect((try Location.parse(value)).valid());
    for ([_][]const u8{ "", "1", "1,2,3", "91,0", "0,-181", "nan,0", "0,inf" }) |value|
        try t.expectError(error.InvalidLocation, Location.parse(value));
}
