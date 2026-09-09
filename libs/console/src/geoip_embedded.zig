//! A build may embed one validated country snapshot (-Dgeoip-data). It is decoded once at
//! startup and activated only while storage holds no durable generation.
const std = @import("std");
const geoip = @import("geoip");
const bytes = @embedFile("geoip_snapshot");
pub const present = bytes.len != 0;

pub fn load(allocator: std.mem.Allocator) !?geoip.Database {
    return geoip.embedded.load(allocator, bytes);
}

test "an embedded snapshot, when present, decodes into a usable generation" {
    const t = std.testing;
    var database = (try load(t.allocator)) orelse {
        try t.expect(!present);
        return;
    };
    defer database.deinit();
    try t.expect(database.ranges.len != 0);
}
