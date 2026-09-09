//! IP address to country lookup: bounded CSV loading for published range datasets,
//! immutable sorted generations with binary search, a compact snapshot format, and the
//! provider facts (licence, attribution, URLs, version syntax) callers must not invent.
//! Standard library only; nothing here touches storage, networking or the request path.
const std = @import("std");
pub const address = @import("address.zig");
pub const country = @import("country.zig");
pub const range = @import("range.zig");
pub const database = @import("database.zig");
pub const provider = @import("provider.zig");
pub const gzip = @import("gzip.zig");
pub const wire = @import("wire.zig");
pub const snapshot = @import("snapshot.zig");
pub const embedded = @import("embedded.zig");

pub const Range = range.Range;
pub const Error = range.Error;
pub const Builder = range.Builder;
pub const Database = database.Database;
pub const Loader = database.Loader;
pub const Version = database.Version;
pub const Provider = provider.Provider;
pub const max_ranges = database.max_ranges;
pub const max_csv_bytes = database.max_csv_bytes;
pub const max_line = range.max_line;

pub const parseAddress = address.parse;
pub const countryValid = country.valid;
pub const parseRow = range.parseRow;
pub const lookup = range.lookup;
pub const fromCsv = database.fromCsv;

test {
    _ = address;
    _ = country;
    _ = range;
    _ = database;
    _ = provider;
    _ = gzip;
    _ = wire;
    _ = snapshot;
    _ = embedded;
}

test "committed user-country fixtures load as one two-file generation" {
    const t = std.testing;
    var loader = try Loader.init(t.allocator);
    errdefer loader.abandon();
    try loader.feed(@embedFile("testdata/user-country-ipv4.csv"));
    try loader.endFile();
    try loader.feed(@embedFile("testdata/user-country-ipv6.csv"));
    try loader.endFile();
    var db = try loader.finish(.user_country, "2026-09-09");
    defer db.deinit();
    try t.expectEqual(@as(usize, 25), db.ranges.len);
    try t.expectEqualStrings("AU", &db.lookupText("1.0.0.1").?);
    try t.expectEqualStrings("JP", &db.lookupText("2001:200::1").?);
    try t.expectEqualStrings("AN", &db.lookupText("2401:b60:1a10::1").?);
    try t.expectEqualStrings("FX", &db.lookupText("176.23.148.5").?);
    var buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try snapshot.encode(&writer, &db);
    var restored = try snapshot.decode(t.allocator, writer.buffered());
    defer restored.deinit();
    try t.expectEqual(db.ranges.len, restored.ranges.len);
    try t.expectEqualSlices(u8, &db.file_digests[1], &restored.file_digests[1]);
}
