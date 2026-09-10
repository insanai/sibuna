//! Shared numeric setting catalog. The UI and storage owner enforce the same bounds;
//! no arbitrary keys, expressions or secret-bearing values enter this interface.
const std = @import("std");
pub const Group = enum { notification, retention };
pub const Definition = struct {
    key: []const u8,
    label: []const u8,
    default: []const u8,
    maximum: u32,
    group: Group = .notification,
};
pub const catalog = [_]Definition{
    .{
        .key = "notify.spike_factor",
        .label = "Spike multiplier",
        .default = "3",
        .maximum = 1_000_000,
    },
    .{
        .key = "notify.spike_minimum",
        .label = "Minimum denials",
        .default = "100",
        .maximum = 1_000_000,
    },
    .{
        .key = "retention.minutes",
        .label = "Minute history (days)",
        .default = "90",
        .maximum = 90,
        .group = .retention,
    },
    .{
        .key = "retention.rankings",
        .label = "Rankings (days)",
        .default = "7",
        .maximum = 7,
        .group = .retention,
    },
    .{
        .key = "retention.incidents",
        .label = "Incidents (days)",
        .default = "30",
        .maximum = 30,
        .group = .retention,
    },
    .{
        .key = "retention.audit",
        .label = "Audit (days)",
        .default = "365",
        .maximum = 365,
        .group = .retention,
    },
};
pub const keys = block: {
    var result: [catalog.len][]const u8 = undefined;
    for (catalog, &result) |entry, *key| key.* = entry.key;
    break :block result;
};

pub fn definition(key: []const u8) ?Definition {
    for (catalog) |entry| if (std.mem.eql(u8, key, entry.key)) return entry;
    return null;
}

pub fn valid(key: []const u8, value: []const u8) bool {
    const entry = definition(key) orelse return false;
    if (value.len == 0 or value.len > 7) return false;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return false;
    const number = std.fmt.parseInt(u32, value, 10) catch return false;
    return number >= 1 and number <= entry.maximum;
}

test "numeric settings reject unknown keys, expressions and retention beyond fixed capacity" {
    const t = std.testing;
    for (catalog) |entry| try t.expect(valid(entry.key, entry.default));
    for ([_][]const u8{ "", "0", "-1", "+1", "1.0", " 1", "1e2", "999999999" }) |value|
        try t.expect(!valid("retention.minutes", value));
    try t.expect(!valid("retention.minutes", "91"));
    try t.expect(!valid("retention.rankings", "8"));
    try t.expect(!valid("retention.incidents", "31"));
    try t.expect(!valid("retention.audit", "366"));
    try t.expect(!valid("retention.other", "1"));
    try t.expect(valid("retention.minutes", "1"));
}
