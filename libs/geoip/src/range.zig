//! Publisher rows are `start,end,country`. A builder validates ordering within each
//! address family, drops explicit Unknown rows, then normalizes both families into one
//! sorted, non-overlapping array for binary search.
const std = @import("std");
const address = @import("address.zig");
const country = @import("country.zig");
pub const Error = error{
    InvalidRow,
    InvalidAddress,
    InvalidCountry,
    Unordered,
    Overlap,
    Capacity,
};
pub const max_line = 128;
pub const Range = struct { first: [16]u8, last: [16]u8, country: [2]u8 };

fn column(text: []const u8) []const u8 {
    if (text.len >= 2 and text[0] == '"' and text[text.len - 1] == '"')
        return text[1 .. text.len - 1];
    return text;
}

pub fn parseRow(line: []const u8) Error!Range {
    if (line.len > max_line) return error.InvalidRow;
    var columns = std.mem.splitScalar(u8, std.mem.trimEnd(u8, line, "\r"), ',');
    const first = column(columns.next() orelse return error.InvalidRow);
    const last = column(columns.next() orelse return error.InvalidRow);
    const code = column(columns.next() orelse return error.InvalidRow);
    if (columns.next() != null) return error.InvalidRow;
    if (!country.valid(code)) return error.InvalidCountry;
    const first_v4 = std.mem.indexOfScalar(u8, first, ':') == null;
    const last_v4 = std.mem.indexOfScalar(u8, last, ':') == null;
    if (first_v4 != last_v4) return error.InvalidAddress;
    const range: Range = .{
        .first = try address.parse(first),
        .last = try address.parse(last),
        .country = code[0..2].*,
    };
    if (std.mem.order(u8, &range.first, &range.last) == .gt) return error.Unordered;
    return range;
}

pub const Builder = struct {
    storage: []Range,
    count: usize = 0,
    rows: usize = 0,
    last_v4: ?[16]u8 = null,
    last_v6: ?[16]u8 = null,

    pub fn append(self: *Builder, line: []const u8) Error!void {
        if (self.rows == self.storage.len) return error.Capacity;
        const range = try parseRow(line);
        const last = if (address.isMapped(range.first)) &self.last_v4 else &self.last_v6;
        if (last.*) |previous| {
            if (std.mem.order(u8, &range.first, &previous) != .gt) return error.Overlap;
        }
        last.* = range.last;
        self.rows += 1;
        // Publishers include broad ZZ ranges, some spanning the IPv4-mapped region.
        // Validate source ordering, then omit explicitly unknown ranges before normalizing.
        if (country.isUnknown(range.country)) return;
        self.storage[self.count] = range;
        self.count += 1;
    }

    pub fn finish(self: *Builder) Error![]Range {
        if (self.count == 0) return error.InvalidRow;
        const ranges = self.storage[0..self.count];
        // Publishers group IPv4 and IPv6 separately. Normalize before one binary search;
        // reject IPv4-mapped overlaps as well as overlaps within either family.
        std.sort.heap(Range, ranges, {}, less);
        try checkSorted(ranges);
        return ranges;
    }
};

fn less(_: void, a: Range, b: Range) bool {
    return std.mem.order(u8, &a.first, &b.first) == .lt;
}

/// Every range must be internally ordered, strictly after its predecessor and known.
pub fn checkSorted(ranges: []const Range) Error!void {
    for (ranges, 0..) |current, i| {
        if (std.mem.order(u8, &current.first, &current.last) == .gt) return error.Unordered;
        if (!country.valid(&current.country) or country.isUnknown(current.country))
            return error.InvalidCountry;
        if (i != 0 and std.mem.order(u8, &current.first, &ranges[i - 1].last) != .gt)
            return error.Overlap;
    }
}

pub fn lookup(ranges: []const Range, ip: [16]u8) ?[2]u8 {
    if (!address.public(ip)) return null;
    var lo: usize = 0;
    var hi = ranges.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (std.mem.order(u8, &ranges[mid].first, &ip) == .gt) {
            hi = mid;
        } else if (std.mem.order(u8, &ranges[mid].last, &ip) == .lt) {
            lo = mid + 1;
        } else return if (country.isUnknown(ranges[mid].country)) null else ranges[mid].country;
    }
    return null;
}

test "generations reject overlap, malformed input, and capacity overflow" {
    const t = std.testing;
    var storage: [3]Range = undefined;
    var builder: Builder = .{ .storage = &storage };
    try builder.append("\"8.8.8.0\",\"8.8.8.255\",\"US\"\r");
    try builder.append("2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US");
    try t.expectError(error.Overlap, builder.append("8.8.8.255,8.8.9.0,US"));
    try t.expectError(error.InvalidCountry, builder.append("9.0.0.0,9.0.0.1,AA"));
    try t.expectError(error.InvalidAddress, builder.append("9.0.0.0,2001:4860::,US"));
    try t.expectError(error.Unordered, builder.append("9.0.0.9,9.0.0.1,US"));
    try builder.append("9.0.0.0,9.0.0.255,DE");
    try t.expectError(error.Capacity, builder.append("10.0.0.0,10.0.0.1,US"));
    const ranges = try builder.finish();
    try t.expectEqualStrings("US", &(lookup(ranges, try address.parse("8.8.8.255")).?));
    try t.expectEqualStrings("US", &(lookup(ranges, try address.parse("::ffff:8.8.8.8")).?));
    try t.expectEqualStrings("US", &(lookup(ranges, try address.parse("2001:4860::8888")).?));
    try t.expect(lookup(ranges, try address.parse("8.8.9.0")) == null);
}

test "private and reserved addresses never acquire a country from provider rows" {
    const ranges = [_]Range{.{
        .first = @splat(0),
        .last = @splat(255),
        .country = .{ 'U', 'S' },
    }};
    for ([_][]const u8{
        "127.0.0.1",   "10.0.0.1",    "192.168.1.1", "100.64.0.1", "198.18.0.1",
        "192.0.2.1",   "203.0.113.1", "::1",         "fc00::1",    "fe80::1",
        "2001:db8::1",
    }) |ip| try std.testing.expect(lookup(&ranges, try address.parse(ip)) == null);
}

test "publisher unknown IPv6 super-ranges do not overlap normalized IPv4 countries" {
    const t = std.testing;
    var storage: [4]Range = undefined;
    var builder: Builder = .{ .storage = &storage };
    try builder.append("0.0.0.0,7.255.255.255,ZZ");
    try builder.append("8.8.8.0,8.8.8.255,US");
    try builder.append("::,1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,ZZ");
    try builder.append("2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US");
    const ranges = try builder.finish();
    try t.expectEqual(@as(usize, 2), ranges.len);
    try t.expectEqualStrings("US", &(lookup(ranges, try address.parse("8.8.8.8")).?));
    try t.expect(lookup(ranges, try address.parse("1.1.1.1")) == null);
}

test "transitionally reserved publisher codes load" {
    const t = std.testing;
    var storage: [2]Range = undefined;
    var builder: Builder = .{ .storage = &storage };
    try builder.append("192.0.1.0,192.0.1.255,FX");
    try builder.append("2001:678::,2001:678:ffff:ffff:ffff:ffff:ffff:ffff,AN");
    const ranges = try builder.finish();
    try t.expectEqualStrings("FX", &(lookup(ranges, try address.parse("192.0.1.7")).?));
}
