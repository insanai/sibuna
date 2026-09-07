//! DB-IP country ranges. Only the off-path collector may enrich request samples.
//! Parsing borrows caller-owned storage; activation must follow finish() success.
const std = @import("std");
pub const Error = error{
    InvalidRow,
    InvalidAddress,
    InvalidCountry,
    Unordered,
    Overlap,
    Capacity,
};
pub const Range = struct { first: [16]u8, last: [16]u8, country: [2]u8 };
const mapped = [_]u8{0} ** 10 ++ .{ 255, 255 };
const countries =
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO " ++
    "BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ " ++
    "DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP " ++
    "GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG " ++
    "KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML " ++
    "MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE " ++
    "PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL " ++
    "SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM " ++
    "US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW";

pub fn countryValid(code: []const u8) bool {
    if (code.len != 2) return false;
    if (std.mem.eql(u8, code, "ZZ")) return true;
    var i: usize = 0;
    while (i < countries.len) : (i += 3) {
        if (std.mem.eql(u8, countries[i..][0..2], code)) return true;
    }
    return false;
}

pub fn address(text: []const u8) Error![16]u8 {
    if (text.len == 0 or text.len > 45 or std.mem.indexOfScalar(u8, text, '%') != null)
        return error.InvalidAddress;
    const parsed = std.Io.net.IpAddress.parse(text, 0) catch return error.InvalidAddress;
    return switch (parsed) {
        .ip4 => |ip| mapped ++ ip.bytes,
        .ip6 => |ip| ip.bytes,
    };
}

fn column(text: []const u8) []const u8 {
    if (text.len >= 2 and text[0] == '"' and text[text.len - 1] == '"')
        return text[1 .. text.len - 1];
    return text;
}

pub fn parseRow(line: []const u8) Error!Range {
    if (line.len > 128) return error.InvalidRow;
    var columns = std.mem.splitScalar(u8, std.mem.trimEnd(u8, line, "\r"), ',');
    const first = column(columns.next() orelse return error.InvalidRow);
    const last = column(columns.next() orelse return error.InvalidRow);
    const country = column(columns.next() orelse return error.InvalidRow);
    if (columns.next() != null) return error.InvalidRow;
    if (!countryValid(country)) return error.InvalidCountry;
    const first_v4 = std.mem.indexOfScalar(u8, first, ':') == null;
    const last_v4 = std.mem.indexOfScalar(u8, last, ':') == null;
    if (first_v4 != last_v4) return error.InvalidAddress;
    const range: Range = .{
        .first = try address(first),
        .last = try address(last),
        .country = country[0..2].*,
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
        const last = if (std.mem.indexOfScalar(u8, line, ':') == null)
            &self.last_v4
        else
            &self.last_v6;
        if (last.*) |previous| {
            if (std.mem.order(u8, &range.first, &previous) != .gt) return error.Overlap;
        }
        last.* = range.last;
        self.rows += 1;
        // DB-IP includes broad ZZ ranges spanning the IPv4-mapped IPv6 region. Validate
        // source ordering, then omit these explicitly unknown ranges before normalization.
        if (std.mem.eql(u8, &range.country, "ZZ")) return;
        self.storage[self.count] = range;
        self.count += 1;
    }

    pub fn finish(self: *Builder) Error![]const Range {
        if (self.count == 0) return error.InvalidRow;
        const ranges = self.storage[0..self.count];
        // Publishers group IPv4 and IPv6 separately. Normalize before one binary search;
        // reject IPv4-mapped IPv6 overlaps as well as overlaps within either source family.
        std.sort.heap(Range, ranges, {}, less);
        for (ranges[1..], ranges[0 .. ranges.len - 1]) |current, previous| {
            if (std.mem.order(u8, &current.first, &previous.last) != .gt) return error.Overlap;
        }
        return ranges;
    }
};

fn less(_: void, a: Range, b: Range) bool {
    return std.mem.order(u8, &a.first, &b.first) == .lt;
}

pub fn lookup(ranges: []const Range, ip: [16]u8) ?[2]u8 {
    if (!publicAddress(ip)) return null;
    var lo: usize = 0;
    var hi = ranges.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (std.mem.order(u8, &ranges[mid].first, &ip) == .gt) {
            hi = mid;
        } else if (std.mem.order(u8, &ranges[mid].last, &ip) == .lt) {
            lo = mid + 1;
        } else return if (std.mem.eql(u8, &ranges[mid].country, "ZZ"))
            null
        else
            ranges[mid].country;
    }
    return null;
}

fn publicAddress(ip: [16]u8) bool {
    if (std.mem.startsWith(u8, &ip, &mapped)) {
        const a = ip[12];
        const b = ip[13];
        if (a == 0 or a == 10 or a == 127 or a >= 224) return false;
        if (a == 100 and b >= 64 and b <= 127) return false;
        if (a == 169 and b == 254) return false;
        if (a == 172 and b >= 16 and b <= 31) return false;
        if (a == 192 and (b == 168 or (b == 0 and (ip[14] == 0 or ip[14] == 2)))) return false;
        if (a == 192 and b == 88 and ip[14] == 99) return false;
        if (a == 198 and (b == 18 or b == 19 or (b == 51 and ip[14] == 100))) return false;
        if (a == 203 and b == 0 and ip[14] == 113) return false;
        return true;
    }
    // Only global unicast is eligible; special/documentation/transition space stays Unknown.
    if (ip[0] & 0xe0 != 0x20) return false;
    if (ip[0] == 0x3f and ip[1] == 0xff and ip[2] < 16) return false;
    if (ip[0] == 0x20 and ip[1] == 0x02) return false;
    if (ip[0] == 0x20 and ip[1] == 0x01) {
        if (ip[2] < 2 or (ip[2] == 0x0d and ip[3] == 0xb8)) return false;
    }
    return true;
}

test "DB-IP generations reject overlap, malformed input, and capacity overflow" {
    const t = std.testing;
    var storage: [3]Range = undefined;
    var builder: Builder = .{ .storage = &storage };
    try builder.append("\"8.8.8.0\",\"8.8.8.255\",\"US\"\r");
    try builder.append("2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US");
    try t.expectError(error.Overlap, builder.append("8.8.8.255,8.8.9.0,US"));
    try t.expectError(error.InvalidCountry, builder.append("9.0.0.0,9.0.0.1,AA"));
    try t.expectError(error.InvalidAddress, builder.append("9.0.0.0,2001:4860::,US"));
    try builder.append("9.0.0.0,9.0.0.255,DE");
    try t.expectError(error.Capacity, builder.append("10.0.0.0,10.0.0.1,US"));
    const ranges = try builder.finish();
    try t.expectEqualStrings("US", &(lookup(ranges, try address("8.8.8.255")).?));
    try t.expectEqualStrings("US", &(lookup(ranges, try address("::ffff:8.8.8.8")).?));
    try t.expectEqualStrings("US", &(lookup(ranges, try address("2001:4860::8888")).?));
    try t.expect(lookup(ranges, try address("8.8.9.0")) == null);
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
    }) |ip| try std.testing.expect(lookup(&ranges, try address(ip)) == null);
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
    try t.expectEqualStrings("US", &(lookup(ranges, try address("8.8.8.8")).?));
    try t.expect(lookup(ranges, try address("1.1.1.1")) == null);
}
