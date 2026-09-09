//! ISO 3166-1 alpha-2 codes accepted from publishers, plus the transitionally reserved
//! codes AN and FX that appear in published RIR-derived data. ZZ means unknown.
const std = @import("std");
const codes =
    "AD AE AF AG AI AL AM AN AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM " ++
    "BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY " ++
    "CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR FX GA GB GD GE GF GG GH " ++
    "GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT " ++
    "JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC " ++
    "MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL " ++
    "NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB " ++
    "SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM " ++
    "TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW";
pub const unknown = [2]u8{ 'Z', 'Z' };
pub const count = (codes.len + 1) / 3;

pub fn valid(code: []const u8) bool {
    if (code.len != 2) return false;
    if (std.mem.eql(u8, code, &unknown)) return true;
    var i: usize = 0;
    while (i < codes.len) : (i += 3) {
        if (std.mem.eql(u8, codes[i..][0..2], code)) return true;
    }
    return false;
}

pub fn isUnknown(code: [2]u8) bool {
    return std.mem.eql(u8, &code, &unknown);
}

/// Dense index over the 26×26 uppercase alphabet for fixed-size per-country tables.
pub fn index(code: [2]u8) ?u16 {
    if (code[0] < 'A' or code[0] > 'Z' or code[1] < 'A' or code[1] > 'Z') return null;
    return @as(u16, code[0] - 'A') * 26 + (code[1] - 'A');
}

pub fn nth(n: usize) [2]u8 {
    std.debug.assert(n < count);
    return codes[n * 3 ..][0..2].*;
}

test "assigned and transitionally reserved codes validate, others do not" {
    const t = std.testing;
    for ([_][]const u8{ "US", "DE", "ZZ", "AN", "FX", "XK", "ZW", "AD" }) |code|
        try t.expect(valid(code));
    for ([_][]const u8{ "AA", "us", "", "USA", "Z", "QQ" }) |code| try t.expect(!valid(code));
    try t.expectEqual(@as(?u16, 0), index(.{ 'A', 'A' }));
    try t.expectEqual(@as(?u16, 675), index(.{ 'Z', 'Z' }));
    try t.expect(index(.{ 'a', 'A' }) == null);
    try t.expectEqualStrings("AD", &nth(0));
    try t.expectEqualStrings("ZW", &nth(count - 1));
    try t.expect(isUnknown(unknown));
}
