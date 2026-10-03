//! Providers publish the same `start,end,country` rows under different licences, version
//! syntaxes, compression and hosts. The library owns these facts so callers never embed
//! download URLs or attribution text.
const std = @import("std");
pub const Compression = enum { none, gzip };
pub const max_name = 12;
pub const max_version = 10;
pub const max_url = 160;
pub const max_files = 2;
const github = "https://github.com/sapics/ip-location-db/releases/download/";

pub const Provider = enum(u8) {
    user_country = 1,
    dbip = 2,

    pub fn parse(text: []const u8) ?Provider {
        inline for (std.enums.values(Provider)) |tag| {
            if (std.mem.eql(u8, text, tag.name())) return tag;
        }
        return null;
    }

    pub fn name(self: Provider) []const u8 {
        return switch (self) {
            .user_country => "user-country",
            .dbip => "dbip",
        };
    }

    pub fn title(self: Provider) []const u8 {
        return switch (self) {
            .user_country => "ip-location-db user-country",
            .dbip => "DB-IP IP to Country Lite",
        };
    }

    pub fn license(self: Provider) []const u8 {
        return switch (self) {
            .user_country => "PDDL 1.0",
            .dbip => "CC BY 4.0",
        };
    }

    /// Attribution link required by the licence, or null when none is required.
    pub fn attribution(self: Provider) ?[]const u8 {
        return switch (self) {
            .user_country => null,
            .dbip => "https://db-ip.com",
        };
    }

    pub fn attributionText(self: Provider) ?[]const u8 {
        return switch (self) {
            .user_country => null,
            .dbip => "IP Geolocation by DB-IP",
        };
    }

    pub fn homepage(self: Provider) []const u8 {
        return switch (self) {
            .user_country => "https://github.com/sapics/ip-location-db",
            .dbip => "https://db-ip.com/db/lite.php",
        };
    }

    pub fn compression(self: Provider) Compression {
        return switch (self) {
            .user_country => .none,
            .dbip => .gzip,
        };
    }

    pub fn fileCount(self: Provider) u8 {
        return switch (self) {
            .user_country => 2,
            .dbip => 1,
        };
    }

    pub fn versionSyntax(self: Provider) []const u8 {
        return switch (self) {
            .user_country => "YYYY-MM-DD",
            .dbip => "YYYY-MM",
        };
    }

    pub fn versionValid(self: Provider, text: []const u8) bool {
        return switch (self) {
            .user_country => validDate(text),
            .dbip => validMonth(text),
        };
    }

    pub fn fileName(self: Provider, file: u8, version: []const u8, buf: []u8) ![]const u8 {
        if (file >= self.fileCount() or !self.versionValid(version)) return error.InvalidInput;
        return switch (self) {
            .user_country => if (file == 0) "user-country-ipv4.csv" else "user-country-ipv6.csv",
            .dbip => std.fmt.bufPrint(buf, "dbip-country-lite-{s}.csv.gz", .{version}),
        };
    }

    pub fn url(self: Provider, file: u8, version: []const u8, buf: []u8) ![]const u8 {
        var name_buffer: [64]u8 = undefined;
        const file_name = try self.fileName(file, version, &name_buffer);
        return switch (self) {
            .user_country => std.fmt.bufPrint(buf, github ++ "latest/{s}", .{file_name}),
            .dbip => std.fmt.bufPrint(buf, "https://download.db-ip.com/free/{s}", .{file_name}),
        };
    }

    /// Publisher digest file for one source file, or null when the provider has none.
    pub fn checksumUrl(self: Provider, file: u8, version: []const u8, buf: []u8) !?[]const u8 {
        var name_buffer: [64]u8 = undefined;
        const file_name = try self.fileName(file, version, &name_buffer);
        return switch (self) {
            .user_country => try std.fmt.bufPrint(
                buf,
                github ++ "checksum/{s}.sha256",
                .{file_name},
            ),
            .dbip => null,
        };
    }

    /// Hosts that a single HTTPS redirect from the publisher URL may reach. Exact match.
    pub fn redirectAllowed(self: Provider, host: []const u8) bool {
        return switch (self) {
            .user_country => std.mem.eql(u8, host, "release-assets.githubusercontent.com") or
                std.mem.eql(u8, host, "objects.githubusercontent.com"),
            .dbip => false,
        };
    }
};

fn digits(text: []const u8) bool {
    for (text) |byte| if (!std.ascii.isDigit(byte)) return false;
    return text.len != 0;
}

pub fn validMonth(text: []const u8) bool {
    if (text.len != 7 or text[4] != '-' or !digits(text[0..4]) or !digits(text[5..7]))
        return false;
    const year = std.fmt.parseInt(u16, text[0..4], 10) catch return false;
    const month = std.fmt.parseInt(u8, text[5..7], 10) catch return false;
    return year >= 2000 and month >= 1 and month <= 12;
}

pub fn validDate(text: []const u8) bool {
    if (text.len != 10 or text[7] != '-' or !validMonth(text[0..7]) or !digits(text[8..10]))
        return false;
    const year = std.fmt.parseInt(u16, text[0..4], 10) catch return false;
    const month = std.fmt.parseInt(u8, text[5..7], 10) catch return false;
    const day = std.fmt.parseInt(u8, text[8..10], 10) catch return false;
    return day >= 1 and day <= daysInMonth(year, month);
}

fn daysInMonth(year: u16, month: u8) u8 {
    const leap = (year % 4 == 0 and year % 100 != 0) or year % 400 == 0;
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (leap) 29 else 28,
        else => 0,
    };
}

/// `<64 hex>  <name>` as written by sha256sum; the name must match the expected file.
pub fn parseChecksumFile(
    text: []const u8,
    expected_name: []const u8,
) error{InvalidChecksum}![32]u8 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len < 66 or trimmed.len > 256) return error.InvalidChecksum;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, trimmed[0..64]) catch return error.InvalidChecksum;
    var name = std.mem.trimStart(u8, trimmed[64..], " \t");
    if (name.len == trimmed.len - 64) return error.InvalidChecksum;
    if (name.len != 0 and name[0] == '*') name = name[1..];
    if (!std.mem.eql(u8, name, expected_name)) return error.InvalidChecksum;
    return digest;
}

test "provider names, versions and files are fixed by the library" {
    const t = std.testing;
    try t.expectEqual(Provider.user_country, Provider.parse("user-country").?);
    try t.expectEqual(Provider.dbip, Provider.parse("dbip").?);
    try t.expect(Provider.parse("maxmind") == null);
    try t.expect(Provider.user_country.versionValid("2026-09-09"));
    try t.expect(Provider.user_country.versionValid("2024-02-29"));
    try t.expect(!Provider.user_country.versionValid("2023-02-29"));
    try t.expect(!Provider.user_country.versionValid("2026-09"));
    try t.expect(!Provider.user_country.versionValid("2026-13-01"));
    try t.expect(Provider.dbip.versionValid("2026-09"));
    for ([_][]const u8{ "../evil", "2026-13", "2026-00", "2026- 1", "//a.b/c", "2026-09-09" }) |v|
        try t.expect(!Provider.dbip.versionValid(v));
    var buf: [max_url]u8 = undefined;
    try t.expectEqualStrings(
        github ++ "latest/user-country-ipv6.csv",
        try Provider.user_country.url(1, "2026-09-09", &buf),
    );
    try t.expectEqualStrings(
        github ++ "checksum/user-country-ipv4.csv.sha256",
        (try Provider.user_country.checksumUrl(0, "2026-09-09", &buf)).?,
    );
    try t.expectEqualStrings(
        "https://download.db-ip.com/free/dbip-country-lite-2026-09.csv.gz",
        try Provider.dbip.url(0, "2026-09", &buf),
    );
    try t.expect((try Provider.dbip.checksumUrl(0, "2026-09", &buf)) == null);
    try t.expectError(error.InvalidInput, Provider.dbip.url(1, "2026-09", &buf));
    try t.expectError(error.InvalidInput, Provider.user_country.url(0, "2026-09", &buf));
    try t.expect(Provider.user_country.redirectAllowed("release-assets.githubusercontent.com"));
    try t.expect(!Provider.user_country.redirectAllowed("evil.githubusercontent.com"));
    try t.expect(!Provider.dbip.redirectAllowed("release-assets.githubusercontent.com"));
    try t.expect(Provider.user_country.attribution() == null);
    try t.expectEqualStrings("https://db-ip.com", Provider.dbip.attribution().?);
}

test "publisher checksum files are matched by name" {
    const t = std.testing;
    const hex = "bc74ffee42cced41df6d64239b5227e874e4fd52a12f900830bab4ca391f4a6d";
    const name = "user-country-ipv4.csv";
    const digest = try parseChecksumFile(hex ++ "  " ++ name ++ "\n", name);
    try t.expectEqual(@as(u8, 0xbc), digest[0]);
    _ = try parseChecksumFile(hex ++ " *" ++ name, name);
    try t.expectError(error.InvalidChecksum, parseChecksumFile(hex ++ "  other.csv", name));
    try t.expectError(error.InvalidChecksum, parseChecksumFile(hex, name));
    try t.expectError(error.InvalidChecksum, parseChecksumFile("zz" ++ hex[2..] ++ "  x", "x"));
}
