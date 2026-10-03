//! Bounded client-family labels for sampled traffic: a small deterministic classifier over
//! the User-Agent value shared by the collector and the browser. Labels are display
//! families, never an admission input; an unrecognised agent stays unknown, not zero.
const std = @import("std");

pub const Os = enum(u8) { unknown, windows, macos, ios, android, linux, other, bot };
pub const Browser = enum(u8) { unknown, chrome, firefox, safari, edge, opera, bot, other };
pub const status_codes = [_]u16{
    200, 201, 204, 206, 301, 302, 304, 307, 308, 400, 401, 403,
    404, 405, 413, 429, 500, 502, 503, 504,
};
/// One histogram slot per listed status, then "other status", then "no status sampled".
pub const status_slots = status_codes.len + 2;

pub const Family = struct { os: Os = .unknown, browser: Browser = .unknown };

pub fn classify(agent: []const u8) Family {
    if (agent.len == 0) return .{};
    if (isBot(agent)) return .{ .os = .bot, .browser = .bot };
    return .{ .os = operatingSystem(agent), .browser = browser(agent) };
}

pub fn statusSlot(status: u16) usize {
    if (status == 0) return status_slots - 1;
    for (status_codes, 0..) |code, slot| if (code == status) return slot;
    return status_slots - 2;
}

pub fn statusLabel(slot: usize, buffer: *[8]u8) []const u8 {
    if (slot < status_codes.len)
        return std.fmt.bufPrint(buffer, "{d}", .{status_codes[slot]}) catch unreachable;
    return if (slot == status_codes.len) "other" else "none";
}

pub fn osLabel(os: Os) []const u8 {
    return switch (os) {
        .unknown => "Unknown",
        .windows => "Windows",
        .macos => "macOS",
        .ios => "iOS",
        .android => "Android",
        .linux => "Linux",
        .other => "Other",
        .bot => "Automated",
    };
}

pub fn browserLabel(value: Browser) []const u8 {
    return switch (value) {
        .unknown => "Unknown",
        .chrome => "Chrome",
        .firefox => "Firefox",
        .safari => "Safari",
        .edge => "Edge",
        .opera => "Opera",
        .bot => "Automated",
        .other => "Other",
    };
}

fn contains(agent: []const u8, needle: []const u8) bool {
    return std.ascii.findIgnoreCase(agent, needle) != null;
}

fn isBot(agent: []const u8) bool {
    const marks = [_][]const u8{
        "bot",   "crawl",      "spider", "curl/",    "wget/",   "python", "go-http",
        "java/", "httpclient", "scrapy", "headless", "monitor", "fetch",
    };
    for (marks) |mark| if (contains(agent, mark)) return true;
    return false;
}

fn operatingSystem(agent: []const u8) Os {
    if (contains(agent, "iphone") or contains(agent, "ipad") or contains(agent, "ipod"))
        return .ios;
    if (contains(agent, "android")) return .android;
    if (contains(agent, "windows")) return .windows;
    if (contains(agent, "mac os") or contains(agent, "macintosh")) return .macos;
    if (contains(agent, "cros") or contains(agent, "linux") or contains(agent, "x11"))
        return .linux;
    return if (contains(agent, "mozilla") or contains(agent, "opera")) .other else .unknown;
}

fn browser(agent: []const u8) Browser {
    if (contains(agent, "edg/") or contains(agent, "edge/") or contains(agent, "edga/") or
        contains(agent, "edgios/")) return .edge;
    if (contains(agent, "opr/") or contains(agent, "opera")) return .opera;
    if (contains(agent, "firefox/") or contains(agent, "fxios/")) return .firefox;
    if (contains(agent, "chrome/") or contains(agent, "crios/") or contains(agent, "chromium/"))
        return .chrome;
    if (contains(agent, "safari/") and contains(agent, "version/")) return .safari;
    return if (contains(agent, "mozilla")) .other else .unknown;
}

test "client families are deterministic, bounded and never invent a platform" {
    const t = std.testing;
    const cases = .{
        .{ "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " ++
            "Chrome/126.0 Safari/537.36 Edg/126.0", Os.windows, Browser.edge },
        .{ "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like " ++
            "Gecko) Version/17.5 Safari/605.1.15", Os.macos, Browser.safari },
        .{ "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 " ++
            "(KHTML, like Gecko) CriOS/126.0 Mobile/15E148 Safari/604.1", Os.ios, Browser.chrome },
        .{
            "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
            Os.linux,
            Browser.firefox,
        },
        .{ "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) " ++
            "Chrome/126.0 Mobile Safari/537.36 OPR/80.0", Os.android, Browser.opera },
        .{ "curl/8.6.0", Os.bot, Browser.bot },
        .{ "Googlebot/2.1 (+http://www.google.com/bot.html)", Os.bot, Browser.bot },
        .{ "", Os.unknown, Browser.unknown },
        .{ "SomethingElse/1.0", Os.unknown, Browser.unknown },
    };
    inline for (cases) |case| {
        const family = classify(case[0]);
        try t.expectEqual(case[1], family.os);
        try t.expectEqual(case[2], family.browser);
    }
    try t.expectEqual(@as(usize, 0), statusSlot(200));
    try t.expectEqual(status_slots - 2, statusSlot(418));
    try t.expectEqual(status_slots - 1, statusSlot(0));
    var buffer: [8]u8 = undefined;
    try t.expectEqualStrings("429", statusLabel(statusSlot(429), &buffer));
    try t.expectEqualStrings("none", statusLabel(status_slots - 1, &buffer));
}
