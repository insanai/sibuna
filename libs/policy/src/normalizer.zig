//! Sibuna WAF Normalization & Canonicalization Engine
//!
//! Provides zero-allocation, multi-pass decoding, comment stripping, and
//! whitespace collapsing to neutralize evasion attacks before WAF inspection.

const std = @import("std");

fn hexVal(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return null;
}

/// Decodes percent-encoded characters (%20 -> ' ', %27 -> ''', etc.)
pub fn percentDecode(input: []const u8, out: []u8) []const u8 {
    var in_i: usize = 0;
    var out_i: usize = 0;
    while (in_i < input.len and out_i < out.len) {
        if (input[in_i] == '%' and in_i + 2 < input.len) {
            const h1 = hexVal(input[in_i + 1]);
            const h2 = hexVal(input[in_i + 2]);
            if (h1 != null and h2 != null) {
                out[out_i] = (h1.? << 4) | h2.?;
                out_i += 1;
                in_i += 3;
                continue;
            }
        } else if (input[in_i] == '+') {
            out[out_i] = ' ';
            out_i += 1;
            in_i += 1;
            continue;
        }
        out[out_i] = input[in_i];
        out_i += 1;
        in_i += 1;
    }
    return out[0..out_i];
}

/// Strips C-style inline SQL comments (/* ... */) and replaces them with a space.
pub fn stripSqlComments(input: []const u8, out: []u8) []const u8 {
    var in_i: usize = 0;
    var out_i: usize = 0;
    while (in_i < input.len and out_i < out.len) {
        if (in_i + 1 < input.len and input[in_i] == '/' and input[in_i + 1] == '*') {
            in_i += 2;
            while (in_i + 1 < input.len and !(input[in_i] == '*' and input[in_i + 1] == '/')) {
                in_i += 1;
            }
            if (in_i + 1 < input.len) in_i += 2;
            out[out_i] = ' ';
            out_i += 1;
            continue;
        }
        out[out_i] = input[in_i];
        out_i += 1;
        in_i += 1;
    }
    return out[0..out_i];
}

/// Collapses consecutive whitespace (spaces, tabs, newlines) into a single space.
pub fn collapseWhitespace(input: []const u8, out: []u8) []const u8 {
    var in_i: usize = 0;
    var out_i: usize = 0;
    var in_ws = false;

    while (in_i < input.len and out_i < out.len) {
        const c = input[in_i];
        const is_ws = (c == ' ' or c == '\t' or c == '\r' or c == '\n' or c == 0x0b or c == 0x0c);
        if (is_ws) {
            if (!in_ws) {
                out[out_i] = ' ';
                out_i += 1;
                in_ws = true;
            }
        } else {
            out[out_i] = c;
            out_i += 1;
            in_ws = false;
        }
        in_i += 1;
    }
    return out[0..out_i];
}

/// Full canonicalization pipeline: multi-pass percent-decode, comment strip,
/// whitespace collapse, and ASCII lowercase normalization.
pub fn canonicalize(input: []const u8, out: []u8) []const u8 {
    // Every stage only shrinks its input, so all passes can share the
    // caller's buffer without fixed-size intermediate truncation.
    const pass1 = percentDecode(input, out);
    const pass2 = if (std.mem.indexOfScalar(u8, pass1, '%') != null)
        percentDecode(pass1, out)
    else
        pass1;
    const pass3 = stripSqlComments(pass2, out);
    const pass4 = collapseWhitespace(pass3, out);

    // Pass 5: Lowercase in-place
    for (out[0..pass4.len]) |*b| {
        b.* = std.ascii.toLower(b.*);
    }
    return out[0..pass4.len];
}

test "percentDecode decodes standard and plus encodings" {
    var buf: [128]u8 = undefined;
    const res = percentDecode("hello%20world%27+test", &buf);
    try std.testing.expectEqualStrings("hello world' test", res);
}

test "stripSqlComments replaces comments with single space" {
    var buf: [128]u8 = undefined;
    const res = stripSqlComments("UNION/**/SELECT/**/1", &buf);
    try std.testing.expectEqualStrings("UNION SELECT 1", res);
}

test "collapseWhitespace collapses whitespace variations" {
    var buf: [128]u8 = undefined;
    const res = collapseWhitespace("SELECT  \t\r\n  FROM   users", &buf);
    try std.testing.expectEqualStrings("SELECT FROM users", res);
}

test "canonicalize normalizes obfuscated SQL injection" {
    var buf: [256]u8 = undefined;
    const res = canonicalize("1%27/**/UnIoN/**/SeLeCt/**/1", &buf);
    try std.testing.expectEqualStrings("1' union select 1", res);
}

test "canonicalize decodes double-encoded path traversal" {
    var buf: [256]u8 = undefined;
    const res = canonicalize("/api/%252e%252e/%252e%252e/etc/passwd", &buf);
    try std.testing.expectEqualStrings("/api/../../etc/passwd", res);
}
