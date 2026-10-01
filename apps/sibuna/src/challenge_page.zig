//! The embedded challenge interstitial split into its template default (with the solver
//! script replaced by the fixed `{{ challenge }}` slot) and the solver block itself, which the
//! daemon supplies at render time and no operator template can alter.
const std = @import("std");
const challenge_html = @embedFile("challenge_html");
const solver_start = "<script>";
const solver_end = "</script>";

pub const default = blk: {
    @setEvalBranchQuota(200_000);
    const start = std.mem.indexOf(u8, challenge_html, solver_start).?;
    const end = std.mem.indexOfPos(u8, challenge_html, start, solver_end).? + solver_end.len;
    break :blk challenge_html[0..start] ++ "{{ challenge }}" ++ challenge_html[end..];
};

/// Only the fixed solver script is executable; edited page markup cannot acquire authority
/// by sharing the protected application's origin. Worker and verification URLs stay local.
pub const security_policy = blk: {
    @setEvalBranchQuota(1_000_000);
    const start = std.mem.indexOf(u8, challenge_html, solver_start).? + solver_start.len;
    const end = std.mem.indexOfPos(u8, challenge_html, start, solver_end).?;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(challenge_html[start..end], &digest, .{});
    var encoded: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &digest);
    break :blk "Content-Security-Policy: default-src 'none'; base-uri 'none'; " ++
        "form-action 'none'; frame-ancestors 'none'; style-src 'unsafe-inline'; " ++
        "img-src 'self'; connect-src 'self'; worker-src 'self'; script-src 'sha256-" ++
        encoded ++ "'\r\n";
};

const solver_block = blk: {
    @setEvalBranchQuota(200_000);
    const start = std.mem.indexOf(u8, challenge_html, solver_start).?;
    const end = std.mem.indexOfPos(u8, challenge_html, start, solver_end).? + solver_end.len;
    break :blk challenge_html[start..end];
};

pub fn solverBlock() []const u8 {
    return solver_block;
}

const requirement_open = "<div hidden id=\"sibuna-requirement\" data-ticket=\"";
const requirement_close = "\"></div>";
const ticket_capacity = 64;
pub const block_capacity = requirement_open.len + ticket_capacity + requirement_close.len +
    solver_block.len;

/// The slot's contents: the requirement the challenged request was given, as inert markup the
/// fixed solver reads, then the solver itself. Tickets are base64url, so nothing needs
/// escaping; any other text is left out rather than written into the attribute.
pub fn block(ticket: []const u8, out: *[block_capacity]u8) []const u8 {
    var w: std.Io.Writer = .fixed(out);
    if (ticket.len != 0 and ticket.len <= ticket_capacity and urlSafe(ticket)) {
        w.writeAll(requirement_open) catch unreachable;
        w.writeAll(ticket) catch unreachable;
        w.writeAll(requirement_close) catch unreachable;
    }
    w.writeAll(solver_block) catch unreachable;
    return w.buffered();
}

fn urlSafe(text: []const u8) bool {
    for (text) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return false;
    }
    return true;
}

test "the challenge default keeps the interstitial and isolates the solver block" {
    const t = std.testing;
    try t.expect(std.mem.indexOf(u8, default, "{{ challenge }}") != null);
    try t.expect(std.mem.indexOf(u8, default, "<script") == null);
    try t.expect(std.mem.startsWith(u8, solverBlock(), "<script>"));
    try t.expect(std.mem.indexOf(u8, solverBlock(), "/__sibuna/verify") != null);
    var out: [block_capacity]u8 = undefined;
    const carried = block("abc-_9", &out);
    try t.expect(std.mem.startsWith(u8, carried, requirement_open ++ "abc-_9\""));
    try t.expect(std.mem.endsWith(u8, carried, solverBlock()));
    try t.expectEqualStrings(solverBlock(), block("\"><script>", &out));
}
