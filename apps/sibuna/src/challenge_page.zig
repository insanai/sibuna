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

pub fn solverBlock() []const u8 {
    const start = std.mem.indexOf(u8, challenge_html, solver_start).?;
    const end = std.mem.indexOfPos(u8, challenge_html, start, solver_end).? + solver_end.len;
    return challenge_html[start..end];
}

test "the challenge default keeps the interstitial and isolates the solver block" {
    const t = std.testing;
    try t.expect(std.mem.indexOf(u8, default, "{{ challenge }}") != null);
    try t.expect(std.mem.indexOf(u8, default, "<script") == null);
    try t.expect(std.mem.startsWith(u8, solverBlock(), "<script>"));
    try t.expect(std.mem.indexOf(u8, solverBlock(), "/__sibuna/verify") != null);
}
