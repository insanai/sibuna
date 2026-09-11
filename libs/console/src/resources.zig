//! Process resource gauges read on the console tick, never on a request thread. Resident
//! memory is a gauge (last and peak); CPU is cumulative process time whose per-interval delta
//! becomes a rate. A platform without a current-RSS source reports it unavailable, not zero.
const std = @import("std");
const builtin = @import("builtin");

pub const Sample = struct {
    rss_kib: ?u64 = null,
    rss_max_kib: ?u64 = null,
    cpu_ms: u64 = 0,
};

pub fn sample(io: std.Io) Sample {
    const usage = std.posix.getrusage(0);
    const peak: u64 = @intCast(@max(0, usage.maxrss));
    return .{
        .rss_kib = resident(io),
        // Linux reports the peak in KiB, the Darwin family in bytes.
        .rss_max_kib = if (builtin.os.tag == .linux) peak else peak / 1024,
        .cpu_ms = milliseconds(usage.utime) + milliseconds(usage.stime),
    };
}

fn milliseconds(value: anytype) u64 {
    const seconds: u64 = @intCast(@max(0, value.sec));
    const micro: u64 = @intCast(@max(0, value.usec));
    return seconds * 1000 + micro / 1000;
}

fn resident(io: std.Io) ?u64 {
    if (builtin.os.tag != .linux) return null;
    var buffer: [4096]u8 = undefined;
    const text = std.Io.Dir.cwd().readFile(io, "/proc/self/status", &buffer) catch return null;
    return parseResident(text);
}

fn parseResident(text: []const u8) ?u64 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "VmRSS:")) continue;
        var words = std.mem.tokenizeAny(u8, line["VmRSS:".len..], " \t");
        const number = words.next() orelse return null;
        if (!std.mem.eql(u8, words.next() orelse "", "kB")) return null;
        return std.fmt.parseInt(u64, number, 10) catch null;
    }
    return null;
}

test "resource samples are monotonic in CPU time and parse the Linux status line" {
    const t = std.testing;
    const first = sample(t.io);
    try t.expect(first.rss_max_kib.? > 0);
    try t.expect(sample(t.io).cpu_ms >= first.cpu_ms);
    try t.expectEqual(@as(?u64, 5120), parseResident("VmPeak:\t9000 kB\nVmRSS:\t   5120 kB\n"));
    try t.expect(parseResident("VmRSS: 5120 MB\n") == null);
    try t.expect(parseResident("VmSize: 1 kB\n") == null);
}
