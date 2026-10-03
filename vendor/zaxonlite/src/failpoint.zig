//! Crash failpoints for the mandatory crash matrix.
//!
//! A failpoint terminates the process with `_exit`-like abruptness (no
//! deferred cleanup, no flushing) to model SIGKILL at a precise point in
//! the write path. Two arming mechanisms exist:
//!
//! * the `ZAXON_FAILPOINT` environment variable, read on every check, for
//!   single-process tests that arm before spawning; and
//! * `arm()`, used by the `zaxon serve` failpoint RPC so a cluster test
//!   controller can arm the current leader at runtime. The RPC is only
//!   honored when the server was started with failpoints enabled.
//!
//! Checks are free when nothing is armed beyond one atomic load.

const std = @import("std");
const builtin = @import("builtin");

var armed_len = std.atomic.Value(usize).init(0);
var armed_name: [64]u8 = undefined;

/// Arms `name` for the next matching `hit`. Empty disarms.
pub fn arm(name: []const u8) void {
    const len = @min(name.len, armed_name.len);
    @memcpy(armed_name[0..len], name[0..len]);
    armed_len.store(len, .release);
}

/// Terminates the process if `name` is armed via `arm` or the
/// `ZAXON_FAILPOINT` environment variable.
pub fn hit(name: []const u8) void {
    const len = armed_len.load(.acquire);
    if (len > 0 and std.mem.eql(u8, armed_name[0..len], name)) {
        crash(name);
    }
    // getenv is only consulted when libc is linked (always, for SQLite).
    const raw = std.c.getenv("ZAXON_FAILPOINT") orelse return;
    if (std.mem.eql(u8, std.mem.span(raw), name)) crash(name);
}

fn crash(name: []const u8) noreturn {
    // Both paths must skip the C runtime's exit handlers: flushing stdio
    // or running destructors would defeat the point of modeling SIGKILL.
    if (comptime builtin.os.tag == .windows) {
        std.debug.print("zaxon: failpoint '{s}' hit\n", .{name});
        std.os.windows.ntdll.RtlExitUserProcess(137);
    }
    var buffer: [96]u8 = undefined;
    const message = std.fmt.bufPrint(
        &buffer,
        "zaxon: failpoint '{s}' hit\n",
        .{name},
    ) catch "zaxon: failpoint hit\n";
    _ = std.c.write(2, message.ptr, message.len);
    std.c._exit(137);
}
