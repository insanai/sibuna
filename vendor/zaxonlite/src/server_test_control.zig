//! Failpoint-gated runtime controls used only by process test harnesses.

const Io = @import("std").Io;
const failpoint = @import("failpoint.zig");

pub const Action = enum { arm_failpoint, set_vote_delay };

pub fn apply(
    server: anytype,
    action: Action,
    name: ?[]const u8,
    delay_ms: ?u64,
    out: *Io.Writer,
) !void {
    if (!server.options.enable_failpoints) {
        return writeError(out, switch (action) {
            .arm_failpoint => "failpoints disabled",
            .set_vote_delay => "test controls disabled",
        });
    }
    switch (action) {
        .arm_failpoint => failpoint.arm(name orelse ""),
        .set_vote_delay => {
            const delay = delay_ms orelse return writeError(out, "delay_ms is required");
            server.mutex.lockUncancelable(server.io);
            server.options.test_faults.vote_delay_ms = delay;
            server.mutex.unlock(server.io);
        },
    }
    try out.writeAll("{\"ok\":true}");
}

fn writeError(out: *Io.Writer, message: []const u8) !void {
    try out.print(
        "{{\"ok\":false,\"error\":\"bad_request\",\"message\":\"{s}\"}}",
        .{message},
    );
}
