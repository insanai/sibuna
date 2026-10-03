//! Leader admission after a condition-variable wake, with the host mutex held.

pub fn awaitReady(
    server: anytype,
    comptime settled: anytype,
    start_tick: u64,
    timeout_ms: u64,
) error{ Unavailable, NotLeader, OpTimeoutQueued }!void {
    server.frontier_waiters += 1;
    defer server.frontier_waiters -= 1;
    while (true) {
        // A wake can both settle the frontier and demote or fail the
        // node. Recheck admission before accepting the settled state.
        if (server.failed or server.shutdown_flag.load(.acquire)) return error.Unavailable;
        if (!server.node.isLeader()) return error.NotLeader;
        if (settled(server.node)) return;
        const elapsed_ms = (server.tick_count -| start_tick) * server.options.tick_ms;
        if (elapsed_ms > timeout_ms) return error.OpTimeoutQueued;
        server.frontier_cond.waitUncancelable(server.io, &server.mutex);
    }
}
