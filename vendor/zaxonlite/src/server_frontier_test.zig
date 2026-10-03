const std = @import("std");

pub fn check(comptime Node: type, comptime Server: type, comptime await_frontier: anytype) !void {
    // Model the state seen after a wake that settled the frontier while
    // failure or a higher ballot invalidated this request's admission.
    const Settled = struct {
        fn check(_: *const Node) bool {
            return true;
        }
    };
    var node: Node = undefined;
    var log: @typeInfo(@TypeOf(node.log)).pointer.child = undefined;
    node.log = &log;
    node.log.core.role = .leader;
    var server: Server = undefined;
    server.node = &node;
    server.frontier_waiters = 0;
    server.failed = true;
    server.shutdown_flag = .init(false);
    try std.testing.expectError(
        error.Unavailable,
        await_frontier(&server, Settled.check, 0),
    );
    server.failed = false;
    node.log.core.role = .follower;
    try std.testing.expectError(
        error.NotLeader,
        await_frontier(&server, Settled.check, 0),
    );
    node.log.core.role = .leader;
    try await_frontier(&server, Settled.check, 0);
    server.shutdown_flag.store(true, .release);
    try std.testing.expectError(
        error.Unavailable,
        await_frontier(&server, Settled.check, 0),
    );
    try std.testing.expectEqual(@as(u32, 0), server.frontier_waiters);
}
