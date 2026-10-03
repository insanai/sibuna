//! Pre-parse refusals have no request owner or worker. Keep their accept-loop cost bounded
//! while allowing bytes sent concurrently with the response to be discarded before close.
const std = @import("std");
const connect = @import("connect.zig");

pub fn send(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8) !void {
    const deadline = std.Io.Clock.awake.now(io).nanoseconds + 100 * std.time.ns_per_ms;
    try connect.writeBounded(io, stream, bytes, deadline);
    try stream.shutdown(io, .send);
    // The peer can receive the complete response and EOF immediately. It normally closes
    // then; a peer withholding input/close gets no more than this same absolute budget.
    // Closing over unread input can reset TCP and discard the response on Windows.
    var discarded: [64 * 1024]u8 = undefined;
    _ = connect.readBounded(io, stream, &discarded, deadline) catch return;
}
