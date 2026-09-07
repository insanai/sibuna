//! Sibuna Streaming Reverse Proxy
//!
//! Streams approved HTTP requests to upstream backends and pipes response bytes
//! back to clients with zero dynamic heap allocations.

const std = @import("std");
const Io = std.Io;

pub fn streamProxy(
    client_stream: Io.net.Stream,
    io: Io,
    upstream_host: []const u8,
    upstream_port: u16,
    initial_request_data: []const u8,
) !void {
    const upstream_addr = try Io.net.IpAddress.parse(upstream_host, upstream_port);
    const upstream_stream = try upstream_addr.connect(io, .{ .mode = .stream });
    defer upstream_stream.close(io);

    var up_writer_buf: [4096]u8 = undefined;
    var up_writer = upstream_stream.writer(io, &up_writer_buf);
    try up_writer.interface.writeAll(initial_request_data);
    try up_writer.interface.flush();

    var up_reader_buf: [16 * 1024]u8 = undefined;
    var up_reader = upstream_stream.reader(io, &up_reader_buf);

    var client_writer_buf: [16 * 1024]u8 = undefined;
    var client_writer = client_stream.writer(io, &client_writer_buf);

    _ = up_reader.interface.streamRemaining(&client_writer.interface) catch {};
    try client_writer.interface.flush();
}
