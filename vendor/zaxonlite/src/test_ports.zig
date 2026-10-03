//! Collision-resistant loopback port reservations for process controllers.
//!
//! Asking the kernel for port zero avoids guessing from a shared fixed range.
//! Keeping every bound socket open until its child is spawned also prevents a
//! second reservation in this process, or an unrelated process, from taking
//! one of the later ports during controller setup. Reservations deliberately
//! do not listen: peers must see connection refusal, not connect to an inert
//! test-controller socket before the real node starts. The final
//! close-to-spawn handoff is necessarily non-atomic unless the product accepts
//! inherited sockets, but its race is limited to that one direct handoff.

const std = @import("std");
const Io = std.Io;

pub const FourReservations = struct {
    sockets: [4]?std.Io.net.Socket = @as([4]?std.Io.net.Socket, @splat(null)),
    ports: [4]u16 = undefined,

    pub fn init(io: Io) !FourReservations {
        var reservations = FourReservations{};
        errdefer reservations.deinit(io);

        const loopback = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        for (&reservations.sockets, &reservations.ports) |*slot, *port| {
            slot.* = try loopback.bind(io, .{ .mode = .stream });
            port.* = slot.*.?.address.getPort();
        }
        return reservations;
    }

    pub fn release(self: *FourReservations, io: Io, index: usize) void {
        if (self.sockets[index]) |*socket| {
            socket.close(io);
            self.sockets[index] = null;
        }
    }

    pub fn deinit(self: *FourReservations, io: Io) void {
        for (0..self.sockets.len) |index| self.release(io, index);
    }
};

test "four ports are distinct and unavailable while reserved" {
    const io = std.testing.io;
    var reservations = try FourReservations.init(io);
    defer reservations.deinit(io);

    for (reservations.ports, 0..) |port, index| {
        try std.testing.expect(port != 0);
        for (reservations.ports[index + 1 ..]) |other| {
            try std.testing.expect(port != other);
        }

        const address = try std.Io.net.IpAddress.parse("127.0.0.1", port);
        if (address.listen(io, .{ .reuse_address = true })) |server| {
            var listener = server;
            listener.deinit(io);
            return error.TestUnexpectedResult;
        } else |err| try std.testing.expectEqual(error.AddressInUse, err);
    }
}
