//! Bounded definite-length OpenPGP framing and canonical unsigned MPIs.
const std = @import("std");
pub const Error = error{ TruncatedPacket, InvalidPacket, PartialPacket, InvalidMpi };
pub const Packet = struct { tag: u6, bytes: []const u8 };
pub const Mpi = struct { bits: u16, bytes: []const u8 };
pub const Reader = struct {
    bytes: []const u8,
    position: usize = 0,

    pub fn take(self: *Reader, length: usize) Error![]const u8 {
        if (length > self.bytes.len - self.position) return error.TruncatedPacket;
        const value = self.bytes[self.position..][0..length];
        self.position += length;
        return value;
    }

    pub fn integer(self: *Reader, comptime T: type) Error!T {
        const value = try self.take(@sizeOf(T));
        return std.mem.readInt(T, value[0..@sizeOf(T)], .big);
    }

    pub fn remaining(self: *const Reader) usize {
        return self.bytes.len - self.position;
    }

    pub fn mpi(self: *Reader, maximum: usize) Error!Mpi {
        const bits = try self.integer(u16);
        const length = (@as(usize, bits) + 7) / 8;
        if (bits == 0 or length > maximum) return error.InvalidMpi;
        const bytes = try self.take(length);
        // Leading zeros and inconsistent top-bit counts are not alternate encodings.
        const actual = length * 8 - @as(usize, @clz(bytes[0]));
        if (bytes[0] == 0 or actual != bits) return error.InvalidMpi;
        return .{ .bits = bits, .bytes = bytes };
    }

    pub fn packet(self: *Reader) Error!?Packet {
        if (self.remaining() == 0) return null;
        const header = try self.integer(u8);
        if (header & 0x80 == 0) return error.InvalidPacket;
        const modern = header & 0x40 != 0;
        const tag: u6 = @intCast(if (modern) header & 0x3f else (header >> 2) & 0xf);
        const length: usize = if (modern)
            try self.packetLength()
        else switch (header & 3) {
            0 => try self.integer(u8),
            1 => try self.integer(u16),
            2 => try self.integer(u32),
            3 => return error.PartialPacket,
            else => unreachable,
        };
        return .{ .tag = tag, .bytes = try self.take(length) };
    }

    /// Signature subpacket lengths use the same one/two/five-octet encoding,
    /// except 224..254 are ordinary two-octet lengths rather than partial packets.
    pub fn subpacketLength(self: *Reader) Error!usize {
        const first = try self.integer(u8);
        if (first < 192) return first;
        if (first == 255) return try self.integer(u32);
        return (@as(usize, first) - 192) * 256 + try self.integer(u8) + 192;
    }

    fn packetLength(self: *Reader) Error!usize {
        const first = try self.integer(u8);
        if (first < 192) return first;
        if (first <= 223)
            return (@as(usize, first) - 192) * 256 + try self.integer(u8) + 192;
        if (first == 255) return try self.integer(u32);
        return error.PartialPacket;
    }
};
