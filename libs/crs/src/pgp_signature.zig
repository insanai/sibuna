//! Narrow v4 binary-document signature profile for the pinned CRS primary key.
const std = @import("std");
const packet = @import("pgp_packet.zig");
const trust = @import("crs-trust");
pub const Error = packet.Error || error{
    UnsupportedSignature,
    InvalidSignature,
    InvalidSubpacket,
    UnknownCriticalSubpacket,
    WrongIssuer,
    MissingIssuer,
    InvalidSignatureTime,
    ExpiredSignature,
};
pub const Parsed = struct {
    hashed: []const u8,
    hash: enum { sha256, sha512 },
    prefix: *const [2]u8,
    mpi: []const u8,
    created: u32,
};
const Metadata = struct {
    issuer: bool = false,
    key_id: bool = false,
    created: ?u32 = null,
    expires: ?u32 = null,
};

pub fn parse(bytes: []const u8, key_created: u32, now: u64) Error!Parsed {
    var stream: packet.Reader = .{ .bytes = bytes };
    const envelope = (try stream.packet()) orelse return error.InvalidSignature;
    if (envelope.tag != 2 or stream.remaining() != 0) return error.InvalidSignature;
    var reader: packet.Reader = .{ .bytes = envelope.bytes };
    if (try reader.integer(u8) != 4 or try reader.integer(u8) != 0 or
        try reader.integer(u8) != 1) return error.UnsupportedSignature;
    const hash: @FieldType(Parsed, "hash") = switch (try reader.integer(u8)) {
        8 => .sha256,
        10 => .sha512,
        else => return error.UnsupportedSignature,
    };
    var metadata: Metadata = .{};
    const hashed_length = try reader.integer(u16);
    try subpackets(try reader.take(hashed_length), true, &metadata);
    const hashed_end = reader.position;
    const unhashed_length = try reader.integer(u16);
    try subpackets(try reader.take(unhashed_length), false, &metadata);
    const prefix = try reader.take(2);
    const signature = try reader.mpi(512);
    if (reader.remaining() != 0) return error.InvalidSignature;
    if (!metadata.issuer) return error.MissingIssuer;
    const created = metadata.created orelse return error.InvalidSignatureTime;
    if (created < key_created or (created > now and @as(u64, created) - now > 300))
        return error.InvalidSignatureTime;
    if (metadata.expires) |seconds| {
        if (seconds != 0 and now >= @as(u64, created) + seconds) return error.ExpiredSignature;
    }
    return .{
        .hashed = envelope.bytes[0..hashed_end],
        .hash = hash,
        .prefix = prefix[0..2],
        .mpi = signature.bytes,
        .created = created,
    };
}

fn subpackets(bytes: []const u8, hashed: bool, metadata: *Metadata) Error!void {
    var reader: packet.Reader = .{ .bytes = bytes };
    while (reader.remaining() != 0) {
        const size = try reader.subpacketLength();
        if (size == 0) return error.InvalidSubpacket;
        const payload = try reader.take(size);
        const kind = payload[0] & 0x7f;
        const value = payload[1..];
        switch (kind) {
            2, 3 => {
                if (!hashed or value.len != 4) return error.InvalidSubpacket;
                const slot = if (kind == 2) &metadata.created else &metadata.expires;
                if (slot.* != null) return error.InvalidSubpacket;
                slot.* = std.mem.readInt(u32, value[0..4], .big);
            },
            16 => {
                if (metadata.key_id or value.len != 8) return error.InvalidSubpacket;
                var identity: [20]u8 = undefined;
                _ = std.fmt.hexToBytes(&identity, trust.fingerprint) catch unreachable;
                if (!std.mem.eql(u8, value, identity[12..])) return error.WrongIssuer;
                metadata.key_id = true;
            },
            33 => {
                if (!hashed or metadata.issuer or value.len != 21 or value[0] != 4)
                    return error.InvalidSubpacket;
                var identity: [20]u8 = undefined;
                _ = std.fmt.hexToBytes(&identity, trust.fingerprint) catch unreachable;
                if (!std.mem.eql(u8, value[1..], &identity)) return error.WrongIssuer;
                metadata.issuer = true;
            },
            else => if (payload[0] & 0x80 != 0) return error.UnknownCriticalSubpacket,
        }
    }
}
