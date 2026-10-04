const std = @import("std");
const armor = @import("pgp_armor.zig");
const packet = @import("pgp_packet.zig");
const signature = @import("pgp_signature.zig");
const release = @import("release_signature.zig");
const trust = @import("crs-trust");
const created = 1791049738;

test "pinned trust anchor and upstream signature metadata have the expected identities" {
    var scratch: release.Scratch = .{};
    const verifier = try release.Verifier.init(&scratch);
    try std.testing.expectEqual(@as(u32, 1571582197), verifier.created);
    const bytes = try armor.decode(
        trust.signature,
        .signature,
        &scratch.encoded,
        &scratch.decoded,
    );
    const parsed = try signature.parse(bytes, verifier.created, created);
    try std.testing.expectEqual(@as(u32, created), parsed.created);
    try std.testing.expectEqual(@as(usize, 512), parsed.mpi.len);
    try std.testing.expect(parsed.hash == .sha512);
    try std.testing.expectError(
        error.InvalidSignatureTime,
        signature.parse(bytes, verifier.created, created - 301),
    );
    try std.testing.expectError(
        error.InvalidSignature,
        verifier.verify("incorrect archive bytes", trust.signature, created, &scratch),
    );
    try std.testing.expectError(
        error.ArchiveLimit,
        verifier.verify("", trust.signature, created, &scratch),
    );
}

test "armor ignores missing disagreeing and malformed CRC footers without trusting them" {
    var encoded: [16]u8 = undefined;
    var decoded: [16]u8 = undefined;
    for ([_][]const u8{ "", "=AAAA\n", "=malformed\n" }) |checksum| {
        const text = try std.fmt.allocPrint(
            std.testing.allocator,
            "-----BEGIN PGP SIGNATURE-----\n\nAQID\n{s}-----END PGP SIGNATURE-----\n",
            .{checksum},
        );
        defer std.testing.allocator.free(text);
        const result = try armor.decode(text, .signature, &encoded, &decoded);
        try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, result);
    }
    try std.testing.expectError(error.InvalidArmor, armor.decode(
        "-----BEGIN PGP SIGNATURE-----\n\nAQID\n",
        .signature,
        &encoded,
        &decoded,
    ));
    try std.testing.expectError(error.ArmorLimit, armor.decode(
        "-----BEGIN PGP SIGNATURE-----\n\nAQID\n-----END PGP SIGNATURE-----\n",
        .signature,
        &encoded,
        decoded[0..2],
    ));
}

test "packet reader refuses partial indeterminate truncated and noncanonical MPI encodings" {
    for ([_][]const u8{ &.{ 0xc2, 224 }, &.{0x8b} }) |bytes| {
        var reader: packet.Reader = .{ .bytes = bytes };
        try std.testing.expectError(error.PartialPacket, reader.packet());
    }
    var invalid: packet.Reader = .{ .bytes = &.{ 0, 0 } };
    try std.testing.expectError(error.InvalidPacket, invalid.packet());
    var truncated: packet.Reader = .{ .bytes = &.{ 0xc2, 255, 0, 0, 1, 0 } };
    try std.testing.expectError(error.TruncatedPacket, truncated.packet());
    for ([_][]const u8{ &.{ 0, 0 }, &.{ 0, 8, 1 }, &.{ 0, 9, 0, 1 } }) |bytes| {
        var reader: packet.Reader = .{ .bytes = bytes };
        try std.testing.expectError(error.InvalidMpi, reader.mpi(512));
    }
    var valid: packet.Reader = .{ .bytes = &.{ 0, 9, 1, 0 } };
    const mpi = try valid.mpi(512);
    try std.testing.expectEqual(@as(u16, 9), mpi.bits);
}

fn identity(output: *[29]u8) []const u8 {
    output.* = .{ 5, 2, 0x6a, 0xc1, 0x40, 0x0a, 22, 33, 4 } ++ @as([20]u8, @splat(0));
    _ = std.fmt.hexToBytes(output[9..], trust.fingerprint) catch unreachable;
    return output;
}

fn document(hashed: []const u8, unhashed: []const u8, output: []u8) []const u8 {
    const length = 13 + hashed.len + unhashed.len;
    output[0] = 0xc2;
    output[1] = 255;
    std.mem.writeInt(u32, output[2..6], @intCast(length), .big);
    @memcpy(output[6..10], &[_]u8{ 4, 0, 1, 10 });
    std.mem.writeInt(u16, output[10..12], @intCast(hashed.len), .big);
    @memcpy(output[12..][0..hashed.len], hashed);
    const offset = 12 + hashed.len;
    std.mem.writeInt(u16, output[offset..][0..2], @intCast(unhashed.len), .big);
    @memcpy(output[offset + 2 ..][0..unhashed.len], unhashed);
    @memcpy(output[offset + 2 + unhashed.len ..][0..5], &[_]u8{ 0, 0, 0, 1, 1 });
    return output[0 .. 6 + length];
}

test "signature metadata requires protected identity time and understood critical fields" {
    var protected: [29]u8 = undefined;
    const base = identity(&protected);
    var bytes: [256]u8 = undefined;
    const parsed = try signature.parse(document(base, &.{}, &bytes), 0, created);
    try std.testing.expectEqual(@as(u32, created), parsed.created);
    var altered = protected;
    altered[9] ^= 1;
    try std.testing.expectError(
        error.WrongIssuer,
        signature.parse(document(&altered, &.{}, &bytes), 0, created),
    );
    try std.testing.expectError(
        error.MissingIssuer,
        signature.parse(document(base[0..6], &.{}, &bytes), 0, created),
    );
    try std.testing.expectError(
        error.InvalidSubpacket,
        signature.parse(document(base, base[0..6], &bytes), 0, created),
    );
    const critical = protected ++ @as([3]u8, .{ 2, 0xe4, 0 });
    try std.testing.expectError(
        error.UnknownCriticalSubpacket,
        signature.parse(document(&critical, &.{}, &bytes), 0, created),
    );
    const duplicate = protected ++ protected[0..6].*;
    try std.testing.expectError(
        error.InvalidSubpacket,
        signature.parse(document(&duplicate, &.{}, &bytes), 0, created),
    );
    const expires = protected ++ @as([6]u8, .{ 5, 3, 0, 0, 0, 1 });
    try std.testing.expectError(
        error.ExpiredSignature,
        signature.parse(document(&expires, &.{}, &bytes), 0, created + 1),
    );
}

test "every truncated upstream signature is refused and appended packets cannot hide" {
    var scratch: release.Scratch = .{};
    const bytes = try armor.decode(
        trust.signature,
        .signature,
        &scratch.encoded,
        &scratch.decoded,
    );
    for (0..bytes.len) |length| {
        if (signature.parse(bytes[0..length], 0, created)) |_| {
            return error.TestUnexpectedResult;
        } else |err| {
            try std.testing.expect(err == error.InvalidSignature or err == error.TruncatedPacket);
        }
    }
    scratch.decoded[bytes.len] = 0xc2;
    scratch.decoded[bytes.len + 1] = 0;
    try std.testing.expectError(
        error.InvalidSignature,
        signature.parse(scratch.decoded[0 .. bytes.len + 2], 0, created),
    );
}
