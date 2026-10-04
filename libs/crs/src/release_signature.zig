//! Portable release verification. This runs off-path on bounded archive bytes;
//! trust is compiled in and RSA padding verification belongs to std.crypto.
const std = @import("std");
const armor = @import("pgp_armor.zig");
const packet = @import("pgp_packet.zig");
const signature = @import("pgp_signature.zig");
const trust = @import("crs-trust");
const buffers = @import("buffers.zig");
const rsa = std.crypto.Certificate.rsa;
pub const Error = armor.Error || signature.Error || error{
    InvalidTrustAnchor,
    ArchiveLimit,
};
pub const Scratch = struct {
    encoded: [8192]u8 = undefined,
    decoded: [4096]u8 = undefined,
};
pub const Receipt = struct {
    digest: [32]u8,
    created: u32,
    archive_bytes: usize,
};
pub const Verifier = struct {
    key: rsa.PublicKey,
    created: u32,

    pub fn init(scratch: *Scratch) Error!Verifier {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(trust.key, &digest, .{});
        var expected: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&expected, trust.key_sha256) catch unreachable;
        if (!std.mem.eql(u8, &digest, &expected)) return error.InvalidTrustAnchor;
        const bytes = try armor.decode(trust.key, .key, &scratch.encoded, &scratch.decoded);
        var stream: packet.Reader = .{ .bytes = bytes };
        const primary = (try stream.packet()) orelse return error.InvalidTrustAnchor;
        if (primary.tag != 6) return error.InvalidTrustAnchor;
        var reader: packet.Reader = .{ .bytes = primary.bytes };
        if (try reader.integer(u8) != 4) return error.InvalidTrustAnchor;
        const created = try reader.integer(u32);
        if (try reader.integer(u8) != 1) return error.InvalidTrustAnchor;
        const modulus = try reader.mpi(512);
        const exponent = try reader.mpi(3);
        if (modulus.bits != 4096 or reader.remaining() != 0 or
            !std.mem.eql(u8, exponent.bytes, &.{ 1, 0, 1 })) return error.InvalidTrustAnchor;
        var framing: [3]u8 = .{ 0x99, 0, 0 };
        std.mem.writeInt(u16, framing[1..3], @intCast(primary.bytes.len), .big);
        var hash = std.crypto.hash.Sha1.init(.{});
        hash.update(&framing);
        hash.update(primary.bytes);
        var fingerprint: [20]u8 = undefined;
        hash.final(&fingerprint);
        var pinned: [20]u8 = undefined;
        _ = std.fmt.hexToBytes(&pinned, trust.fingerprint) catch unreachable;
        if (!std.mem.eql(u8, &fingerprint, &pinned)) return error.InvalidTrustAnchor;
        return .{
            .key = rsa.PublicKey.fromBytes(exponent.bytes, modulus.bytes) catch
                return error.InvalidTrustAnchor,
            .created = created,
        };
    }

    pub fn verify(
        self: *const Verifier,
        archive: []const u8,
        armored: []const u8,
        now: u64,
        scratch: *Scratch,
    ) Error!Receipt {
        buffers.assertExclusive(&.{ archive, armored, &scratch.encoded, &scratch.decoded });
        if (archive.len == 0 or archive.len > 8 * 1024 * 1024) return error.ArchiveLimit;
        const bytes = try armor.decode(armored, .signature, &scratch.encoded, &scratch.decoded);
        const parsed = try signature.parse(bytes, self.created, now);
        var trailer: [6]u8 = .{ 4, 0xff, 0, 0, 0, 0 };
        std.mem.writeInt(u32, trailer[2..6], @intCast(parsed.hashed.len), .big);
        var padded: [512]u8 = @splat(0);
        @memcpy(padded[padded.len - parsed.mpi.len ..], parsed.mpi);
        const parts = [_][]const u8{ archive, parsed.hashed, &trailer };
        switch (parsed.hash) {
            .sha256 => try check(
                std.crypto.hash.sha2.Sha256,
                self.key,
                &padded,
                &parts,
                parsed.prefix,
            ),
            .sha512 => try check(
                std.crypto.hash.sha2.Sha512,
                self.key,
                &padded,
                &parts,
                parsed.prefix,
            ),
        }
        var receipt: Receipt = .{
            .digest = undefined,
            .created = parsed.created,
            .archive_bytes = archive.len,
        };
        std.crypto.hash.sha2.Sha256.hash(archive, &receipt.digest, .{});
        return receipt;
    }
};

fn check(
    comptime Hash: type,
    key: rsa.PublicKey,
    padded: *const [512]u8,
    parts: []const []const u8,
    prefix: *const [2]u8,
) Error!void {
    var hash = Hash.init(.{});
    for (parts) |part| hash.update(part);
    var digest: [Hash.digest_length]u8 = undefined;
    hash.final(&digest);
    if (!std.mem.eql(u8, digest[0..2], prefix)) return error.InvalidSignature;
    rsa.PKCS1v1_5Signature.concatVerify(512, padded, parts, key, Hash) catch
        return error.InvalidSignature;
}

test {
    _ = @import("release_signature_test.zig");
}
