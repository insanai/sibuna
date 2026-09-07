//! Console-only secret protection. The 256-bit key is provisioned separately from the
//! firewall secret and database. Envelopes bind their version, key id and owning user.
const std = @import("std");
const Seed = @import("totp.zig").Seed;
const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const Hash = std.crypto.hash.sha2.Sha256;
pub const Envelope = [60]u8;
pub const KeyId = [32]u8;
pub const Recovery = [16]u8;
const domain = "sibuna-console-totp-seed-v1";

pub fn keyId(key: [32]u8) KeyId {
    var hash = Hash.init(.{});
    hash.update("sibuna-console-key-id-v1");
    hash.update(&key);
    return hash.finalResult();
}

fn associated(user: u64, id: KeyId) [domain.len + 40]u8 {
    var output: [domain.len + 40]u8 = undefined;
    @memcpy(output[0..domain.len], domain);
    std.mem.writeInt(u64, output[domain.len..][0..8], user, .big);
    @memcpy(output[domain.len + 8 ..], &id);
    return output;
}

pub fn seal(io: std.Io, seed: Seed, key: [32]u8, user: u64) Envelope {
    var output: Envelope = undefined;
    io.random(output[0..24]);
    const ad = associated(user, keyId(key));
    Aead.encrypt(output[24..44], output[44..60], &seed, &ad, output[0..24].*, key);
    return output;
}

pub fn open(envelope: Envelope, key: [32]u8, user: u64) error{AuthenticationFailed}!Seed {
    var seed: Seed = undefined;
    errdefer std.crypto.secureZero(u8, &seed);
    const ad = associated(user, keyId(key));
    try Aead.decrypt(&seed, envelope[24..44], envelope[44..60].*, &ad, envelope[0..24].*, key);
    return seed;
}

/// Random 128-bit recovery values have no password-style stretching requirement. Each
/// digest is scoped to its owner; Persistent must consume it once in the login transaction.
pub fn recoveryDigest(user: u64, raw: Recovery) [32]u8 {
    var encoded_user: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded_user, user, .big);
    var hash = Hash.init(.{});
    hash.update("sibuna-console-recovery-v1");
    hash.update(&encoded_user);
    hash.update(&raw);
    return hash.finalResult();
}

pub fn parseRecovery(input: []const u8) error{InvalidCode}!Recovery {
    if (input.len != 32) return error.InvalidCode;
    var raw: Recovery = undefined;
    _ = std.fmt.hexToBytes(&raw, input) catch return error.InvalidCode;
    return raw;
}

test "seed envelopes reject tampering, owner substitution and a different provisioned key" {
    const t = std.testing;
    const seed: Seed = "12345678901234567890".*;
    const key = [_]u8{17} ** 32;
    const sealed = seal(t.io, seed, key, 42);
    try t.expectEqualSlices(u8, &seed, &try open(sealed, key, 42));
    try t.expectError(error.AuthenticationFailed, open(sealed, key, 43));
    try t.expectError(error.AuthenticationFailed, open(sealed, @splat(18), 42));
    for (0..sealed.len) |index| {
        var altered = sealed;
        altered[index] ^= 1;
        try t.expectError(error.AuthenticationFailed, open(altered, key, 42));
    }
    const second = seal(t.io, seed, key, 42);
    try t.expect(!std.mem.eql(u8, &sealed, &second));
    const raw = try parseRecovery("00112233445566778899AABBCCDDEEFF");
    try t.expect(!std.mem.eql(u8, &recoveryDigest(42, raw), &recoveryDigest(43, raw)));
    try t.expectError(error.InvalidCode, parseRecovery("001122"));
}
