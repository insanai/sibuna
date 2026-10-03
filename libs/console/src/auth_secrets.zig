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
    const key = @as([32]u8, @splat(17));
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

const bytes_domain = "sibuna-console-notify-secret-v1";
pub const max_sealed = 64;
pub const sealed_prefix = 24 + 1;

fn associatedBytes(subject: u64, id: KeyId) [bytes_domain.len + 40]u8 {
    var output: [bytes_domain.len + 40]u8 = undefined;
    @memcpy(output[0..bytes_domain.len], bytes_domain);
    std.mem.writeInt(u64, output[bytes_domain.len..][0..8], subject, .big);
    @memcpy(output[bytes_domain.len + 8 ..], &id);
    return output;
}

/// Seals up to 64 bytes under the console key, bound to a subject id. Layout: 24-byte
/// nonce, one length byte, 64 ciphertext bytes (zero padded before sealing), 16-byte tag.
pub fn sealBytes(io: std.Io, plaintext: []const u8, key: [32]u8, subject: u64) ![105]u8 {
    if (plaintext.len == 0 or plaintext.len > max_sealed) return error.InvalidLength;
    var padded: [max_sealed]u8 = @splat(0);
    @memcpy(padded[0..plaintext.len], plaintext);
    var output: [105]u8 = undefined;
    io.random(output[0..24]);
    output[24] = @intCast(plaintext.len);
    const ad = associatedBytes(subject, keyId(key));
    Aead.encrypt(output[25..89], output[89..105], &padded, &ad, output[0..24].*, key);
    std.crypto.secureZero(u8, &padded);
    return output;
}

/// Opens a `sealBytes` envelope into `out`; returns the plaintext length.
pub fn openBytes(envelope: []const u8, key: [32]u8, subject: u64, out: *[max_sealed]u8) !u8 {
    if (envelope.len != 105) return error.AuthenticationFailed;
    const length = envelope[24];
    if (length == 0 or length > max_sealed) return error.AuthenticationFailed;
    const ad = associatedBytes(subject, keyId(key));
    try Aead.decrypt(out, envelope[25..89], envelope[89..105].*, &ad, envelope[0..24].*, key);
    return length;
}

test "byte envelopes bind the subject and refuse tampering" {
    const t = std.testing;
    const key = @as([32]u8, @splat(5));
    const sealed = try sealBytes(t.io, "hook secret", key, 7);
    var out: [max_sealed]u8 = undefined;
    try t.expectEqual(@as(u8, 11), try openBytes(&sealed, key, 7, &out));
    try t.expectEqualStrings("hook secret", out[0..11]);
    try t.expectError(error.AuthenticationFailed, openBytes(&sealed, key, 8, &out));
    var altered = sealed;
    altered[30] ^= 1;
    try t.expectError(error.AuthenticationFailed, openBytes(&altered, key, 7, &out));
    try t.expectError(error.InvalidLength, sealBytes(t.io, "", key, 7));
}
