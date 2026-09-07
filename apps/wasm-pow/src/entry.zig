//! Sibuna Browser WebAssembly PoW Solver
//! Target: wasm32-freestanding

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

var memory_buffer: [1024]u8 = undefined;

export fn sibuna_get_buffer_ptr() [*]u8 {
    return &memory_buffer;
}

fn formatU64(val: u64, buf: *[32]u8) usize {
    var v = val;
    var i: usize = 32;
    while (true) {
        i -= 1;
        buf[i] = @intCast('0' + (v % 10));
        v /= 10;
        if (v == 0) break;
    }
    const len = 32 - i;
    @memcpy(buf[0..len], buf[i..32]);
    return len;
}

fn checkDifficulty(digest: [32]u8, difficulty: u32) bool {
    const full_bytes = difficulty / 2;
    var i: usize = 0;
    while (i < full_bytes) : (i += 1) {
        if (digest[i] != 0) return false;
    }
    if (difficulty % 2 != 0) {
        if ((digest[full_bytes] >> 4) != 0) return false;
    }
    return true;
}

export fn sibuna_solve_step(
    challenge_ptr: [*]const u8,
    challenge_len: usize,
    target_difficulty: u32,
    start_nonce: u64,
    max_steps: u32,
) u64 {
    const challenge = challenge_ptr[0..challenge_len];
    var base_hasher = Sha256.init(.{});
    base_hasher.update(challenge);
    base_hasher.update(":");

    var nonce = start_nonce;
    var step: u32 = 0;
    var nonce_buf: [32]u8 = undefined;

    while (step < max_steps) : (step += 1) {
        const nonce_len = formatU64(nonce, &nonce_buf);
        var hasher = base_hasher;
        hasher.update(nonce_buf[0..nonce_len]);

        var digest: [32]u8 = undefined;
        hasher.final(&digest);

        if (checkDifficulty(digest, target_difficulty)) {
            return nonce;
        }
        nonce += 1;
    }
    return std.math.maxInt(u64);
}

export fn sibuna_solve_sha256(
    challenge_ptr: [*]const u8,
    challenge_len: usize,
    target_difficulty: u32,
) u64 {
    return sibuna_solve_step(
        challenge_ptr,
        challenge_len,
        target_difficulty,
        0,
        std.math.maxInt(u32),
    );
}

test "checkDifficulty validates correctly" {
    var digest: [32]u8 = [_]u8{0xff} ** 32;
    try std.testing.expect(!checkDifficulty(digest, 1));

    digest[0] = 0x0f;
    try std.testing.expect(checkDifficulty(digest, 1));
    try std.testing.expect(!checkDifficulty(digest, 2));

    digest[0] = 0x00;
    try std.testing.expect(checkDifficulty(digest, 2));
    try std.testing.expect(!checkDifficulty(digest, 3));
}

test "formatU64 formats numbers correctly" {
    var buf: [32]u8 = undefined;
    const l1 = formatU64(0, &buf);
    try std.testing.expectEqualStrings("0", buf[0..l1]);

    const l2 = formatU64(12345, &buf);
    try std.testing.expectEqualStrings("12345", buf[0..l2]);
}
