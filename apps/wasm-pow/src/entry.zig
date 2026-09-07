//! Sibuna Browser Proof-of-Work Solver
//! Target: wasm32-freestanding
//!
//! Exports two solvers that share one SHA-256 implementation:
//! * Hashcash (Tier 1): bit-level leading-zero search with the challenge
//!   prefix pre-hashed once per batch.
//! * Proof of Sequential Work (Tier 2): the Cohen–Pietrzak prover from
//!   `libs/crypto/src/posw.zig`, compiled unchanged for the browser so the
//!   server verifier and the client prover can never drift apart.

const std = @import("std");
const pow = @import("pow");
const posw = @import("posw");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Shared input buffer: JavaScript writes the challenge here.
var input_buffer: [256]u8 = undefined;
/// Prover memory for the sequential-work tier (about 90 KB).
var workspace: posw.Workspace = undefined;

export fn sibuna_get_buffer_ptr() [*]u8 {
    return &input_buffer;
}

export fn sibuna_get_buffer_len() usize {
    return input_buffer.len;
}

fn formatU64(val: u64, buf: *[20]u8) usize {
    var v = val;
    var i: usize = buf.len;
    while (true) {
        i -= 1;
        buf[i] = @intCast('0' + (v % 10));
        v /= 10;
        if (v == 0) break;
    }
    const len = buf.len - i;
    std.mem.copyForwards(u8, buf[0..len], buf[i..]);
    return len;
}

/// Searches `max_steps` nonces from `start_nonce` for a digest with at least
/// `difficulty_bits` leading zero bits. Returns the nonce, or `maxInt(u64)`
/// when the batch is exhausted so the worker can post progress and resume.
export fn sibuna_solve_step(
    challenge_ptr: [*]const u8,
    challenge_len: usize,
    difficulty_bits: u32,
    start_nonce: u64,
    max_steps: u32,
) u64 {
    const challenge = challenge_ptr[0..challenge_len];
    var base_hasher = Sha256.init(.{});
    base_hasher.update(challenge);
    base_hasher.update(":");

    var nonce = start_nonce;
    var step: u32 = 0;
    var nonce_buf: [20]u8 = undefined;
    while (step < max_steps) : (step += 1) {
        const nonce_len = formatU64(nonce, &nonce_buf);
        var hasher = base_hasher;
        hasher.update(nonce_buf[0..nonce_len]);
        var digest: [32]u8 = undefined;
        hasher.final(&digest);
        if (pow.checkDifficultyBits(digest, difficulty_bits)) return nonce;
        nonce += 1;
    }
    return std.math.maxInt(u64);
}

export fn sibuna_solve_sha256(
    challenge_ptr: [*]const u8,
    challenge_len: usize,
    difficulty_bits: u32,
) u64 {
    return sibuna_solve_step(challenge_ptr, challenge_len, difficulty_bits, 0, std.math.maxInt(u32));
}

/// Runs the sequential-work prover over `input_buffer[0..challenge_len]`
/// and returns the proof length written to the proof buffer (0 on invalid
/// parameters).
export fn sibuna_posw_solve(challenge_len: usize, depth: u32, challenges: u32) usize {
    if (challenge_len > input_buffer.len or depth > 255 or challenges > 255) return 0;
    const params = posw.Params{ .depth = @intCast(depth), .challenges = @intCast(challenges) };
    const proof = posw.solve(input_buffer[0..challenge_len], params, &workspace) catch return 0;
    return proof.len;
}

export fn sibuna_posw_proof_ptr() [*]const u8 {
    return &workspace.proof;
}

test "formatU64 formats numbers correctly" {
    var buf: [20]u8 = undefined;
    const l1 = formatU64(0, &buf);
    try std.testing.expectEqualStrings("0", buf[0..l1]);
    const l2 = formatU64(12345, &buf);
    try std.testing.expectEqualStrings("12345", buf[0..l2]);
    const l3 = formatU64(std.math.maxInt(u64), &buf);
    try std.testing.expectEqualStrings("18446744073709551615", buf[0..l3]);
}

test "hashcash step finds a solution the verifier accepts" {
    const challenge = "wasm-entry-test-challenge";
    const nonce = sibuna_solve_step(challenge.ptr, challenge.len, 8, 0, 1_000_000);
    try std.testing.expect(nonce != std.math.maxInt(u64));
    try std.testing.expect(pow.verifyHashcashBits(challenge, nonce, 8));
}

test "posw export produces a verifiable proof" {
    const challenge = "wasm-entry-posw-challenge";
    @memcpy(input_buffer[0..challenge.len], challenge);
    const len = sibuna_posw_solve(challenge.len, 8, 4);
    try std.testing.expect(len > 0);
    const proof = sibuna_posw_proof_ptr()[0..len];
    try std.testing.expect(posw.verify(challenge, .{ .depth = 8, .challenges = 4 }, proof));
}
