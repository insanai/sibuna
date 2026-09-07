//! Sibuna Browser WebAssembly PoW Solver
//! Target: wasm32-freestanding

const std = @import("std");

export fn sibuna_solve_sha256(
    challenge_ptr: [*]const u8,
    challenge_len: usize,
    target_difficulty: u32,
) u32 {
    _ = challenge_ptr;
    _ = challenge_len;
    _ = target_difficulty;
    return 0;
}
