//! The browser proof-of-work solver, compiled to WebAssembly (`wasm32-unknown-unknown`).
//!
//! The module exports two solvers over the same SHA-256 the server verifies with:
//!
//! - Hashcash (tier 1): a bit-level leading-zero search that absorbs `challenge ":"` once
//!   per batch ([`sibuna_solve_step`], [`sibuna_solve_sha256`]).
//! - Proof of sequential work (tier 2): the Cohen-Pietrzak prover of `sibuna-pow`, compiled
//!   unchanged, so the client prover and the server verifier cannot drift apart
//!   ([`sibuna_posw_solve`], [`sibuna_posw_proof_ptr`]).
//!
//! The bridge to JavaScript is a fixed 256-byte input buffer and integer exports, with no
//! generated glue and no imports. `web/worker.js` writes the challenge at
//! [`sibuna_get_buffer_ptr`] in the exported `memory` and calls the solvers. The exports
//! and their signatures are those of the Zig module `apps/wasm-pow/src/entry.zig`.
//!
//! Build with `cargo build -p sibuna-pow-wasm --target wasm32-unknown-unknown --profile wasm`
//! (the workspace's size profile; its hashing crates keep `opt-level = 3`, so the module is
//! byte-identical to the `--release` build that the daemon's build script embeds).
//!
//! # Deliberate changes from Zig
//!
//! - The Hashcash batch is [`sibuna_pow::hashcash::Search`], shared with the native
//!   reference solver, instead of a loop of its own; the nonces found are the same.
//! - The nonce wraps from `u64::MAX` to 0 instead of relying on unchecked overflow.
//! - [`sibuna_solve_step`] treats a zero-length challenge as empty without reading the
//!   pointer.
//!
//! # Threading
//!
//! The exports share one input buffer and one prover workspace and are not reentrant. A
//! WebAssembly instance without shared memory runs one thread, which is how the worker uses
//! it. On the host (tests only) callers must serialise the calls themselves.
#![no_std]
// The exports take raw pointers from JavaScript and hand out pointers into static buffers;
// that is the FFI boundary, and the only unsafe code, of this crate.
#![allow(unsafe_code)]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

use core::cell::UnsafeCell;

use sibuna_pow::hashcash::Search;
use sibuna_pow::posw::{self, Params, Workspace};

/// Size of the input buffer that JavaScript writes the challenge into.
pub const INPUT_LEN: usize = 256;

/// Returned by the Hashcash exports when a batch holds no solution.
pub const EXHAUSTED: u64 = u64::MAX;

/// A static that the exports mutate.
///
/// The exports run on one thread at a time (see the crate documentation), so at most one
/// reference into a cell is live at any moment: each export creates its references, uses
/// them and drops them before returning.
struct ExportCell<T>(UnsafeCell<T>);

// SAFETY: a WebAssembly instance without shared memory is single-threaded, and on the host
// the callers serialise the exports (the tests hold `tests::EXPORTS`). No two threads ever
// touch a cell at once.
unsafe impl<T> Sync for ExportCell<T> {}

/// The shared input buffer: JavaScript writes the challenge here.
static INPUT: ExportCell<[u8; INPUT_LEN]> = ExportCell(UnsafeCell::new([0; INPUT_LEN]));

/// Prover memory for the sequential-work tier (about 92 KiB of zeroed data).
static WORKSPACE: ExportCell<Workspace> = ExportCell(UnsafeCell::new(Workspace::new()));

/// Returns the address of the 256-byte input buffer in linear memory.
#[unsafe(no_mangle)]
pub extern "C" fn sibuna_get_buffer_ptr() -> *mut u8 {
    INPUT.0.get().cast()
}

/// Returns the length of the input buffer, 256 bytes.
#[unsafe(no_mangle)]
pub extern "C" fn sibuna_get_buffer_len() -> usize {
    INPUT_LEN
}

/// Searches `max_steps` nonces from `start_nonce` for one whose Hashcash digest has at
/// least `difficulty_bits` leading zero bits. Returns the nonce, or `u64::MAX` when the
/// batch is exhausted, so the worker can post progress and resume.
///
/// # Safety
///
/// `challenge_ptr` must point to `challenge_len` initialised bytes that nothing writes
/// during the call, unless `challenge_len` is zero. JavaScript passes
/// [`sibuna_get_buffer_ptr`] and at most [`sibuna_get_buffer_len`] bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sibuna_solve_step(
    challenge_ptr: *const u8,
    challenge_len: usize,
    difficulty_bits: u32,
    start_nonce: u64,
    max_steps: u32,
) -> u64 {
    let challenge: &[u8] = if challenge_len == 0 {
        &[]
    } else {
        // SAFETY: the caller guarantees `challenge_len` readable bytes at `challenge_ptr`
        // that stay unchanged for the duration of the call.
        unsafe { core::slice::from_raw_parts(challenge_ptr, challenge_len) }
    };
    Search::new(challenge)
        .find(difficulty_bits, start_nonce, u64::from(max_steps))
        .unwrap_or(EXHAUSTED)
}

/// Searches nonces from 0 in one batch of `u32::MAX` steps; see [`sibuna_solve_step`].
///
/// # Safety
///
/// As for [`sibuna_solve_step`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sibuna_solve_sha256(
    challenge_ptr: *const u8,
    challenge_len: usize,
    difficulty_bits: u32,
) -> u64 {
    // SAFETY: the caller upholds the contract of `sibuna_solve_step`, which is the same.
    unsafe { sibuna_solve_step(challenge_ptr, challenge_len, difficulty_bits, 0, u32::MAX) }
}

/// Runs the sequential-work prover over the first `challenge_len` bytes of the input
/// buffer and returns the length of the proof written to the proof buffer, or 0 when
/// `challenge_len` exceeds the buffer or the parameters are invalid.
#[unsafe(no_mangle)]
pub extern "C" fn sibuna_posw_solve(challenge_len: usize, depth: u32, challenges: u32) -> usize {
    let (Ok(depth), Ok(challenges)) = (u8::try_from(depth), u8::try_from(challenges)) else {
        return 0;
    };
    // SAFETY: the exports run one at a time (see `ExportCell`), so these are the only
    // references into INPUT and WORKSPACE while this call runs, and they are distinct cells.
    let (input, workspace) = unsafe { (&*INPUT.0.get(), &mut *WORKSPACE.0.get()) };
    let Some(chi) = input.get(..challenge_len) else {
        return 0;
    };
    posw::solve(chi, Params { depth, challenges }, workspace).map_or(0, <[u8]>::len)
}

/// Returns the address of the proof buffer that [`sibuna_posw_solve`] writes.
#[unsafe(no_mangle)]
pub extern "C" fn sibuna_posw_proof_ptr() -> *const u8 {
    // SAFETY: the exports run one at a time (see `ExportCell`); the shared reference lives
    // only for this expression, and the returned raw pointer carries no borrow.
    unsafe { (*WORKSPACE.0.get()).proof_buffer().as_ptr() }
}

/// Traps on a panic. Panics are unreachable by construction; trapping keeps the module free
/// of formatting code and imports.
#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(test)]
mod tests;
