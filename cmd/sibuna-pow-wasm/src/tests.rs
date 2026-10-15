use std::sync::{Mutex, MutexGuard};

use sibuna_pow::hashcash::{self, NONCE_DIGITS_MAX, format_decimal};

use super::*;

/// Serialises the tests that call the exports: they share the static buffers, which the
/// module contract allows one caller at a time.
static EXPORTS: Mutex<()> = Mutex::new(());

fn exclusive() -> MutexGuard<'static, ()> {
    EXPORTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Copies `challenge` into the input buffer, as `web/worker.js` does.
fn write_input(challenge: &[u8]) {
    assert!(challenge.len() <= sibuna_get_buffer_len());
    // SAFETY: the caller holds `EXPORTS`, and the buffer holds 256 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            challenge.as_ptr(),
            sibuna_get_buffer_ptr(),
            challenge.len(),
        )
    };
}

/// Borrows the first `len` bytes of the proof buffer.
fn proof(len: usize) -> &'static [u8] {
    // SAFETY: the caller holds `EXPORTS` and does not solve again while using the slice;
    // the proof buffer holds MAX_PROOF_SIZE bytes and `len` comes from `sibuna_posw_solve`.
    unsafe { core::slice::from_raw_parts(sibuna_posw_proof_ptr(), len) }
}

#[test]
fn format_decimal_formats_numbers_correctly() {
    let mut buf = [0u8; NONCE_DIGITS_MAX];
    assert_eq!(format_decimal(0, &mut buf), b"0");
    assert_eq!(format_decimal(12345, &mut buf), b"12345");
    assert_eq!(format_decimal(u64::MAX, &mut buf), b"18446744073709551615");
}

#[test]
fn hashcash_step_finds_a_solution_the_verifier_accepts() {
    let challenge = b"wasm-entry-test-challenge";
    // SAFETY: the pointer and length describe `challenge`.
    let nonce = unsafe { sibuna_solve_step(challenge.as_ptr(), challenge.len(), 8, 0, 1_000_000) };
    assert_ne!(nonce, EXHAUSTED);
    assert!(hashcash::verify_bits(challenge, nonce, 8));
    // Zig 0.16 finds the same nonce.
    assert_eq!(nonce, 681);
}

#[test]
fn hashcash_batches_resume_like_the_worker() {
    let _guard = exclusive();
    let challenge = b"AQEQEAAAAAAAAAAAsibuna-benchmark-challenge-identifier-0000000000000";
    write_input(challenge);
    let (ptr, len) = (sibuna_get_buffer_ptr().cast_const(), challenge.len());
    let max_steps = 20_000;
    let mut start = 0u64;
    let nonce = loop {
        // SAFETY: the input buffer holds the challenge, and we hold `EXPORTS`.
        let found = unsafe { sibuna_solve_step(ptr, len, 16, start, max_steps) };
        if found != EXHAUSTED {
            break found;
        }
        start += u64::from(max_steps);
    };
    // The Zig 0.16 reference solver finds nonce 210125 for this challenge.
    assert_eq!(nonce, 210_125);
    // SAFETY: as above.
    assert_eq!(unsafe { sibuna_solve_sha256(ptr, len, 16) }, 210_125);
    // SAFETY: a zero length never reads the pointer.
    let empty = unsafe { sibuna_solve_step(core::ptr::null(), 0, 12, 0, 2000) };
    assert_eq!(empty, 1289);
    // SAFETY: as above.
    assert_eq!(unsafe { sibuna_solve_step(ptr, len, 300, 0, 10) }, EXHAUSTED);
}

#[test]
fn posw_export_produces_a_verifiable_proof() {
    let _guard = exclusive();
    let challenge = b"wasm-entry-posw-challenge";
    write_input(challenge);
    let len = sibuna_posw_solve(challenge.len(), 8, 4);
    assert!(len > 0);
    let params = Params { depth: 8, challenges: 4 };
    assert_eq!(len, params.proof_size());
    assert!(posw::verify(challenge, params, proof(len)));
}

#[test]
fn posw_export_rejects_bad_arguments() {
    let _guard = exclusive();
    write_input(b"x");
    assert_eq!(sibuna_posw_solve(INPUT_LEN + 1, 8, 4), 0);
    assert_eq!(sibuna_posw_solve(1, 3, 4), 0);
    assert_eq!(sibuna_posw_solve(1, 25, 4), 0);
    assert_eq!(sibuna_posw_solve(1, 8, 0), 0);
    assert_eq!(sibuna_posw_solve(1, 8, 33), 0);
    assert_eq!(sibuna_posw_solve(1, 256 + 8, 4), 0);
    assert_eq!(sibuna_posw_solve(1, 8, 256 + 4), 0);
    assert_eq!(sibuna_posw_solve(1, u32::MAX, u32::MAX), 0);
    // The whole buffer is a valid statement.
    assert_eq!(
        sibuna_posw_solve(INPUT_LEN, 4, 1),
        Params { depth: 4, challenges: 1 }.proof_size()
    );
}
